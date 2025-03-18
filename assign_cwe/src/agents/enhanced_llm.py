# src/agents/enhanced_llm.py

from utils.logger import get_logger
from typing import Any, Dict, List, Optional
from .base import ContextAwareAgent
from retrievers.enhanced_hybrid import EnhancedHybridRetriever
from pathlib import Path
import re
import time
from models.cwe import CWEEntry, load_cwe_database
from utils.llm_factory import LLMFactory
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from utils.helpers import safe_access

logger = get_logger(__name__)

class EnhancedLLMAgent(ContextAwareAgent):
    """Enhanced LLM Agent with both RAG and property graph capabilities."""
    
    def __init__(
        self,
        role: str,
        llm_provider: str = "anthropic",
        llm_config: Dict[str, Any] = None,
        context_limit: int = 5,
        max_iterations: int = 3,
        max_input_length: int = 10000,
        embedding_client = None,
        retriever = None,
        cwe_database_path: str = None
    ):
        """Initialize an enhanced LLM agent.
        
        Args:
            role: The role of this agent ("analyzer", "critic", or "resolver")
            llm_provider: The LLM provider to use ("anthropic", "gemini", "openai")
            llm_config: Configuration for the LLM
            context_limit: Maximum number of previous interactions to maintain
            max_iterations: Maximum number of iterations for feedback loop
            max_input_length: Maximum length of input text
            embedding_client: Embedding client instance
            retriever: Optional existing retriever to use
            cwe_database_path: Path to CWE database JSON file
        """
        super().__init__(role, context_limit)
        self.max_input_length = max_input_length
        self.max_iterations = max_iterations
        
        # Set default LLM config if not provided
        if llm_config is None:
            llm_config = {
                "model": "claude-3-haiku-20240307" if llm_provider == "anthropic" else "gemini-pro",
                "temperature": 0.7,
                "max_tokens": 2048
            }
        
        # Load CWE database if path provided
        self.cwe_entries = None
        if cwe_database_path:
            self.cwe_entries = load_cwe_database(cwe_database_path)
            logger.info(f"Loaded {len(self.cwe_entries)} CWE entries for {role} agent")
        
        # Load role prompts from files
        self.role_prompts = {}
        valid_roles = ["analyzer", "critic", "resolver"]
        
        # Ensure all role prompt files exist and can be loaded
        for role_name in valid_roles:
            prompt = self._load_prompt_from_file(role_name)
            if not prompt:
                raise FileNotFoundError(f"Required prompt file for role '{role_name}' not found")
            self.role_prompts[role_name] = prompt
        
        # Load the analysis template
        self.analysis_template = self._load_prompt_from_file("analysis_template")
        if not self.analysis_template:
            raise FileNotFoundError("Required prompt file 'analysis_template.txt' not found")
        
        if role not in valid_roles:
            logger.error("Invalid role: {}", role)
            raise ValueError(f"Invalid role: {role}. Must be one of {valid_roles}")
        
        if not embedding_client:
            logger.error("Embedding client must be provided")
            raise ValueError("Embedding client must be provided")
        
        # Initialize LLM using the factory
        try:
            self.llm = LLMFactory.create_llm(llm_provider, llm_config)
            self.llm_provider = llm_provider
            self.llm_config = llm_config
            logger.info(f"Successfully initialized {llm_provider} LLM for {role} agent")
        except Exception as e:
            logger.error(f"Error initializing LLM: {e}")
            raise
        
        # Initialize retriever
        self.retriever = retriever
        if not self.retriever:
            self.retriever = EnhancedHybridRetriever(
                name=f"{role}_retriever",
                llm=self.llm,
                embedding_client=embedding_client
            )
        
        logger.debug("Initialized EnhancedLLMAgent for role {} with {} retriever", 
                    role, "shared" if retriever else "new")

    # Helper function to build the CWE table with mapping usage
    def _build_cwe_table(self, cwe_results: List[Dict[str, Any]]) -> str:
        """Build detailed CWE table for the analysis template showing retriever sources and mapping usage."""
        table_rows = []
        
        for result in cwe_results:
            metadata = result.get('metadata', {})
            doc_id = metadata.get('doc_id', 'Unknown')
            name = metadata.get('name', 'Unknown')
            combined_score = result.get('similarity', 0.0)
            
            # Get mapping usage if available - no special preprocessing needed
            mapping_usage = "Not specified"
            if 'mapping_notes' in metadata and metadata['mapping_notes']:
                mapping_notes = metadata['mapping_notes']
                if isinstance(mapping_notes, dict) and 'usage' in mapping_notes:
                    mapping_usage = mapping_notes['usage']
            
            # Get retriever-specific information if available
            score_info = metadata.get('score_info', {})
            retrievers = score_info.get('retrievers', [])
            retriever_scores = score_info.get('individual_scores', {})
            
            # Create retriever source text
            retriever_text = ""
            if retrievers:
                retriever_parts = []
                for retriever in ["dense", "sparse", "graph"]:
                    if retriever in retrievers:
                        score = retriever_scores.get(retriever, 0.0)
                        retriever_parts.append(f"{retriever}:{score:.2f}")
                retriever_text = f" ({', '.join(retriever_parts)})"
            
            # Format CWE ID as clickable link
            cwe_num = doc_id.replace('CWE-', '')
            cwe_id_formatted = f"[CWE-{cwe_num}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)"
            
            # Add row to table with mapping usage
            table_rows.append(f"| {cwe_id_formatted} | {name} | {combined_score:.2f}{retriever_text} | {mapping_usage} |")
        
        # If no results, add placeholder row
        if not table_rows:
            table_rows.append("| No CWEs found | N/A | 0.00 | N/A |")
        
        return "\n".join(table_rows)


    def _create_mapping_guidance_section(self, cwe_results: List[Dict[str, Any]]) -> str:
        """Create a dedicated section for mapping guidance from retrieved CWEs."""
        guidance_parts = [
            "The following mapping guidance is provided by MITRE for the retrieved CWEs:",
            ""
        ]
        
        has_guidance = False
        
        for result in cwe_results:
            metadata = result.get('metadata', {})
            doc_id = metadata.get('doc_id', 'Unknown')
            name = metadata.get('name', 'Unknown')
            
            # Get mapping notes if available
            mapping_notes = metadata.get('mapping_notes', {})
            
            if mapping_notes:
                has_guidance = True
                guidance_parts.append(f"### CWE-{doc_id}: {name}")
                
                # Extract usage information
                usage = mapping_notes.get('usage', 'Not specified')
                guidance_parts.append(f"**Usage:** {usage}")
                
                # Extract rationale
                rationale = mapping_notes.get('rationale', 'Not specified')
                guidance_parts.append(f"**Rationale:** {rationale}")
                
                # Add reasons if available
                reasons = mapping_notes.get('reasons', [])
                if reasons:
                    guidance_parts.append("**Reasons:**")
                    # Handle reasons being either a list or a single string
                    if isinstance(reasons, list):
                        for reason in reasons:
                            guidance_parts.append(f"- {reason}")
                    else:
                        guidance_parts.append(f"- {reasons}")
                
                # Add suggestions if available
                suggestions = mapping_notes.get('suggestions', [])
                if suggestions:
                    guidance_parts.append("**Suggested Alternatives:**")
                    # Handle suggestions being either a list or a single item
                    if isinstance(suggestions, list):
                        for suggestion in suggestions:
                            # Handle suggestion being string or dict
                            if isinstance(suggestion, dict) and 'CweID' in suggestion:
                                suggestion_text = f"- CWE-{suggestion['CweID']}"
                                if 'Comment' in suggestion:
                                    suggestion_text += f": {suggestion['Comment']}"
                                guidance_parts.append(suggestion_text)
                            else:
                                guidance_parts.append(f"- CWE-{suggestion}")
                    else:
                        guidance_parts.append(f"- {suggestions}")
                
                guidance_parts.append("")
        
        if not has_guidance:
            return "No specific mapping guidance available for the retrieved CWEs."
        
        return "\n".join(guidance_parts)

    def _create_mitigations_guidance_section(self, cwe_results: List[Dict[str, Any]]) -> str:
        """Create a dedicated section for potential mitigations from retrieved CWEs."""
        guidance_parts = [
            "The following potential mitigations are provided for the retrieved CWEs:",
            ""
        ]
        
        has_mitigations = False
        
        for result in cwe_results:
            metadata = result.get('metadata', {})
            doc_id = metadata.get('doc_id', 'Unknown')
            name = metadata.get('name', 'Unknown')
            
            # Get mitigations if available
            mitigations = metadata.get('mitigations', [])
            
            if mitigations:
                has_mitigations = True
                guidance_parts.append(f"### CWE-{doc_id}: {name}")
                
                # Handle mitigations being a list or a single item
                if not isinstance(mitigations, list):
                    mitigations = [mitigations]
                
                for mitigation in mitigations[:3]:  # Limit to 3 mitigations per CWE for brevity
                    # Extract phase information, handling various formats
                    phase_text = "Unknown Phase"
                    if isinstance(mitigation, dict) and "phase" in mitigation:
                        phase = mitigation["phase"]
                        if isinstance(phase, list):
                            phase_text = ", ".join(phase)
                        else:
                            phase_text = str(phase)
                            
                    guidance_parts.append(f"**Phase:** {phase_text}")
                    
                    # Extract effectiveness if available
                    if isinstance(mitigation, dict) and "effectiveness" in mitigation:
                        guidance_parts.append(f"**Effectiveness:** {mitigation['effectiveness']}")
                    
                    # Extract strategy if available
                    if isinstance(mitigation, dict) and "strategy" in mitigation:
                        guidance_parts.append(f"**Strategy:** {mitigation['strategy']}")
                    
                    # Always include description if available
                    description = "No description provided"
                    if isinstance(mitigation, dict) and "description" in mitigation:
                        description = mitigation["description"]
                    elif isinstance(mitigation, str):
                        description = mitigation
                        
                    guidance_parts.append(f"**Description:** {description}")
                    guidance_parts.append("")
        
        if not has_mitigations:
            return "No specific mitigation guidance available for the retrieved CWEs."
        
        return "\n".join(guidance_parts)


    def _get_retriever_interpretation(self) -> str:
        """Get an enhanced retriever score interpretation text with retriever source information."""
        return """
The scores above have been normalized to a 0-1 scale for comparison across different retrieval methods:
- **Dense Vector Search**: Measures semantic similarity to the vulnerability description
- **Property Graph**: Identifies CWEs with relevant structural relationships
- **Sparse Retrieval**: Finds exact keyword matches, especially for keyphrases

The main score is the combined score after applying boosting factors. Individual retriever scores are shown in parentheses when available (dense:X.XX, sparse:Y.YY, graph:Z.ZZ).

Additional scoring factors:
- **Retriever Count Boost**: CWEs found by multiple retrievers receive a score boost (25% for 2 retrievers, 50% for all 3 retrievers)
- **Abstraction Level**: Base CWEs (+30%) and Variant CWEs (+20%) are favored, while Class CWEs (-20%) and Pillar CWEs (-40%) are discouraged

Higher scores indicate stronger relevance. CWEs found by multiple retrievers are particularly significant as they were identified through different analysis methods.
"""

    def _get_cwe_details(self, cwe_id: str) -> Optional[CWEEntry]:
        """Get full CWE entry details by ID."""
        if not self.cwe_entries:
            return None
        
        # Remove 'CWE-' prefix if present
        numeric_id = cwe_id.replace('CWE-', '')
        return next((cwe for cwe in self.cwe_entries if cwe.ID == numeric_id), None)

    def _extract_cwe_references(self, text: str) -> List[str]:
        """Extract CWE references from text."""
        return re.findall(r'CWE-\d+', text)

    def _format_cwe_info(self, cwe: CWEEntry) -> str:
        """Format full CWE information for inclusion in prompts with proper markdown headings."""
        if not cwe:
            return ""

        # Format relationships
        relationships = []
        if cwe.RelatedWeaknesses:
            for rel in cwe.RelatedWeaknesses:
                relationships.append(f"{rel.Nature} -> CWE-{rel.CweID}")

        # Format alternate terms
        alternate_terms = []
        if cwe.AlternateTerms:
            for term in cwe.AlternateTerms:
                if term.Description:
                    alternate_terms.append(f"{term.Term}: {term.Description}")
                else:
                    alternate_terms.append(term.Term)
        
        # Format mapping notes - handle potential dict/object structure flexibly
        mapping_guidance = ""
        if cwe.MappingNotes:
            mapping_guidance = "\n### Mapping Guidance\n"
            
            # Handle Usage field
            if isinstance(cwe.MappingNotes, dict) and "Usage" in cwe.MappingNotes:
                mapping_guidance += f"**Usage:** {cwe.MappingNotes['Usage']}\n"
            elif hasattr(cwe.MappingNotes, "Usage"):
                mapping_guidance += f"**Usage:** {cwe.MappingNotes.Usage}\n"
                
            # Handle Rationale field
            if isinstance(cwe.MappingNotes, dict) and "Rationale" in cwe.MappingNotes:
                mapping_guidance += f"**Rationale:** {cwe.MappingNotes['Rationale']}\n"
            elif hasattr(cwe.MappingNotes, "Rationale"):
                mapping_guidance += f"**Rationale:** {cwe.MappingNotes.Rationale}\n"
                
            # Handle Comments field
            if isinstance(cwe.MappingNotes, dict) and "Comments" in cwe.MappingNotes:
                mapping_guidance += f"**Comments:** {cwe.MappingNotes['Comments']}\n"
            elif hasattr(cwe.MappingNotes, "Comments"):
                mapping_guidance += f"**Comments:** {cwe.MappingNotes.Comments}\n"
                
            # Handle Reasons field
            reasons = None
            if isinstance(cwe.MappingNotes, dict) and "Reasons" in cwe.MappingNotes:
                reasons = cwe.MappingNotes["Reasons"]
            elif hasattr(cwe.MappingNotes, "Reasons"):
                reasons = cwe.MappingNotes.Reasons
                
            if reasons:
                mapping_guidance += "**Reasons:**\n"
                # Handle reasons being either a list or string or other structure
                if isinstance(reasons, list):
                    for reason in reasons:
                        mapping_guidance += f"- {reason}\n"
                else:
                    mapping_guidance += f"- {reasons}\n"
                    
            # Handle Suggestions field
            suggestions = None
            if isinstance(cwe.MappingNotes, dict) and "Suggestions" in cwe.MappingNotes:
                suggestions = cwe.MappingNotes["Suggestions"]
            elif hasattr(cwe.MappingNotes, "Suggestions"):
                suggestions = cwe.MappingNotes.Suggestions
                
            if suggestions:
                mapping_guidance += "**Suggested Alternatives:**\n"
                # Handle suggestions being either a list or string or other structure
                if isinstance(suggestions, list):
                    for suggestion in suggestions:
                        # Handle suggestion being a string or dict
                        if isinstance(suggestion, dict) and "CweID" in suggestion:
                            mapping_guidance += f"- CWE-{suggestion['CweID']}"
                            if "Comment" in suggestion:
                                mapping_guidance += f": {suggestion['Comment']}"
                            mapping_guidance += "\n"
                        else:
                            mapping_guidance += f"- CWE-{suggestion}\n"
                else:
                    mapping_guidance += f"- {suggestions}\n"

        # Format potential mitigations - treat as a flexible structure
        mitigations = ""
        if cwe.PotentialMitigations:
            mitigations = "\n### Potential Mitigations\n"
            
            # Handle mitigations being a list or a single item
            mitigation_items = cwe.PotentialMitigations
            if not isinstance(mitigation_items, list):
                mitigation_items = [mitigation_items]
                
            # Limit to avoid overwhelming
            for i, mitigation in enumerate(mitigation_items[:3]):
                mitigations += f"**Mitigation {i+1}:**\n"
                
                # Handle Phase field in various formats
                if isinstance(mitigation, dict) and "Phase" in mitigation:
                    phase = mitigation["Phase"]
                    if isinstance(phase, list):
                        mitigations += f"- **Phase:** {', '.join(phase)}\n"
                    else:
                        mitigations += f"- **Phase:** {phase}\n"
                elif hasattr(mitigation, "Phase"):
                    phase = mitigation.Phase
                    if isinstance(phase, list):
                        mitigations += f"- **Phase:** {', '.join(phase)}\n"
                    else:
                        mitigations += f"- **Phase:** {phase}\n"
                        
                # Handle other attributes flexibly
                for attr_name in ["Effectiveness", "Strategy"]:
                    if isinstance(mitigation, dict) and attr_name in mitigation:
                        mitigations += f"- **{attr_name}:** {mitigation[attr_name]}\n"
                    elif hasattr(mitigation, attr_name):
                        mitigations += f"- **{attr_name}:** {getattr(mitigation, attr_name)}\n"
                
                # Always include Description if available
                if isinstance(mitigation, dict) and "Description" in mitigation:
                    mitigations += f"- **Description:** {mitigation['Description']}\n"
                elif hasattr(mitigation, "Description"):
                    mitigations += f"- **Description:** {mitigation.Description}\n"
                else:
                    # If no formal description, but mitigation is a string, use the string
                    if isinstance(mitigation, str):
                        mitigations += f"- **Description:** {mitigation}\n"
                
                mitigations += "\n"

        # Format additional notes - handle flexibly
        additional_notes = ""
        if cwe.Notes:
            additional_notes = "\n### Additional Notes\n"
            
            # Handle notes being a list or a single item
            note_items = cwe.Notes
            if not isinstance(note_items, list):
                note_items = [note_items]
                
            for note in note_items:
                # Handle note being a dict with Type and Note fields
                if isinstance(note, dict):
                    note_type = note.get("Type", "General")
                    note_content = note.get("Note", str(note))
                    additional_notes += f"**[{note_type}]** {note_content}\n\n"
                # Handle note being an object with Type and Note attributes
                elif hasattr(note, "Type") and hasattr(note, "Note"):
                    additional_notes += f"**[{safe_access(note, 'Type', 'General').Type}]** {note.Note}\n\n"
                # Handle note being a string
                else:
                    additional_notes += f"{str(note)}\n\n"

        # Generate examples section if available
        examples = ""
        if cwe.ObservedExamples:
            examples = "\n### Observed Examples\n"
            for ex in cwe.ObservedExamples[:3]:  # Limit to 3 examples to avoid overwhelming
                examples += f"- **{ex.Reference}:** {ex.Description}\n"

        # Use markdown heading format for the CWE heading and subheadings
        return f"""
## CWE-{cwe.ID}: {cwe.Name}
**Abstraction:** {cwe.Abstraction}
**Status:** {cwe.Status}

### Description
{cwe.Description}

### Extended Description
{cwe.ExtendedDescription if cwe.ExtendedDescription else 'Not provided'}

### Alternative Terms
{chr(10).join(alternate_terms) if alternate_terms else 'None'}

### Relationships
{chr(10).join(relationships) if relationships else 'None'}
{mapping_guidance}
{mitigations}
{additional_notes}
{examples}
"""

    def generate_response(self, input_text: str) -> Dict[str, Any]:
        """Generate response with enhanced CWE context including mapping guidance and mitigations."""
        
        # Validate input
        if error := self.validate_input(input_text, self.max_input_length):
            logger.error("Input validation failed: {}", error)
            raise ValueError(error)
            
        try:
            # Start Time the retrieval
            retriever_start_time = time.time()
            logger.info("Generating enhanced response for input: {:.100}...", input_text)
            
            # Get relevant CWEs using both retrieval methods
            logger.debug("Performing hybrid search with RAG and property graph")
            cwe_results = self.retriever.search(
                input_text,
                k=5,
                use_graph=True,
                use_rag=True,
                rerank=False 
            )
            
            # Check the structure of cwe_results and handle appropriately
            if isinstance(cwe_results, dict) and 'all_results' in cwe_results:
                # If we received a dict with 'all_results', use that as our cwe_results
                cwe_results = cwe_results['all_results']
                
            logger.debug("Retrieved {} relevant CWEs", len(cwe_results))
            
            # Build context string with relationship information
            context = self._build_enhanced_context(cwe_results)
            logger.debug("Built enhanced context with relationships")
            
            # Build CWE table
            retrieved_cwes_table = self._build_cwe_table(cwe_results)
            
            # Get retriever interpretation
            retriever_interpretation = self._get_retriever_interpretation()
            
            # Generate mapping guidance section
            mapping_guidance = self._create_mapping_guidance_section(cwe_results)
            
            # Generate mitigations guidance section
            mitigations_guidance = self._create_mitigations_guidance_section(cwe_results)
            
            # Create prompt with context using the loaded role prompt
            prompt = self.analysis_template.format(
                role_prompt=self.role_prompts[self.role],
                context=context,
                retrieved_cwes_table=retrieved_cwes_table,
                retriever_interpretation=retriever_interpretation,
                mapping_guidance=mapping_guidance,
                mitigations_guidance=mitigations_guidance,
                input_text=input_text
            )
            logger.debug("Full prompt prepared")

            # Initialize variables for response and CWE IDs
            response_text = ""
            extracted_cwe_ids = []
            
            # Generate initial response using the appropriate LLM
            logger.debug(f"Generating LLM response with provider: {self.llm_provider}")
            llm_response = self._call_llm(prompt)
            response_text = llm_response["response"]
            logger.debug("Response received")

            # If this is the analyzer, extract CWE IDs from the response
            if self.role == "analyzer":
                extracted_cwe_ids = list(set(self._extract_cwe_references(response_text)))
                logger.debug("Extracted {} CWE IDs from analyzer response: {}", 
                            len(extracted_cwe_ids), extracted_cwe_ids)

            # If this is the critic, get CWE details from the entire input
            elif self.role == "critic":
                # Extract CWE references from the entire input text
                cwe_ids = self._extract_cwe_references(input_text)
                
                if cwe_ids and self.cwe_entries:
                    # Build detailed CWE information
                    cwe_details = []
                    for cwe_id in cwe_ids:
                        cwe = self._get_cwe_details(cwe_id)
                        if cwe:
                            cwe_details.append(self._format_cwe_info(cwe))
                    
                    # Generate new response with CWE details - no section parsing needed
                    enhanced_prompt = f"""
Review this analysis with the full CWE specifications:

Analysis to review:
{input_text}

Complete CWE Specifications for Referenced Weaknesses:
{chr(10).join(cwe_details)}

Using these full CWE specifications, provide your critique of the analysis.
Pay special attention to the mapping guidance and potential mitigations provided for each CWE.
"""
        
                    enhanced_response = self._call_llm(enhanced_prompt)
                    response_text = enhanced_response["response"]
                    logger.debug("Enhanced response received")

                    # Extract any new CWEs suggested by the critic (ones not in the input)
                    critic_cwe_ids = list(set(self._extract_cwe_references(response_text)))
                    extracted_cwe_ids = [cwe_id for cwe_id in critic_cwe_ids if cwe_id not in cwe_ids]
                    if extracted_cwe_ids:
                        logger.debug("Critic suggested additional CWEs: {}", extracted_cwe_ids)
        
            # Add to context history
            self.add_to_context({
                "input": input_text,
                "response": response_text
            })
            
            logger.info("Successfully generated enhanced response")
            logger.debug("Response length: {} characters", len(response_text))
            
            # End time: retrieval is complete
            retrieval_time = time.time() - retriever_start_time
            logger.info(f"Retrieval completed in {retrieval_time:.3f}s, found {len(cwe_results)} results")
            
            return {
                "response": self.format_response(response_text),
                "cwe_ids": extracted_cwe_ids,
                "retriever_diagnostics": {
                    "total_results": len(cwe_results),
                    "retrieval_time": retrieval_time,
                    "sources_breakdown": self._get_retriever_breakdown(cwe_results)
                }
            }
            
        except Exception as e:
            logger.exception("Error generating enhanced response: {}", str(e))
            raise
        
    def _get_retriever_breakdown(self, cwe_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate statistics about which retrievers found results."""
        stats = {
            "dense_only": 0,
            "sparse_only": 0,
            "graph_only": 0,
            "dense_and_sparse": 0,
            "dense_and_graph": 0,
            "sparse_and_graph": 0,
            "all_retrievers": 0,
            "by_retriever": {"dense": 0, "sparse": 0, "graph": 0}
        }
        
        for result in cwe_results:
            retrievers = result.get("metadata", {}).get("score_info", {}).get("retrievers", [])
            # Count by individual retriever
            for retriever in retrievers:
                stats["by_retriever"][retriever] = stats["by_retriever"].get(retriever, 0) + 1
                
            # Count by combination
            if len(retrievers) == 1:
                if "dense" in retrievers: stats["dense_only"] += 1
                if "sparse" in retrievers: stats["sparse_only"] += 1
                if "graph" in retrievers: stats["graph_only"] += 1
            elif len(retrievers) == 2:
                if "dense" in retrievers and "sparse" in retrievers: stats["dense_and_sparse"] += 1
                if "dense" in retrievers and "graph" in retrievers: stats["dense_and_graph"] += 1
                if "sparse" in retrievers and "graph" in retrievers: stats["sparse_and_graph"] += 1
            elif len(retrievers) == 3:
                stats["all_retrievers"] += 1
                
        return stats
           
    def _build_enhanced_context(self, cwe_results: List[Dict[str, Any]]) -> str:
        """Build context string with relationship information, mapping notes, and mitigations."""
        logger.debug("Building enhanced context from {} CWE results", len(cwe_results))
        
        context_parts = []
        for result in cwe_results:
            # Get metadata and relationships
            metadata = result['metadata']
            relationships = metadata.get('relationships', [])
            
            # Get retriever source information if available
            score_info = metadata.get('score_info', {})
            retrievers = score_info.get('retrievers', [])
            retriever_scores = score_info.get('individual_scores', {})
            
            # Get mapping notes if available
            mapping_notes = metadata.get('mapping_notes', {})
            mapping_guidance = ""
            if mapping_notes:
                usage = mapping_notes.get('usage', 'Not specified')
                rationale = mapping_notes.get('rationale', 'Not specified')
                mapping_guidance = f"\nMapping Guidance:\nUsage: {usage}\nRationale: {rationale}"
                
                # Add reasons if available
                reasons = mapping_notes.get('reasons', [])
                if reasons:
                    mapping_guidance += "\nReasons:"
                    for reason in reasons:
                        mapping_guidance += f"\n- {reason}"
            
            # Get mitigations if available
            mitigations = metadata.get('mitigations', [])
            mitigation_text = ""
            if mitigations:
                mitigation_text = "\nPotential Mitigations:"
                for mitigation in mitigations[:2]:  # Limit to 2 for brevity
                    phase = mitigation.get('phase', 'Unknown')
                    description = mitigation.get('description', 'No description')
                    
                    # Truncate long descriptions
                    if len(description) > 100:
                        description = description[:97] + "..."
                        
                    mitigation_text += f"\n- {phase}: {description}"
            
            # Get additional notes if available
            notes = metadata.get('notes', [])
            notes_text = ""
            if notes:
                notes_text = "\nAdditional Notes:"
                for note in notes[:1]:  # Limit to 1 note for brevity
                    note_type = note.get('type', 'General')
                    note_content = note.get('content', '')
                    if note_content:
                        # Truncate long notes
                        if len(note_content) > 100:
                            note_content = note_content[:97] + "..."
                        notes_text += f"\n[{note_type}] {note_content}"
            
            # Build retriever source section if available
            retriever_section = ""
            if retrievers:
                retriever_parts = []
                for retriever in ["dense", "sparse", "graph"]:
                    if retriever in retrievers:
                        score = retriever_scores.get(retriever, 0.0)
                        retriever_parts.append(f"{retriever.capitalize()}: {score:.2f}")
                
                if retriever_parts:
                    retriever_section = "\nRetriever Sources:\n" + "\n".join(retriever_parts)
            
            context_parts.append(f"""
CWE-{metadata['doc_id']}
Similarity Score: {result['similarity']:.2f}
Type: {metadata.get('type', 'Unknown')}{retriever_section}

Description:
{metadata['original_content']}
{mapping_guidance}
{mitigation_text}
{notes_text}

Relationships:
{self._format_relationships(relationships)}
---""")
            
        final_context = "\n".join(context_parts) if context_parts else "No relevant CWEs found."
        logger.debug("Built context with {} parts", len(context_parts))
        return final_context


    def _format_relationships(self, relationships: List[Dict[str, Any]]) -> str:
        """Format relationship information for context."""
        if not relationships:
            return "No direct relationships found."
            
        formatted = []
        for rel in relationships:
            formatted.append(
                f"- {rel['label']} -> CWE-{rel['target_id']}"
            )
        
        logger.debug("Formatted {} relationships", len(relationships))
        return "\n".join(formatted)
        
    def get_metadata(self) -> Dict[str, Any]:
        """Get metadata about this agent."""
        return {
            "role": self.role,
            "llm_provider": self.llm_provider,
            "llm_config": self.llm_config,
            "context_limit": self.context_limit,
            "context_size": len(self.context_history),
            "max_iterations": self.max_iterations,
            "max_input_length": self.max_input_length,
            "retriever": self.retriever.get_metadata()
        }
        
    def _load_prompt_from_file(self, role: str) -> str:
        """Load prompt from file - with modifications for backward compatibility."""
        prompt_file = Path(__file__).parent.parent / "prompts" / f"{role}.md"
        if role == "analysis_template":
            prompt_file = Path(__file__).parent.parent / "prompts" / "analysis_template.md"
            
        if not prompt_file.exists():
            logger.error(f"Required prompt file not found: {prompt_file}")
            return ""
            
        try:
            with open(prompt_file, "r") as f:
                content = f.read().strip()
                if not content:
                    logger.error(f"Prompt file is empty: {prompt_file}")
                    return ""
                    
                # If this is the analysis template, ensure it's compatible
                if role == "analysis_template" and "{retrieved_cwes_table}" in content:
                    # Remove the section that depends on retrieved_cwes_table
                    # Replace with a version that doesn't require that variable
                    modified_template = re.sub(
                        r"## Retrieved CWEs and Scores.*?(?=Current Input:)",
                        "",
                        content, 
                        flags=re.DOTALL
                    )
                    return modified_template.strip()
                    
                return content
        except Exception as e:
            logger.error(f"Error reading prompt file {prompt_file}: {e}")
            return ""
            
