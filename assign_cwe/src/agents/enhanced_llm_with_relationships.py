# src/agents/enhanced_llm_with_relationships.py

from typing import List, Dict, Any, Optional
import logging
import os
from pathlib import Path

from .enhanced_llm import EnhancedLLMAgent
from retrievers.relationship_analyzer import CWERelationshipAnalyzer

from utils.logger import get_logger

logger = get_logger(__name__)

class RelationshipEnhancedLLMAgent(EnhancedLLMAgent):
    """Enhanced LLM Agent with relationship analysis capabilities."""
    
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
        cwe_database_path: str = None,
        output_dir: str = "./output/relationship_analysis"
    ):
        """
        Initialize a relationship-enhanced LLM agent.
        
        Args:
            role: The role of this agent ("analyzer", "critic", or "resolver")
            llm_provider: The LLM provider to use
            llm_config: Configuration for the LLM
            context_limit: Maximum number of previous interactions to maintain
            max_iterations: Maximum number of iterations for feedback loop
            max_input_length: Maximum length of input text
            embedding_client: Embedding client instance
            retriever: Optional existing retriever to use
            cwe_database_path: Path to CWE database JSON file
            output_dir: Directory for saving relationship visualizations
        """
        # First, import the relationship utility
        from utils.cwe_relationship_utils import build_bidirectional_relationships

        
        super().__init__(
            role=role,
            llm_provider=llm_provider,
            llm_config=llm_config,
            context_limit=context_limit,
            max_iterations=max_iterations,
            max_input_length=max_input_length,
            embedding_client=embedding_client,
            retriever=retriever,
            cwe_database_path=cwe_database_path
        )
        
        # Initialize relationship analyzer
        self.relationship_analyzer = None
        self.output_dir = output_dir
        
        # If we have CWE entries, enhance them with bidirectional relationships
        if hasattr(self, 'cwe_entries') and self.cwe_entries:
            logger.info(f"Enhancing CWE entries with bidirectional relationships for {role} agent")
            self.cwe_entries = build_bidirectional_relationships(self.cwe_entries)
        
        # If we have the property graph from the retriever, initialize the analyzer
        if hasattr(self.retriever, 'property_graph'):
            self.relationship_analyzer = CWERelationshipAnalyzer(
                property_graph=self.retriever.property_graph,
                cwe_entries=self.cwe_entries,
                output_dir=output_dir
            )
            logger.info(f"Initialized relationship analyzer for {role} agent")
        else:
            logger.warning(f"Property graph not available; relationship analysis will not be available")
            
            
    
    def _call_llm(self, prompt):
        """
        Call the LLM with the given prompt using the Langchain LLM interface.
        
        Args:
            prompt: The prompt to send to the LLM
            
        Returns:
            Dict containing the response and usage information
        """
        try:
            # Create messages in the format Langchain expects for chat models
            messages = [{"role": "user", "content": prompt}]
            
            # Invoke the model through Langchain's unified interface
            response = self.llm.invoke(messages)
            
            # Extract the response content based on Langchain's return format
            if hasattr(response, 'content'):
                response_text = response.content
            else:
                # For models that might return different formats
                response_text = str(response)
                
            # Handle token usage if available
            usage = {}
            if hasattr(response, 'usage'):
                usage = response.usage
                
            return {
                "response": response_text,
                "usage": usage
            }
        except Exception as e:
            logger.error(f"Error calling LLM via Langchain: {e}")
            raise
    
    def generate_response(self, input_text: str) -> Dict[str, Any]:
        """
        Generate response with enhanced CWE context and relationship analysis.
        
        Args:
            input_text: The input text to process
            
        Returns:
            Dict containing:
                - response: The formatted response text
                - cwe_ids: List of extracted CWE IDs (for analyzer role)
                - relationship_analysis: Dictionary with relationship analysis results
        """
        # First, get the basic response from the parent class
        basic_response = super().generate_response(input_text)
        
        # Extract CWE IDs from the response
        cwe_ids = basic_response.get("cwe_ids", [])
        
        # Initialize relationship analysis result
        relationship_analysis = {
            "available": False,
            "mermaid_diagram": "",
            "abstraction_analysis": {},
            "chain_analysis": {},
            "summary": ""
        }
        
        # If we have relationship analyzer and CWE IDs, perform relationship analysis
        if self.relationship_analyzer and cwe_ids:
            try:
                # Get vulnerability description from input - this could be more sophisticated
                # based on your specific input format
                vulnerability_description = input_text
                
                # Perform comprehensive relationship analysis
                analysis_result = self.relationship_analyzer.incorporate_into_analysis(
                    cwe_ids=cwe_ids,
                    vulnerability_description=vulnerability_description
                )
                
                # Save visualizations
                if analysis_result.get("visualization_base64"):
                    # Save visualization for each CWE ID
                    for cwe_id in cwe_ids:
                        safe_cwe_id = cwe_id.replace('-', '_')
                        viz_filename = os.path.join(
                            self.output_dir, 
                            f"{safe_cwe_id}_relationship_viz.png"
                        )
                        # Save to file - if visualization_base64 is already a filename, this is redundant
                        # but doesn't hurt; if it's base64 data, this saves it
                        try:
                            import base64
                            # Check if it's a filename or base64 data
                            if os.path.exists(analysis_result["visualization_base64"]):
                                # It's a filename
                                viz_filename = analysis_result["visualization_base64"]
                            else:
                                # It's base64 data
                                img_data = base64.b64decode(analysis_result["visualization_base64"])
                                with open(viz_filename, 'wb') as f:
                                    f.write(img_data)
                                logger.info(f"Saved relationship visualization to {viz_filename}")
                        except Exception as e:
                            logger.error(f"Error saving visualization: {e}")
                
                # Update relationship analysis
                relationship_analysis = {
                    "available": True,
                    "mermaid_diagram": analysis_result.get("mermaid_diagram", ""),
                    "abstraction_analysis": analysis_result.get("abstraction_analysis", {}),
                    "chain_analysis": analysis_result.get("chain_analysis", {}),
                    "summary": analysis_result.get("relationship_summary", "")
                }
                
                logger.info(f"Generated relationship analysis for {len(cwe_ids)} CWEs")
                
            except Exception as e:
                logger.error(f"Error generating relationship analysis: {e}")
        
        # Return enhanced response
        return {
            "response": basic_response["response"],
            "cwe_ids": cwe_ids,
            "relationship_analysis": relationship_analysis
        }
    
    def _create_critic_input(self, analysis: str, description: str, cwe_specs: List[str]) -> str:
        """Create formatted input for the critic with markdown structure and relationship information.
        
        Args:
            analysis: The analyzer's analysis text (with relationship information)
            description: The vulnerability description
            cwe_specs: List of formatted CWE specifications
            
        Returns:
            Formatted critic input with markdown structure
        """
        # First call the parent method to get the base critic input format
        base_critic_input = super()._create_critic_input(analysis, description, cwe_specs)
        
        # The parent method already includes:
        # - Analysis to Review (which includes relationship information)
        # - Vulnerability Description
        # - Relevant CWE Specifications
        
        # If there's any additional relationship-specific context you want to add
        # for the critic, you can append it here
        
        return base_critic_input
    
    def enhance_response_with_relationships(self, response: str, relationship_analysis: Dict[str, Any]) -> str:
        """
        Enhance a response with relationship analysis information.
        
        Args:
            response: Original response text
            relationship_analysis: Relationship analysis results
            
        Returns:
            Enhanced response text
        """
        if not relationship_analysis or not relationship_analysis.get("available", False):
            return response
            
        # Create enhanced response sections
        relationship_sections = []
        
        # Add relationship summary
        if relationship_analysis.get("summary"):
            relationship_sections.append(f"""
## CWE Relationship Analysis

{relationship_analysis['summary']}
""")
        
        # Add abstraction level recommendations
        abstraction_analysis = relationship_analysis.get("abstraction_analysis", {})
        if abstraction_analysis:
            more_specific = abstraction_analysis.get("more_specific", [])
            alternatives = abstraction_analysis.get("alternatives", [])
            
            if more_specific or alternatives:
                relationship_sections.append("### Abstraction Level Recommendations")
                
                if more_specific:
                    # Format more specific CWEs
                    specific_items = [
                        f"- **{item['cwe_id']}**: {item['name']} ({item['type']})"
                        for item in more_specific[:3]  # Limit to top 3
                    ]
                    relationship_sections.append("**More Specific CWEs:**\n" + "\n".join(specific_items))
                
                if alternatives:
                    # Format alternative CWEs
                    alt_items = [
                        f"- **{item['cwe_id']}**: {item['name']} ({item['type']})"
                        for item in alternatives[:3]  # Limit to top 3
                    ]
                    relationship_sections.append("**Alternative CWEs:**\n" + "\n".join(alt_items))
        
        # Add chain analysis
        chain_analysis = relationship_analysis.get("chain_analysis", {})
        chains = chain_analysis.get("chains", [])
        if chains:
            relationship_sections.append("### Vulnerability Chain Analysis")
            
            for i, chain_info in enumerate(chains[:2]):  # Limit to 2 chains
                base_cwe = chain_info.get("base_cwe", "Unknown")
                chain_items = chain_info.get("chain", [])
                
                if chain_items:
                    chain_desc = f"**Chain starting from {base_cwe}:**\n"
                    
                    for item in chain_items:
                        chain_desc += f"- {item['cwe_id']} ({item['name']}) - {item['chain_position']}\n"
                    
                    relationship_sections.append(chain_desc)
        
        # Add Mermaid diagram
        if relationship_analysis.get("mermaid_diagram"):
            relationship_sections.append(f"""
### CWE Relationship Diagram

```mermaid
{relationship_analysis['mermaid_diagram']}
```
""")
        
        # Combine with original response
        enhanced_response = response.strip()
        
        # Check if we have content to add
        if relationship_sections:
            # Add separator if needed
            if not enhanced_response.endswith("\n\n"):
                enhanced_response += "\n\n"
                
            # Add relationship sections
            enhanced_response += "\n\n".join(relationship_sections)
        
        return enhanced_response
    
    def process_vulnerability(self, vulnerability_info, analysis_agent, critic_agent, resolver_agent):
        """
        Process a vulnerability with relationship-enhanced analysis.
        
        Args:
            vulnerability_info: Vulnerability information object
            analysis_agent: Analyzer agent
            critic_agent: Critic agent
            resolver_agent: Resolver agent
            
        Returns:
            Updated vulnerability info with analysis
        """
        # Ensure we have relationship analyzer
        if not self.relationship_analyzer and hasattr(self.retriever, 'property_graph'):
            self.relationship_analyzer = CWERelationshipAnalyzer(
                property_graph=self.retriever.property_graph,
                cwe_entries=self.cwe_entries,
                output_dir=self.output_dir
            )
        
        # Step 1: Generate initial analysis
        analysis_response = analysis_agent.generate_response(vulnerability_info.description)
        analysis_text = analysis_response["response"]
        identified_cwes = analysis_response.get("cwe_ids", [])
        
        # Store identified CWEs
        vulnerability_info.identified_cwes['analyzer'] = identified_cwes
        
        # Step 2: Enhance analysis with relationship information if available
        relationship_analysis = analysis_response.get("relationship_analysis", {})
        if relationship_analysis.get("available", False):
            # Save Mermaid diagram to file
            try:
                mermaid_dir = os.path.join(self.output_dir, "mermaid")
                os.makedirs(mermaid_dir, exist_ok=True)
                
                mermaid_filename = os.path.join(
                    mermaid_dir,
                    f"{vulnerability_info.cve_id}_relationships.md"
                )
                
                with open(mermaid_filename, 'w') as f:
                    f.write("```mermaid\n")  # Start mermaid code block
                    f.write(relationship_analysis.get("mermaid_diagram", ""))
                    f.write("\n```")  # End mermaid code block
                    
                logger.info(f"Saved Mermaid diagram to {mermaid_filename}")
            except Exception as e:
                logger.error(f"Error saving Mermaid diagram: {e}")
            
            # Enhance analysis with relationship information
            enhanced_analysis = self.enhance_response_with_relationships(
                analysis_text, 
                relationship_analysis
            )
            
            # Store both versions
            vulnerability_info.analysis = analysis_text
            vulnerability_info.analysis_with_relationships = enhanced_analysis
        else:
            # Just store the regular analysis
            vulnerability_info.analysis = analysis_text
            vulnerability_info.analysis_with_relationships = analysis_text
        
        # Step 3: Generate criticism
        critic_input = self._create_critic_input(
            vulnerability_info.analysis_with_relationships,
            vulnerability_info.description,
            self._get_detailed_cwe_specs(identified_cwes)
        )
        
        criticism_response = critic_agent.generate_response(critic_input)
        criticism_text = criticism_response["response"]
        vulnerability_info.criticism = criticism_text
        
        # Extract any additional CWEs suggested by the critic
        critic_cwes = criticism_response.get("cwe_ids", [])
        vulnerability_info.identified_cwes['critic_additional'] = [
            cwe for cwe in critic_cwes if cwe not in identified_cwes
        ]
        
        # Step 4: Generate final resolution
        # Combine analyzer and critic outputs
        resolver_input = f"""
# Vulnerability Description

{vulnerability_info.description}

# Initial Analysis

{vulnerability_info.analysis_with_relationships}

# Criticism

{vulnerability_info.criticism}

Based on the above information, provide a final determination on the most appropriate CWE classification.
"""
        
        resolution_response = resolver_agent.generate_response(resolver_input)
        resolution_text = resolution_response["response"]
        vulnerability_info.resolution = resolution_text
        
        return vulnerability_info
    
    def _get_detailed_cwe_specs(self, cwe_ids: List[str]) -> List[str]:
        """Get detailed CWE specifications for the given CWE IDs."""
        cwe_specs = []
        
        for cwe_id in cwe_ids:
            if not cwe_id.startswith("CWE-"):
                cwe_id = f"CWE-{cwe_id}"
                
            # Get CWE details from cwe_entries
            cwe = self._get_cwe_details(cwe_id)
            if cwe:
                cwe_specs.append(self._format_cwe_info(cwe))
        
        return cwe_specs


# Update main.py to use the relationship-enhanced agent

def main():
    # Parse arguments
    args = parse_args()
    
    # Load configuration
    config_manager = ConfigManager(args.config)
    
    # Initialize clients and services
    embedding_client = initialize_embedding_client(config_manager)
    
    # Initialize Neo4j for property graph
    neo4j_config = config_manager.get_neo4j_config()
    
    # Initialize the retriever with property graph capability
    retriever = EnhancedHybridRetriever(
        name="hybrid_retriever",
        llm_config=config_manager.get_llm_config()["llm_config"],
        embedding_client=embedding_client,
        neo4j_config=neo4j_config,
        output_dir="./output"
    )
    
    # Load CWE database
    cwe_entries = load_cwe_database(config_manager.config.cwe_database_path)
    retriever.load_data(cwe_entries)
    
    # Initialize agents with relationship-enhanced capabilities
    analyzer = RelationshipEnhancedLLMAgent(
        role="analyzer",
        llm_provider=config_manager.config.llm_config.get("llm_type", "anthropic"),
        llm_config=config_manager.get_llm_config()["llm_config"],
        max_iterations=config_manager.get_llm_config()["max_iterations"],
        max_input_length=config_manager.config.agent_config.get('max_input_length', 20000),
        context_limit=config_manager.config.agent_config.get('context_limit', 5),
        embedding_client=embedding_client,
        retriever=retriever,
        cwe_database_path=config_manager.config.cwe_database_path,
        output_dir=os.path.join(args.output_dir, "relationship_analysis")
    )
    
    critic = RelationshipEnhancedLLMAgent(
        role="critic",
        llm_provider=config_manager.config.llm_config.get("llm_type", "anthropic"),
        llm_config=config_manager.get_llm_config()["llm_config"],
        max_iterations=config_manager.get_llm_config()["max_iterations"],
        max_input_length=config_manager.config.agent_config.get('max_input_length', 20000),
        context_limit=config_manager.config.agent_config.get('context_limit', 5),
        embedding_client=embedding_client,
        retriever=retriever,
        cwe_database_path=config_manager.config.cwe_database_path,
        output_dir=os.path.join(args.output_dir, "relationship_analysis")
    )
    
    resolver = RelationshipEnhancedLLMAgent(
        role="resolver",
        llm_provider=config_manager.config.llm_config.get("llm_type", "anthropic"),
        llm_config=config_manager.get_llm_config()["llm_config"],
        max_iterations=config_manager.get_llm_config()["max_iterations"],
        max_input_length=config_manager.config.agent_config.get('max_input_length', 20000),
        context_limit=config_manager.config.agent_config.get('context_limit', 5),
        embedding_client=embedding_client,
        retriever=retriever,
        cwe_database_path=config_manager.config.cwe_database_path,
        output_dir=os.path.join(args.output_dir, "relationship_analysis")
    )
    
    # Initialize the processor with relationship-enhanced agents
    processor = VulnerabilityProcessor(
        analyzer=analyzer,
        critic=critic,
        resolver=resolver,
        retriever=retriever,
        embedding_client=embedding_client,
        output_dir=args.output_dir,
        config=config_manager.config.processor_config
    )
    
    # Process vulnerability files
    if args.file:
        result = processor.process_file(args.file)
        print_result(result)
    elif args.dir:
        results = processor.process_directory(args.dir)
        for result in results:
            print_result(result)
    else:
        print("No input specified. Please provide either --file or --dir argument.")

if __name__ == "__main__":
    main()