# src/retrievers/enhanced_hybrid.py

import re
import os
import logging
from typing import List, Dict, Any, Optional, Tuple
from .qdrant_retriever import QdrantDenseRetriever
from .sparse import SparseRetriever
from .neo4j_property_graph import CWEPropertyGraph
from models.cwe import CWEEntry
from langchain_anthropic import ChatAnthropic
from llama_index.llms.anthropic import Anthropic
logger = logging.getLogger(__name__)
from datetime import datetime
from utils.file_ops import ensure_directory, save_json, save_markdown
from utils.helpers import safe_access
from utils.score_normalization import normalize_score


class EnhancedHybridRetriever:
    """Enhanced hybrid retriever combining dense, sparse, and property graph retrieval."""
    
    def __init__(
        self,
        name: str,
        llm_config: dict,
        embedding_client: Any,
        neo4j_config: Dict[str, str],
        weights: Dict[str, float] = None,
        reranker: Optional[Any] = None,
        output_dir: str = "./output",
        cwe_entries = None  
    ):
        self.name = name
        self.cwe_entries = cwe_entries  # Store the CWE entries
        self.output_dir = output_dir  # Initialize the output_dir attribute
        
        if not isinstance(llm_config, dict):
            raise ValueError("llm_config must be a dictionary")
        
        # Instantiate an LLM for the retriever
        # Always use Anthropic for the retriever.
        # Anthropic for high-quality contextual summaries (cached for efficiency)
        self.llm = ChatAnthropic(
            model=llm_config.get("model", "claude-3-haiku-20240307"),  # Use a default Anthropic model
            temperature=llm_config.get("temperature", 0.7),
            max_tokens=llm_config.get("max_tokens", 1024)
        )
        
        self.embedding_client = embedding_client
        logger.info(f"LLM object type: {type(self.llm)}")
        
        self.dense_retriever = QdrantDenseRetriever(
            name=f"{name}_dense",
            location="./data/qdrant",
            embedding_client=embedding_client
        )
        
         # Initialize sparse retriever if cwe_entries is provided
        if cwe_entries:
            self.sparse_retriever = SparseRetriever(cwe_entries)
        else:
            self.sparse_retriever = None  # Will initialize during load_data
            
        
        
        # Initialize the property graph with the new non-Pydantic class
        try:
            # Note: The parameters remain the same, but now we're using our regular Python class
            # instead of a Pydantic model
            self.property_graph = CWEPropertyGraph(
                name=f"{name}_graph",
                url=neo4j_config.get("url", "bolt://localhost:7687"),
                username=neo4j_config.get("username", "neo4j"),
                password=neo4j_config.get("password", ""),
                llm_config=llm_config,  # Pass the whole config dict
                embedding_client=embedding_client,
                # Add storage_dir if needed
                storage_dir="./data/neo4j/property_graph"
            )
            logger.info("Successfully initialized property graph with Neo4j")
        except Exception as e:
            logger.error(f"Failed to initialize property graph: {e}")
            raise
        
        self.rag_retriever = self.dense_retriever
        self.weights = weights or {'dense': 0.35, 'sparse': 0.4, 'graph': 0.25}
        if not self._validate_weights():
            raise ValueError("Weights must sum to 1 and be non-negative.")
        self.reranker = reranker
        self.loaded = False
        logger.info("Initialized EnhancedHybridRetriever '%s' with weights: %s", name, self.weights)
            
            
            
    def _enhance_results_with_mapping_info(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enhance all results with mapping information from the CWE database.
        This is a centralized function to ensure consistent mapping information.
        
        Args:
            results: The list of results to enhance
            
        Returns:
            Enhanced results with mapping information
        """
        if not self.cwe_entries:
            return results
            
        enhanced_results = []
        
        for result in results:
            enhanced_result = result.copy()
            
            # Get CWE ID
            cwe_id = None
            if "metadata" in result and "doc_id" in result["metadata"]:
                cwe_id = result["metadata"]["doc_id"]
            elif "cwe_id" in result:
                cwe_id = result["cwe_id"]
                
            if not cwe_id:
                enhanced_results.append(enhanced_result)
                continue
                
            # Normalize CWE ID
            if cwe_id.startswith("CWE-"):
                cwe_id = cwe_id.replace("CWE-", "")
                
            # Find the CWE entry
            cwe_entry = next((cwe for cwe in self.cwe_entries if cwe.ID == cwe_id), None)
            
            # If no metadata, initialize it
            if "metadata" not in enhanced_result:
                enhanced_result["metadata"] = {}
                
            # Extract mapping notes if CWE entry exists
            if cwe_entry and hasattr(cwe_entry, 'MappingNotes') and cwe_entry.MappingNotes:
                mapping_notes = {}
                
                # Extract Usage field - the most important one we need
                if hasattr(cwe_entry.MappingNotes, 'Usage'):
                    mapping_notes["usage"] = cwe_entry.MappingNotes.Usage
                elif isinstance(cwe_entry.MappingNotes, dict) and "Usage" in cwe_entry.MappingNotes:
                    mapping_notes["usage"] = cwe_entry.MappingNotes["Usage"]
                
                # Extract Rationale field
                if hasattr(cwe_entry.MappingNotes, 'Rationale'):
                    mapping_notes["rationale"] = cwe_entry.MappingNotes.Rationale
                elif isinstance(cwe_entry.MappingNotes, dict) and "Rationale" in cwe_entry.MappingNotes:
                    mapping_notes["rationale"] = cwe_entry.MappingNotes["Rationale"]
                
                # Extract Comments field
                if hasattr(cwe_entry.MappingNotes, 'Comments'):
                    mapping_notes["comments"] = cwe_entry.MappingNotes.Comments
                elif isinstance(cwe_entry.MappingNotes, dict) and "Comments" in cwe_entry.MappingNotes:
                    mapping_notes["comments"] = cwe_entry.MappingNotes["Comments"]
                
                # Extract Reasons field
                if hasattr(cwe_entry.MappingNotes, 'Reasons'):
                    mapping_notes["reasons"] = list(cwe_entry.MappingNotes.Reasons) if hasattr(cwe_entry.MappingNotes.Reasons, '__iter__') else [cwe_entry.MappingNotes.Reasons]
                elif isinstance(cwe_entry.MappingNotes, dict) and "Reasons" in cwe_entry.MappingNotes:
                    reasons = cwe_entry.MappingNotes["Reasons"]
                    mapping_notes["reasons"] = list(reasons) if hasattr(reasons, '__iter__') else [reasons]
                    
                # Extract Suggestions field
                if hasattr(cwe_entry.MappingNotes, 'Suggestions'):
                    mapping_notes["suggestions"] = list(cwe_entry.MappingNotes.Suggestions) if hasattr(cwe_entry.MappingNotes.Suggestions, '__iter__') else [cwe_entry.MappingNotes.Suggestions]
                elif isinstance(cwe_entry.MappingNotes, dict) and "Suggestions" in cwe_entry.MappingNotes:
                    suggestions = cwe_entry.MappingNotes["Suggestions"]
                    mapping_notes["suggestions"] = list(suggestions) if hasattr(suggestions, '__iter__') else [suggestions]
                
                enhanced_result["metadata"]["mapping_notes"] = mapping_notes
            else:
                # Set default mapping notes
                enhanced_result["metadata"]["mapping_notes"] = {"usage": "Not specified", "rationale": ""}
                
            enhanced_results.append(enhanced_result)
        
        return enhanced_results
            

    def _format_sparse_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Format results from the sparse retriever to match the expected format.
        Store original scores without normalization and add proper abstraction and mapping info.
        
        This formats for internal processing - a different format is used for JSON logging.
        """
        formatted_results = []
        for result in results:
            # Store original score
            original_score = result.get('score', 0.0)
            
            # Get CWE ID - ensure consistency for internal processing
            cwe_id = result.get('cwe_id', '')
            
            # For internal processing, ensure we have the full CWE-ID format
            internal_cwe_id = cwe_id
            if cwe_id and not isinstance(cwe_id, str):
                internal_cwe_id = f"CWE-{cwe_id}"
            elif cwe_id and isinstance(cwe_id, str) and not cwe_id.startswith("CWE-"):
                internal_cwe_id = f"CWE-{cwe_id}"
            
            # Look up abstraction level from CWE entries
            abstraction = result.get('abstraction', '')
            if not abstraction:
                # Try to find from database
                numeric_id = cwe_id
                if isinstance(cwe_id, str) and cwe_id.startswith("CWE-"):
                    numeric_id = cwe_id.replace("CWE-", "")
                    
                if hasattr(self, 'cwe_entries') and self.cwe_entries:
                    for entry in self.cwe_entries:
                        if hasattr(entry, 'ID') and entry.ID == numeric_id:
                            abstraction = entry.Abstraction
                            break
            
            formatted_results.append({
                'metadata': {
                    'doc_id': internal_cwe_id,  # Use CWE-ID format for internal processing
                    'name': result['name'],
                    'type': abstraction,  # Use correct abstraction from CWE database
                    'original_content': result.get('description', ''),
                    'relationships': [],  # Empty relationships list for sparse results
                    'original_sparse_score': original_score  # Keep original score for reference
                },
                'similarity': original_score  # Use original score, will be normalized later
            })
        
        # Now enhance with mapping information
        formatted_results = self._enhance_results_with_mapping_info(formatted_results)
        return formatted_results


    def _validate_weights(self) -> bool:
        total_weight = sum(self.weights.values())
        return abs(total_weight - 1.0) < 1e-6 and all(w >= 0 for w in self.weights.values())
    
    def load_data(self, dataset: List[CWEEntry]):
        try:
            from utils.cwe_relationship_utils import build_bidirectional_relationships
            
            # Add bidirectional relationships before loading into retrievers
            logger.info("Enhancing CWE entries with bidirectional relationships")
            enhanced_dataset = build_bidirectional_relationships(dataset)
            
            # Store the enhanced CWE entries reference
            self.cwe_entries = enhanced_dataset
            
            # Load into dense retriever
            self.dense_retriever.load_data([
                {
                    'doc_id': entry.ID,
                    'entry': entry,
                    'content': entry.to_searchable_text()
                }
                for entry in enhanced_dataset
            ])
            
            # Initialize sparse retriever
            self.sparse_retriever = SparseRetriever(enhanced_dataset)
            
            # Load into property graph
            self.property_graph.load_data(enhanced_dataset)
            
            self.loaded = True
            logger.info("Data loaded successfully into EnhancedHybridRetriever '%s' with bidirectional relationships", self.name)
        except Exception as e:
            logger.error("Error loading data: %s", e)
            raise
        
    def log_search_details(self, cve_id, query, keyphrases, results, method_name):
        """
        Log search details to a file in the CVE directory.
        
        Args:
            cve_id: The CVE identifier
            query: The query string
            keyphrases: The keyphrases dictionary
            results: The search results
            method_name: Name of the search method
        """
        try:
            # If cve_id is None or not in expected format, use a default
            if not cve_id or cve_id == "unknown" or not cve_id.startswith("CVE-"):
                logger.debug(f"Skipping search log for invalid CVE ID: {cve_id}")
                return
                
            # Determine the CVE directory using the same logic as in process_vulnerability
            cve_dir = os.path.join(self.output_dir, cve_id)
            ensure_directory(cve_dir)
            
            # Create a log file for search details
            log_file = os.path.join(cve_dir, f"{cve_id}_{method_name}_search_log.json")
            
            # Prepare log data
            log_data = {
                "method": method_name,
                "query": query,
                "keyphrases": keyphrases,
                "timestamp": datetime.now().isoformat(),
                "results_count": len(results),
                "results_summary": [
                    {
                        "doc_id": result.get("metadata", {}).get("doc_id", "unknown") 
                                if "metadata" in result else result.get("cwe_id", "unknown"),
                        "name": result.get("metadata", {}).get("name", "unknown") 
                            if "metadata" in result else result.get("name", "unknown"),
                        "score": result.get("similarity", 0.0) if "similarity" in result else result.get("score", 0.0)
                    }
                    for result in results[:5]  # Log only top 5 results for brevity
                ]
            }
            
            # Save the log
            save_json(log_file, log_data)
            
            # Also log to standard logger
            logger.debug(f"Logged {method_name} search details for {cve_id} to {log_file}")
            
        except Exception as e:
            logger.error(f"Failed to log search details: {e}")


    def _prepare_keyphrases(self, keyphrases: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Filter keyphrases to include only rootcause and weakness.
        Handles both string and list values for keyphrases.
        
        Args:
            keyphrases: Dictionary of keyphrases
            
        Returns:
            Dictionary with filtered keyphrases (preserving original types)
        """
        filtered_keyphrases = {}
        if keyphrases:
            # Handle rootcause (can be string or list)
            if 'rootcause' in keyphrases and keyphrases['rootcause']:
                filtered_keyphrases['rootcause'] = keyphrases['rootcause']
                
            # Handle weakness (can be string or list)
            if 'weakness' in keyphrases and keyphrases['weakness']:
                filtered_keyphrases['weakness'] = keyphrases['weakness']
            
            # Log which keyphrases are being used
            if filtered_keyphrases:
                self._log_keyphrases(filtered_keyphrases)
                
        return filtered_keyphrases


    def _log_keyphrases(self, keyphrases: Dict[str, Any]) -> None:
        """
        Log keyphrases in a readable format, handling both string and list values.
        
        Args:
            keyphrases: Dictionary of keyphrases
        """
        keyphrase_strs = []
        
        for key, value in keyphrases.items():
            if isinstance(value, str):
                keyphrase_strs.append(f"{key}: '{value}'")
            elif isinstance(value, list):
                # Format list values as comma-separated strings in quotes
                formatted_list = ", ".join([f"'{item}'" for item in value if item])
                keyphrase_strs.append(f"{key}: [{formatted_list}]")
        
        if keyphrase_strs:
            logger.debug(f"Using keyphrases for search: {', '.join(keyphrase_strs)}")

    def _execute_searches(
        self, 
        query: str, 
        filtered_keyphrases: Dict[str, str],
        k: int,
        use_graph: bool,
        use_rag: bool,
        use_sparse: bool,
        cve_id: str = None,
        **kwargs
    ) -> Tuple[List[Dict[str, Any]], Dict[str, List[str]], Dict[str, Dict[str, float]], Dict[str, List[Dict[str, Any]]]]:
        """Execute searches using all enabled retrievers, passing results between them."""
        all_results = []
        result_sources = {}  # cwe_id -> list of retrievers
        result_scores = {}   # cwe_id -> {retriever: score}
        retriever_results = {
            "graph": [],
            "dense": [],
            "sparse": []
        }
        
        # First, get results from RAG and sparse retrievers
        rag_results = []
        sparse_results = []
        
        # Get results from RAG if enabled
        if use_rag:
            try:
                logger.info(f"Executing dense retriever search for query: {query[:50]}..." if len(query) > 50 else query)
                rag_results = self._search_with_rag(query, filtered_keyphrases, k, **kwargs)
                logger.info(f"Dense retriever returned {len(rag_results)} results")
                retriever_results["dense"] = rag_results
                
                # Process and add to all_results
                formatted_rag_results = self._format_rag_results(rag_results)
                all_results.extend(formatted_rag_results)
                
                # Track which results came from dense retriever
                self._track_result_sources(formatted_rag_results, result_sources, result_scores, "dense")
            except Exception as e:
                logger.error(f"Error executing dense retriever search: {e}")
        
        # Get results from sparse retriever if enabled
        if use_sparse and self.sparse_retriever:
            try:
                logger.info(f"Executing sparse retriever search for query: {query[:50]}..." if len(query) > 50 else query)
                sparse_results = self._search_with_sparse(query, filtered_keyphrases, k, cve_id, **kwargs)
                logger.info(f"Sparse retriever returned {len(sparse_results)} results")
                retriever_results["sparse"] = sparse_results
                
                # Process and add to all_results
                formatted_sparse_results = self._format_sparse_results(sparse_results)
                all_results.extend(formatted_sparse_results)
                
                # Track which results came from sparse retriever
                self._track_result_sources(formatted_sparse_results, result_sources, result_scores, "sparse")
            except Exception as e:
                logger.error(f"Error executing sparse retriever search: {e}")
        
        # Get results from property graph last, passing in the RAG and sparse results
        if use_graph:
            try:
                logger.info(f"Executing graph retriever search with dense and sparse results as starting points")
                graph_results = self._search_with_graph(
                    query, k, 
                    dense_results=rag_results, 
                    sparse_results=sparse_results,
                    **kwargs
                )
                logger.info(f"Graph retriever returned {len(graph_results)} results")
                    
                # Store the raw results
                retriever_results["graph"] = graph_results
                
                # Process the results
                formatted_graph_results = self._format_graph_results(graph_results)
                all_results.extend(formatted_graph_results)
                    
                # Track which results came from graph retriever
                self._track_result_sources(formatted_graph_results, result_sources, result_scores, "graph")
            except Exception as e:
                logger.error(f"Error executing graph retriever search: {e}")
        
        return all_results, result_sources, result_scores, retriever_results

    def _search_with_graph(
        self, 
        query: str, 
        k: int, 
        dense_results=None, 
        sparse_results=None, 
        **kwargs
    ) -> List[Dict[str, Any]]:
        """Perform search with property graph retriever, using dense and sparse results as starting points."""
        try:
            # Log information about inputs to graph search
            dense_count = len(dense_results) if dense_results else 0
            sparse_count = len(sparse_results) if sparse_results else 0
            
            logger.info(f"Executing property graph search with {dense_count} dense and {sparse_count} sparse results as starting points")
            
            # Make sure the property_graph is initialized
            if not hasattr(self, 'property_graph') or self.property_graph is None:
                logger.error("Property graph is not initialized")
                return []
                
            # Extract CWE IDs from dense and sparse results
            extracted_cwes = []
            
            # Process dense results
            if dense_results:
                # Extract CWE IDs from dense results
                for result in dense_results[:5]:  # Take top 5
                    if 'metadata' in result and 'doc_id' in result['metadata']:
                        doc_id = result['metadata']['doc_id']
                        # Add CWE- prefix if not present
                        if not doc_id.startswith("CWE-"):
                            doc_id = f"CWE-{doc_id}"
                        extracted_cwes.append(doc_id)
            
            # Process sparse results
            if sparse_results:
                # Extract CWE IDs from sparse results
                for result in sparse_results[:5]:  # Take top 5
                    # Sparse retriever uses 'cwe_id' field directly
                    if 'cwe_id' in result:
                        doc_id = result['cwe_id']
                        # Add CWE- prefix if not present
                        if not doc_id.startswith("CWE-"):
                            doc_id = f"CWE-{doc_id}"
                        extracted_cwes.append(doc_id)
                        
            # Create an enhanced query that includes the extracted CWEs
            enhanced_query = query
            if extracted_cwes:
                extracted_cwes = list(set(extracted_cwes))  # Deduplicate
                cwe_mentions = " ".join(extracted_cwes)
                # Add the CWE IDs to the query
                enhanced_query = f"{query} Consider specifically these CWEs: {cwe_mentions}"
                logger.info(f"Enhanced query with {len(extracted_cwes)} CWEs from retriever results")
                
            # Execute the search using the enhanced query
            import time  # Add local import in case global import is missing
            start_time = time.time()
            
            # Call the original search method but WITHOUT passing the dense/sparse results
            # This avoids the parameter mismatch error
            results = self.property_graph.search(
                enhanced_query, 
                k=k*2, 
                include_text=True, 
                keyphrases=kwargs.get('keyphrases')
            )
            elapsed = time.time() - start_time
            
            # Handle if property_graph.search returns None
            if results is None:
                logger.warning("Property graph search returned None")
                return []
                
            logger.info(f"Property graph search returned {len(results)} results in {elapsed:.2f}s")
                
            # Standardize CWE IDs by removing "CWE-" prefix
            for result in results:
                if isinstance(result, dict) and "cwe_id" in result and result["cwe_id"].startswith("CWE-"):
                    result["cwe_id"] = result["cwe_id"].replace("CWE-", "")
            
            # Log top results
            if results:
                logger.debug("Top results from property graph search:")
                for i, result in enumerate(results[:3]):
                    doc_id = result.get('doc_id', result.get('metadata', {}).get('doc_id', 'unknown'))
                    name = result.get('name', result.get('metadata', {}).get('name', 'unknown'))
                    score = result.get('similarity', 0.0)
                    logger.debug(f"  Graph #{i+1}: CWE-{doc_id} ({name}) with score {score:.4f}")
                    
            return results
        except Exception as e:
            import traceback
            logger.warning(f"Property graph search failed: {e}")
            logger.debug(f"Traceback: {traceback.format_exc()}")
            return []
        
        
    def _track_result_sources(
        self, 
        results: List[Dict[str, Any]], 
        result_sources: Dict[str, List[str]], 
        result_scores: Dict[str, Dict[str, float]],
        retriever_name: str
    ) -> None:
        """Track which results came from which retriever."""
        for result in results:
            cwe_id = result.get("metadata", {}).get("doc_id")
            if cwe_id:
                # Normalize CWE ID for tracking
                if not cwe_id.startswith("CWE-"):
                    cwe_id = f"CWE-{cwe_id}"
                    
                if cwe_id not in result_sources:
                    result_sources[cwe_id] = []
                    result_scores[cwe_id] = {}
                result_sources[cwe_id].append(retriever_name)
                result_scores[cwe_id][retriever_name] = result.get("similarity", 0.0)


    def _search_with_rag(self, query: str, filtered_keyphrases: Dict[str, Any], k: int, **kwargs) -> List[Dict[str, Any]]:
        """
        Perform search with RAG (dense) retriever.
        Handle both string and list values for keyphrases.
        
        Args:
            query: The search query
            filtered_keyphrases: Dictionary of keyphrases (string or list)
            k: Number of results to return
            **kwargs: Additional search parameters
            
        Returns:
            List of search results
        """
        try:
            # Enhance query with keyphrases - handle both string and list types
            enhanced_query = query
            if filtered_keyphrases:
                for key, phrase in filtered_keyphrases.items():
                    if phrase:
                        if isinstance(phrase, str):
                            enhanced_query += f" {key}: {phrase}"
                        elif isinstance(phrase, list):
                            # Join list items with 'and'
                            phrase_str = " and ".join([p for p in phrase if p])
                            if phrase_str:
                                enhanced_query += f" {key}: {phrase_str}"
            
            # Get results from dense retriever
            results = self.dense_retriever.search(enhanced_query, k=k*2, **kwargs)
            
            # Check if we got actual results
            if not results:
                logger.warning("Dense retriever returned no results")
                return []
                
            # Log the original results for debugging
            logger.debug(f"Dense retriever returned {len(results)} results")
            for i, r in enumerate(results[:3]):
                logger.debug(f"  Dense result #{i+1}: CWE-{r.get('metadata', {}).get('doc_id', 'unknown')}: {r.get('similarity', 0.0):.4f}")
            
            # Filter out results with zero scores
            valid_results = [r for r in results if r.get('similarity', 0.0) > 0.0001]
            
            if len(valid_results) < len(results):
                logger.warning(f"Filtered out {len(results) - len(valid_results)} dense results with zero scores")
                
            return valid_results
        except Exception as e:
            logger.warning(f"RAG search failed: {e}")
            return []



    def _search_with_sparse(
        self, 
        query: str, 
        filtered_keyphrases: Dict[str, Any], 
        k: int, 
        cve_id: str = None,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Perform search with sparse retriever.
        Handle both string and list values for keyphrases.
        
        Args:
            query: The search query
            filtered_keyphrases: Dictionary of keyphrases (string or list)
            k: Number of results to return
            cve_id: CVE identifier for logging
            **kwargs: Additional search parameters
            
        Returns:
            List of search results
        """
        try:
            current_cve_id = cve_id or "unknown"
            
            # Convert any list keyphrases to string format for sparse retriever if needed
            keyphrase_dict_for_sparse = {}
            if filtered_keyphrases:
                for key, value in filtered_keyphrases.items():
                    if isinstance(value, str):
                        keyphrase_dict_for_sparse[key] = value
                    elif isinstance(value, list):
                        # Join list items with 'and' for sparse retriever
                        joined_value = " and ".join([v for v in value if v])
                        if joined_value:
                            keyphrase_dict_for_sparse[key] = joined_value
            
            if filtered_keyphrases:
                # Make sure we have a valid keyphrase dict
                if keyphrase_dict_for_sparse:
                    sparse_results = self.sparse_retriever.search_with_keyphrases(
                        query, keyphrase_dict_for_sparse, k=k*2, separate_searches=True)
                    self.log_search_details(current_cve_id, query, filtered_keyphrases, 
                                        sparse_results, "sparse_with_keyphrases")
                else:
                    # Fall back to basic search if keyphrases couldn't be formatted properly
                    logger.warning("Keyphrases couldn't be formatted for sparse search, using basic search instead")
                    sparse_results = self.sparse_retriever.search(query, k=k*2)
                    self.log_search_details(current_cve_id, query, None, 
                                        sparse_results, "sparse_basic")
            else:
                sparse_results = self.sparse_retriever.search(query, k=k*2)
                self.log_search_details(current_cve_id, query, None, 
                                    sparse_results, "sparse_basic")
            
            return sparse_results
        except Exception as e:
            logger.warning(f"Sparse search failed: {e}")
            return []

    def _format_keyphrases(self, keyphrases: Dict[str, Any]) -> str:
        """
        Format keyphrases for markdown output.
        Handles both string and list values.
        
        Args:
            keyphrases: Dictionary of keyphrases
            
        Returns:
            Formatted markdown string
        """
        if not keyphrases:
            return "No keyphrases provided."
        
        lines = []
        for key, value in keyphrases.items():
            if isinstance(value, str):
                if value:  # Only add non-empty strings
                    lines.append(f"- **{key}**: {value}")
            elif isinstance(value, list):
                # Format list items as comma-separated string
                value_str = ", ".join([f"'{item}'" for item in value if item])
                if value_str:  # Only add if we have content
                    lines.append(f"- **{key}**: {value_str}")
        
        return "\n".join(lines) if lines else "No valid keyphrases provided."


    def _format_full_results_table(self, table_data: Dict[str, Any]) -> str:
        """
        Format the complete results table with all available columns.
        
        Args:
            table_data: Dictionary of table data from _build_results_table
            
        Returns:
            Formatted markdown table as a string
        """
        # Create table header with all columns
        table = """
| Rank | CWE ID | Name | Abstraction | Usage | Combined Score | Retrievers | Individual Scores |
|------|--------|------|-------------|-------|---------------|------------|-------------------|
"""
        
        # Add rows
        for row in table_data["rows"]:
            table += f"| {row['rank']} | {row['cwe_id']} | {row['name']} | {row['abstraction']} | {row['usage']} | {row['combined_score']:.4f} | {row['retrievers_str']} | {row['individual_scores_str']} |\n"
        
        return table


    def _build_results_table(self, results: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Build a comprehensive data structure with all result information for table generation.
        This method doesn't format the table, but prepares the data for formatting.
        
        Args:
            results: List of result dictionaries
            
        Returns:
            Dictionary with table data rows and metadata
        """
        table_data = {
            "rows": [],
            "total_count": len(results)
        }
        
        # Get the CWE database for abstraction lookups
        cwe_entries = getattr(self, 'cwe_entries', None)
        abstraction_lookup = {}
        
        # Build a lookup dictionary if we have the CWE entries
        if cwe_entries:
            for entry in cwe_entries:
                entry_id = getattr(entry, 'ID', '')
                if entry_id:
                    abstraction = getattr(entry, 'Abstraction', '')
                    abstraction_lookup[entry_id] = abstraction
        
        # Process each result into a standardized format
        for i, result in enumerate(results):
            metadata = result.get("metadata", {})
            score_info = metadata.get("score_info", {})
            mapping_notes = metadata.get("mapping_notes", {})
            
            # Get CWE ID without prefix
            cwe_id = metadata.get("doc_id", "Unknown")
            clean_cwe_id = cwe_id.replace("CWE-", "") if isinstance(cwe_id, str) else str(cwe_id)
            
            # Get the correct abstraction from the database
            if clean_cwe_id in abstraction_lookup:
                abstraction = abstraction_lookup[clean_cwe_id]
            else:
                abstraction = metadata.get("type", "Unknown")
            
            # Extract all possible fields
            row = {
                "rank": i + 1,
                "cwe_id": cwe_id,
                "name": metadata.get("name", "Unknown"),
                "abstraction": abstraction,  # Use abstraction from database
                "usage": mapping_notes.get("usage", "Not specified") if isinstance(mapping_notes, dict) else "Not specified",
                "combined_score": result.get("similarity", 0.0),
                "retrievers": score_info.get("retrievers", []),
                "retrievers_str": ", ".join(score_info.get("retrievers", [])) if score_info.get("retrievers") else "unknown",
                "normalized_scores": score_info.get("normalized_scores", {}),
                "individual_scores_str": ""
            }
            
            # Format individual scores
            if score_info.get("normalized_scores"):
                individual_scores = []
                for retriever, score in score_info.get("normalized_scores", {}).items():
                    individual_scores.append(f"{retriever}: {score:.3f}")
                row["individual_scores_str"] = ", ".join(individual_scores)
            
            table_data["rows"].append(row)
        
        return table_data


    def format_sparse_results_for_json(self, results):
        """Format sparse results for JSON output with correct CWE ID format."""
        formatted_results = []
        for r in results:
            # Get CWE ID - Remove CWE- prefix if present
            cwe_id = r.get("cwe_id", "unknown")
            if isinstance(cwe_id, str) and cwe_id.startswith("CWE-"):
                numeric_id = cwe_id.replace("CWE-", "")
            else:
                numeric_id = cwe_id
                
            # Default values
            name = r.get("name", "unknown")
            abstraction = r.get("abstraction", "unknown")
            mapping_usage = r.get("mapping_usage", "Not specified")
            
            # Try to enhance with actual CWE data
            if hasattr(self, 'cwe_entries') and self.cwe_entries and numeric_id != "unknown":
                cwe_entry = next((cwe for cwe in self.cwe_entries if cwe.ID == numeric_id), None)
                if cwe_entry:
                    name = cwe_entry.Name
                    abstraction = cwe_entry.Abstraction
                    
                    # Get mapping usage
                    if hasattr(cwe_entry, 'MappingNotes') and cwe_entry.MappingNotes:
                        if hasattr(cwe_entry.MappingNotes, 'Usage'):
                            mapping_usage = cwe_entry.MappingNotes.Usage
                        elif isinstance(cwe_entry.MappingNotes, dict) and "Usage" in cwe_entry.MappingNotes:
                            mapping_usage = cwe_entry.MappingNotes["Usage"]
            
            formatted_results.append({
                "cwe_id": numeric_id,  # Use numeric ID without CWE- prefix
                "name": name,
                "abstraction": abstraction,
                "score": r.get("score", 0.0),
                "original_score": r.get("original_score", r.get("score", 0.0)),
                "mapping_usage": mapping_usage
            })
        
        return formatted_results


    def _log_raw_results(
        self,
        cve_id: str,
        query: str,
        filtered_keyphrases: Dict[str, str],
        retriever_results: Dict[str, List[Dict[str, Any]]]
    ) -> None:
        """Log raw retriever results for inspection with enhanced visibility."""
        # First, ensure all results have mapping information
        for retriever_type in retriever_results:
            if retriever_results[retriever_type]:
                retriever_results[retriever_type] = self._enhance_results_with_mapping_info(retriever_results[retriever_type])
        
        # Create structured data for logging
        all_raw_results = {
            "query": query,
            "keyphrases": filtered_keyphrases,
            "timestamp": datetime.now().isoformat(),
            "retriever_config": {
                "weights": self.weights,
                "use_graph": len(retriever_results.get("graph", [])) > 0,
                "use_rag": len(retriever_results.get("dense", [])) > 0,
                "use_sparse": len(retriever_results.get("sparse", [])) > 0
            },
            "raw_results": {
                "graph": [
                    {
                        # Remove "CWE-" prefix from cwe_id
                        "cwe_id": r.get("cwe_id", "unknown").replace("CWE-", "") if isinstance(r.get("cwe_id", "unknown"), str) and r.get("cwe_id", "unknown").startswith("CWE-") else r.get("cwe_id", "unknown"),
                        "name": r.get("name", "Unknown"),
                        "abstraction": r.get("type", "unknown"),  # Changed from "type" to "abstraction"
                        "score": r.get("similarity", 0.0),
                        "description": r.get("metadata", {}).get("original_content", "")[:200] + "..." if r.get("metadata", {}).get("original_content") else "",
                        "mapping_usage": r.get("metadata", {}).get("mapping_notes", {}).get("usage", "Not specified")  # Added mapping usage
                    }
                    for r in retriever_results.get("graph", [])
                ],
                "dense": [
                    {
                        "cwe_id": r.get("metadata", {}).get("doc_id", "unknown"),
                        "name": r.get("metadata", {}).get("name", "unknown"),
                        "abstraction": r.get("metadata", {}).get("type", "unknown"),  # Changed from "type" to "abstraction"
                        "score": r.get("similarity", 0.0),
                        "description": r.get("metadata", {}).get("original_content", "")[:200] + "..." if r.get("metadata", {}).get("original_content") else "",
                        "mapping_usage": r.get("metadata", {}).get("mapping_notes", {}).get("usage", "Not specified")  # Added mapping usage
                    }
                    for r in retriever_results.get("dense", [])
                ],
                "sparse": [
                    {
                        "cwe_id": r.get("cwe_id", "unknown").replace("CWE-", "") if isinstance(r.get("cwe_id", "unknown"), str) and r.get("cwe_id", "unknown").startswith("CWE-") else r.get("cwe_id", "unknown"),
                        "name": r.get("name", "Unknown"),
                        "abstraction": self._get_abstraction_for_cwe(r.get("cwe_id", "unknown").replace("CWE-", "") if isinstance(r.get("cwe_id", "unknown"), str) and r.get("cwe_id", "unknown").startswith("CWE-") else r.get("cwe_id", "unknown")),
                        "score": r.get("score", 0.0) or r.get("similarity", 0.0),
                        "description": (r.get("description", "") or r.get("metadata", {}).get("original_content", ""))[:200] + "...",
                        "mapping_usage": r.get("metadata", {}).get("mapping_notes", {}).get("usage", "Not specified")  # Added mapping usage for sparse results
                    }
                    for r in retriever_results.get("sparse", [])
                ]
            },
            "score_statistics": {
                "dense": self._calculate_score_statistics(retriever_results.get("dense", [])),
                "sparse": self._calculate_score_statistics(retriever_results.get("sparse", []), score_key="score"),
                "graph": self._calculate_score_statistics(retriever_results.get("graph", []))
            }
        }
        
        # Save to file
        raw_results_file = os.path.join(self.output_dir, cve_id, f"{cve_id}_raw_retriever_results.json")
        save_json(raw_results_file, all_raw_results)
        
        # Log summary of raw results
        logger.info(f"Raw retriever results for {cve_id}:")
        
        # Create individual files for each retriever type to make analysis easier
        for retriever_type in ["graph", "dense", "sparse"]:
            results = retriever_results.get(retriever_type, [])
            if results:
                # Save detailed JSON for this retriever type
                type_file = os.path.join(self.output_dir, cve_id, f"{cve_id}_{retriever_type}_results.json")
                
                # Format results specific to retriever type - now all include mapping usage
                if retriever_type == "sparse":
                    # Special handling for sparse results
                    formatted_results = self.format_sparse_results_for_json(results)
                    
                    # Save the formatted results
                    save_json(type_file, {
                        "query": query,
                        "count": len(results),
                        "results": formatted_results,
                        "statistics": all_raw_results["score_statistics"][retriever_type]
                    })
                else:
                    # Standard handling for other retriever types
                    formatted_results = [
                        {
                            "cwe_id": r.get("metadata", {}).get("doc_id", "unknown") if "metadata" in r else r.get("cwe_id", "unknown"),
                            "name": r.get("metadata", {}).get("name", "unknown") if "metadata" in r else r.get("name", "unknown"),
                            "abstraction": r.get("metadata", {}).get("type", "unknown"),
                            "score": r.get("similarity", 0.0) if "similarity" in r else r.get("score", 0.0),
                            "original_score": r.get("original_similarity", r.get("similarity", 0.0)) if "similarity" in r else r.get("original_score", r.get("score", 0.0)),
                            "mapping_usage": r.get("metadata", {}).get("mapping_notes", {}).get("usage", "Not specified")
                        }
                        for r in results
                    ]
                        
                    save_json(type_file, {
                        "query": query,
                        "count": len(results),
                        "results": formatted_results,
                        "statistics": all_raw_results["score_statistics"][retriever_type]
                    })
        
        # Log graph results
        graph_results = retriever_results.get("graph", [])
        if graph_results:
            logger.info(f"  Graph: {len(graph_results)} results")
            for i, r in enumerate(graph_results[:5]):  # Show top 5 instead of 3
                cwe_id = r.get("metadata", {}).get("doc_id", "unknown")
                similarity = r.get("similarity", 0.0)
                name = r.get("metadata", {}).get("name", "unknown")
                # Also log mapping usage if available
                mapping_usage = r.get("metadata", {}).get("mapping_notes", {}).get("usage", "")
                mapping_str = f" (Usage: {mapping_usage})" if mapping_usage else ""
                logger.info(f"    {i+1}. CWE-{cwe_id} ({name}): {similarity:.4f}{mapping_str}")
        else:
            logger.info("  Graph: No results")
        
        # Log dense results
        dense_results = retriever_results.get("dense", [])
        if dense_results:
            logger.info(f"  Dense: {len(dense_results)} results")
            score_stats = all_raw_results["score_statistics"]["dense"]
            logger.info(f"    Score range: {score_stats['min']:.4f} - {score_stats['max']:.4f}, Mean: {score_stats['mean']:.4f}")
            for i, r in enumerate(dense_results[:5]):  # Show top 5 instead of 3
                cwe_id = r.get("metadata", {}).get("doc_id", "unknown")
                similarity = r.get("similarity", 0.0)
                original_similarity = r.get("original_similarity", similarity)
                name = r.get("metadata", {}).get("name", "unknown")
                # Also log mapping usage if available
                mapping_usage = r.get("metadata", {}).get("mapping_notes", {}).get("usage", "")
                mapping_str = f" (Usage: {mapping_usage})" if mapping_usage else ""
                logger.info(f"    {i+1}. CWE-{cwe_id} ({name}): {similarity:.4f} (original: {original_similarity:.4f}){mapping_str}")
        else:
            logger.info("  Dense: No results")
        
        # Log sparse results - now with mapping usage
        sparse_results = retriever_results.get("sparse", [])
        if sparse_results:
            logger.info(f"  Sparse: {len(sparse_results)} results")
            score_stats = all_raw_results["score_statistics"]["sparse"]
            logger.info(f"    Score range: {score_stats['min']:.4f} - {score_stats['max']:.4f}, Mean: {score_stats['mean']:.4f}")
            for i, r in enumerate(sparse_results[:5]):  # Show top 5 instead of 3
                cwe_id = r.get("cwe_id", "unknown") or r.get("metadata", {}).get("doc_id", "unknown")
                score = r.get("score", 0.0) or r.get("similarity", 0.0)
                original_score = r.get("original_score", score)
                name = r.get("name", "unknown") or r.get("metadata", {}).get("name", "unknown")
                # Also log mapping usage if available
                mapping_usage = r.get("metadata", {}).get("mapping_notes", {}).get("usage", "")
                mapping_str = f" (Usage: {mapping_usage})" if mapping_usage else ""
                logger.info(f"    {i+1}. CWE-{cwe_id} ({name}): {score:.4f} (original: {original_score:.4f}){mapping_str}")
        else:
            logger.info("  Sparse: No results")
        
        # Create a markdown report for easier viewing
        md_content = f"""# Raw Retriever Results for {cve_id}

## Query
{query}

## Keyphrases
{self._format_keyphrases(filtered_keyphrases)}

## Score Statistics
| Retriever | Min | Max | Mean | Median | Count |
|-----------|-----|-----|------|--------|-------|
| Dense | {all_raw_results["score_statistics"]["dense"]["min"]:.4f} | {all_raw_results["score_statistics"]["dense"]["max"]:.4f} | {all_raw_results["score_statistics"]["dense"]["mean"]:.4f} | {all_raw_results["score_statistics"]["dense"]["median"]:.4f} | {all_raw_results["score_statistics"]["dense"]["count"]} |
| Sparse | {all_raw_results["score_statistics"]["sparse"]["min"]:.4f} | {all_raw_results["score_statistics"]["sparse"]["max"]:.4f} | {all_raw_results["score_statistics"]["sparse"]["mean"]:.4f} | {all_raw_results["score_statistics"]["sparse"]["median"]:.4f} | {all_raw_results["score_statistics"]["sparse"]["count"]} |
| Graph | {all_raw_results["score_statistics"]["graph"]["min"]:.4f} | {all_raw_results["score_statistics"]["graph"]["max"]:.4f} | {all_raw_results["score_statistics"]["graph"]["mean"]:.4f} | {all_raw_results["score_statistics"]["graph"]["median"]:.4f} | {all_raw_results["score_statistics"]["graph"]["count"]} |

## Graph Retriever Results ({len(retriever_results.get('graph', []))})
| # | CWE ID | Name | Abstraction | Score | Mapping Usage |
|---|--------|------|-------------|-------|---------------|
"""
        # Add graph results to markdown
        for i, r in enumerate(retriever_results.get("graph", [])[:15]):  # Show top 15 instead of 10
            cwe_id = r.get("metadata", {}).get("doc_id", "unknown")
            name = r.get("metadata", {}).get("name", "unknown")
            cwe_type = r.get("metadata", {}).get("type", "unknown")
            similarity = r.get("similarity", 0.0)
            mapping_usage = r.get("metadata", {}).get("mapping_notes", {}).get("usage", "Not specified")
            md_content += f"| {i+1} | {cwe_id} | {name} | {cwe_type} | {similarity:.4f} | {mapping_usage} |\n"
        
        # Add dense results to markdown with both normalized and original scores
        md_content += f"""
## Dense Retriever Results ({len(retriever_results.get('dense', []))})
| # | CWE ID | Name | Abstraction | Score | Original Score | Mapping Usage |
|---|--------|------|-------------|-------|----------------|---------------|
"""
        for i, r in enumerate(retriever_results.get("dense", [])[:15]):  # Show top 15 instead of 10
            cwe_id = r.get("metadata", {}).get("doc_id", "unknown")
            name = r.get("metadata", {}).get("name", "unknown")
            cwe_type = r.get("metadata", {}).get("type", "unknown")
            similarity = r.get("similarity", 0.0)
            original_similarity = r.get("original_similarity", similarity)
            mapping_usage = r.get("metadata", {}).get("mapping_notes", {}).get("usage", "Not specified")
            md_content += f"| {i+1} | {cwe_id} | {name} | {cwe_type} | {similarity:.4f} | {original_similarity:.4f} | {mapping_usage} |\n"
        
        # Add sparse results to markdown with both normalized and original scores - now including mapping usage
        md_content += f"""
## Sparse Retriever Results ({len(retriever_results.get('sparse', []))})
| # | CWE ID | Name | Score | Original Score | Mapping Usage |
|---|--------|------|-------|---------------|---------------|
"""
        for i, r in enumerate(retriever_results.get("sparse", [])[:15]):  # Show top 15 instead of 10
            cwe_id = r.get("cwe_id", "unknown") or r.get("metadata", {}).get("doc_id", "unknown")
            name = r.get("name", "unknown") or r.get("metadata", {}).get("name", "unknown")
            score = r.get("score", 0.0) or r.get("similarity", 0.0)
            original_score = r.get("original_score", score)
            mapping_usage = r.get("metadata", {}).get("mapping_notes", {}).get("usage", "Not specified")
            md_content += f"| {i+1} | {cwe_id} | {name} | {score:.4f} | {original_score:.4f} | {mapping_usage} |\n"
        
        # Save markdown report
        md_file = os.path.join(self.output_dir, cve_id, f"{cve_id}_raw_retriever_results.md")
        save_markdown(md_file, f"Raw Retriever Results for {cve_id}", md_content)
        
    

    def _calculate_score_statistics(self, results, score_key="similarity"):
        """Calculate statistics for result scores."""
        if not results:
            return {"min": 0.0, "max": 0.0, "mean": 0.0, "median": 0.0, "count": 0}
        
        import numpy as np
        
        scores = []
        for r in results:
            # Handle different result formats
            if score_key == "similarity":
                score = r.get(score_key, 0.0)
            else:  # For sparse retriever
                score = r.get(score_key, 0.0)
            scores.append(score)
        
        return {
            "min": float(np.min(scores)),
            "max": float(np.max(scores)),
            "mean": float(np.mean(scores)),
            "median": float(np.median(scores)),
            "count": len(scores)
        }


    def _get_abstraction_for_cwe(self, cwe_id: str) -> str:
        """Get abstraction level for a CWE ID from the database."""
        if not hasattr(self, 'cwe_entries') or not self.cwe_entries:
            return "Unknown"
            
        # Remove CWE- prefix if present
        numeric_id = cwe_id.replace("CWE-", "") if isinstance(cwe_id, str) and cwe_id.startswith("CWE-") else cwe_id
        
        # Look up in CWE entries
        for entry in self.cwe_entries:
            if hasattr(entry, 'ID') and entry.ID == numeric_id:
                return entry.Abstraction
                
        return "Unknown"


    def _get_default_response(self) -> List[Dict[str, Any]]:
        """Return default response for when all searches fail."""
        logger.warning("No results from any search method. Returning default response.")
        return [{
            'metadata': {
                'doc_id': 'CWE-000',
                'name': 'Unknown',
                'type': 'Base',
                'original_content': 'No results found for the query.'
            },
            'similarity': 0.0
        }]


    def _process_result(
        self,
        result: Dict[str, Any],
        cwe_id: str,
        retrievers: List[str],
        result_scores: Dict[str, Dict[str, float]],
        retriever_scores: Dict[str, List[float]]
    ) -> Dict[str, Any]:
        """
        Process a single result and calculate its final score.
        
        Args:
            result: The result to process
            cwe_id: The CWE ID of the result
            retrievers: List of retrievers that found this CWE
            result_scores: Dictionary mapping CWE IDs to scores from each retriever
            retriever_scores: Dictionary mapping retriever types to lists of their scores
            
        Returns:
            Enhanced result with combined score
        """
        metadata = result.get("metadata", {})
        cwe_type = metadata.get("type", "").lower()
        
        # Determine if this is a graph-exclusive finding (not found by dense or sparse)
        is_graph_exclusive = "graph" in retrievers and not any(r in retrievers for r in ["dense", "sparse"])
        
        # 1. Calculate normalized scores for each retriever
        normalized_scores = self._calculate_normalized_scores(
            cwe_id, 
            retrievers, 
            result_scores, 
            retriever_scores
        )
        
        # Record the initial combined score before adjustments
        initial_combined_score = normalized_scores["combined_score"]
        adjustment_factors = {
            "initial_combined_score": initial_combined_score
        }
        
        # 2. Apply abstraction level adjustment based on CWE type
        abstraction_factor = self._get_abstraction_factor(cwe_type)
        adjustment_factors["abstraction"] = {
            "type": cwe_type,
            "factor": abstraction_factor,
            "score_after": initial_combined_score * abstraction_factor
        }
        
        # 3. Calculate relationship bonus for graph-discovered CWEs
        relationship_bonus, relationship_count = self._calculate_relationship_bonus(
            metadata, 
            is_graph_exclusive
        )
        adjustment_factors["relationship"] = {
            "count": relationship_count,
            "is_graph_exclusive": is_graph_exclusive,
            "bonus": relationship_bonus,
            "score_after": initial_combined_score * abstraction_factor * relationship_bonus
        }
        
        # 4. Calculate mapping guidance adjustment
        mapping_notes = metadata.get("mapping_notes", {})
        mapping_usage = mapping_notes.get("usage", "").upper() if isinstance(mapping_notes, dict) else ""
        mapping_boost = self._calculate_mapping_boost(metadata)
        adjustment_factors["mapping"] = {
            "usage": mapping_usage,
            "boost": mapping_boost,
            "notes": mapping_notes,
            "score_after": initial_combined_score * abstraction_factor * relationship_bonus * mapping_boost
        }
        
        # 5. Calculate final score
        combined_score = initial_combined_score * abstraction_factor * relationship_bonus * mapping_boost
        
        # Create enhanced result
        enhanced_result = result.copy()
        enhanced_result['similarity'] = combined_score
        
        # Store score details in metadata
        if 'metadata' not in enhanced_result:
            enhanced_result['metadata'] = {}
        
        enhanced_result['metadata']['score_info'] = {
            'retrievers': retrievers,
            'is_graph_exclusive': is_graph_exclusive,
            'raw_scores': result_scores[cwe_id],
            'normalized_scores': normalized_scores["individual_scores"],
            'weighted_scores': normalized_scores["weighted_scores"],
            'normalization_details': normalized_scores.get("normalization_details", {}),  # Added detailed normalization info
            'contribution_percentages': normalized_scores["contribution_percentages"],
            'abstraction_factor': abstraction_factor,
            'relationship_count': relationship_count,
            'relationship_bonus': relationship_bonus,
            'mapping_boost': mapping_boost,
            'mapping_usage': mapping_usage,  # Added mapping usage explicitly
            'adjustment_factors': adjustment_factors,  # Added step-by-step adjustment tracking
            'combined_score': combined_score
        }
        
        # Log score details
        logger.debug(f"Consolidated result for CWE-{cwe_id}:")
        logger.debug(f"  Retrievers: {retrievers}")
        logger.debug(f"  Raw scores: {result_scores[cwe_id]}")
        logger.debug(f"  Normalized scores: {normalized_scores['individual_scores']}")
        logger.debug(f"  Is graph exclusive: {is_graph_exclusive}")
        logger.debug(f"  Abstraction type: {cwe_type}, factor: {abstraction_factor}")
        if relationship_count > 0:
            logger.debug(f"  Relationship bonus: {relationship_bonus:.2f} (from {relationship_count} relationships)")
        if mapping_usage:
            logger.debug(f"  Mapping usage: {mapping_usage}, boost: {mapping_boost:.2f}")
        logger.debug(f"  Initial score: {initial_combined_score:.4f}, Final score: {combined_score:.4f}")
        
        return enhanced_result


    def consolidate_results(
        self,
        all_results: List[Dict[str, Any]],
        result_sources: Dict[str, List[str]],
        result_scores: Dict[str, Dict[str, float]]
    ) -> List[Dict[str, Any]]:
        """
        Consolidate results with enhanced scoring that considers multiple factors.
        Also ensures all results have mapping information and correct abstraction levels.
        
        Args:
            all_results: All raw results from all retrievers
            result_sources: Dictionary mapping CWE IDs to lists of retrievers that found them
            result_scores: Dictionary mapping CWE IDs to scores from each retriever
            
        Returns:
            List of consolidated results with combined scores
        """
        # First, enhance all results with mapping information
        enhanced_results = self._enhance_results_with_mapping_info(all_results)
        
        # Deduplicate by CWE ID and preserve needed information
        unique_results = self._deduplicate_results(enhanced_results)
        
        # Collect scores by retriever type for normalization context
        retriever_scores = self._collect_retriever_scores(result_scores)
        
        # Build a CWE ID to abstraction lookup from our knowledge base
        abstraction_lookup = {}
        if hasattr(self, 'cwe_entries') and self.cwe_entries:
            for entry in self.cwe_entries:
                if hasattr(entry, 'ID') and hasattr(entry, 'Abstraction'):
                    abstraction_lookup[entry.ID] = entry.Abstraction
        
        # Process each result and calculate final scores
        consolidated_results = []
        for result in unique_results:
            cwe_id = result.get("metadata", {}).get("doc_id")
            if not cwe_id or cwe_id not in result_sources:
                continue
            
            # Get which retrievers found this CWE
            retrievers = result_sources[cwe_id]
            
            # Skip if no retrievers found this CWE (shouldn't happen but just in case)
            if not retrievers:
                continue
            
            # Fix abstraction level from the database if available
            if cwe_id.replace("CWE-", "") in abstraction_lookup:
                result["metadata"]["type"] = abstraction_lookup[cwe_id.replace("CWE-", "")]
            
            # If not in the database, try to find the correct abstraction from dense or graph retrievers
            # since they seem to have more reliable abstraction information
            elif len(retrievers) > 1:
                # Find all results for this CWE ID
                cwe_results = [r for r in all_results if r.get("metadata", {}).get("doc_id") == cwe_id]
                
                # Look for abstraction from dense or graph retriever
                for cwe_result in cwe_results:
                    retriever_type = None
                    # Try to determine which retriever this result came from
                    if 'metadata' in cwe_result and 'source' in cwe_result['metadata']:
                        retriever_type = cwe_result['metadata']['source']
                    
                    # Prioritize dense or graph retriever results
                    if retriever_type in ['dense', 'graph'] and 'type' in cwe_result['metadata']:
                        # Use this abstraction and break the loop
                        result['metadata']['type'] = cwe_result['metadata']['type']
                        break
                        
            # Process this result
            enhanced_result = self._process_result(
                result, 
                cwe_id, 
                retrievers, 
                result_scores, 
                retriever_scores
            )
            
            consolidated_results.append(enhanced_result)
        
        # Sort by combined score
        consolidated_results.sort(key=lambda x: x['similarity'], reverse=True)
        return consolidated_results
    
    
    def _collect_retriever_scores(self, result_scores: Dict[str, Dict[str, float]]) -> Dict[str, List[float]]:
        """
        Collect all scores by retriever type for normalization context.
        
        Args:
            result_scores: Dictionary mapping CWE IDs to scores from each retriever
            
        Returns:
            Dictionary mapping retriever types to lists of their scores
        """
        retriever_scores = {
            "sparse": [],
            "dense": [],
            "graph": []
        }
        
        for cwe_id, scores_by_retriever in result_scores.items():
            for retriever, score in scores_by_retriever.items():
                if retriever in retriever_scores:
                    retriever_scores[retriever].append(score)
        
        logger.debug(f"Collected score ranges - Dense: {min(retriever_scores['dense']) if retriever_scores['dense'] else 0} to {max(retriever_scores['dense']) if retriever_scores['dense'] else 0}, Sparse: {min(retriever_scores['sparse']) if retriever_scores['sparse'] else 0} to {max(retriever_scores['sparse']) if retriever_scores['sparse'] else 0}, Graph: {min(retriever_scores['graph']) if retriever_scores['graph'] else 0} to {max(retriever_scores['graph']) if retriever_scores['graph'] else 0}")
        
        return retriever_scores
    
    def _calculate_normalized_scores(
        self,
        cwe_id: str,
        retrievers: List[str],
        result_scores: Dict[str, Dict[str, float]],
        retriever_scores: Dict[str, List[float]]
    ) -> Dict[str, Any]:
        """
        Calculate normalized scores for each retriever.
        
        Args:
            cwe_id: The CWE ID
            retrievers: List of retrievers that found this CWE
            result_scores: Dictionary mapping CWE IDs to scores from each retriever
            retriever_scores: Dictionary mapping retriever types to lists of their scores
            
        Returns:
            Dictionary with normalized and weighted scores, and final combined score
        """

        individual_scores = {}
        weighted_scores = {}
        normalization_details = {}  # New: track details of normalization
        
        # Normalize scores for each retriever
        for retriever in retrievers:
            if retriever not in ["dense", "sparse", "graph"]:
                continue
                
            raw_score = result_scores[cwe_id].get(retriever, 0.0)
            query_scores = retriever_scores[retriever]
            
            # Store the raw score for reference
            normalization_details[retriever] = {
                "raw_score": raw_score,
                "query_max": max(query_scores) if query_scores else 0.0,
                "query_min": min(query_scores) if query_scores else 0.0
            }
            
            # Normalize the score using the normalize_score function
            normalized_score = normalize_score(retriever, raw_score, query_scores)
            individual_scores[retriever] = normalized_score
            normalization_details[retriever]["normalized_score"] = normalized_score
            
            # Apply base weighting from config
            weight = self.weights.get(retriever, 0.33)
            weighted_scores[retriever] = normalized_score * weight
            normalization_details[retriever]["weight"] = weight
            normalization_details[retriever]["weighted_score"] = weighted_scores[retriever]
        
        # CHANGED: Simply add the weighted scores from all retrievers
        combined_score = sum(weighted_scores.values())
        
        # Calculate contribution percentages
        total_contribution = sum(weighted_scores.values()) if sum(weighted_scores.values()) > 0 else 1.0
        contribution_percentages = {
            retriever: (weighted_scores[retriever] / total_contribution) * 100 
            for retriever in weighted_scores
        }
        
        return {
            "individual_scores": individual_scores,
            "weighted_scores": weighted_scores,
            "contribution_percentages": contribution_percentages,
            "normalization_details": normalization_details,  # New: include details
            "combined_score": combined_score
        }
        
    
    def _get_abstraction_factor(self, cwe_type: str) -> float:
        """
        Get abstraction adjustment factor based on CWE type.
        
        Args:
            cwe_type: The type of the CWE
            
        Returns:
            Adjustment factor
        """
        if cwe_type == "base":
            return 1.3  # Favor Base CWEs
        elif cwe_type == "variant":
            return 1.2  # Also favor Variant CWEs
        elif cwe_type == "class":
            return 0.8  # Discourage Class CWEs
        elif cwe_type == "pillar":
            return 0.6  # Strongly discourage Pillar CWEs
        else:
            return 1.0  # Default for unknown types
    
    def _calculate_relationship_bonus(
            self,
            metadata: Dict[str, Any],
            is_graph_exclusive: bool
        ) -> Tuple[float, int]:
        """
        Calculate relationship bonus for graph-discovered CWEs.
        
        Args:
            metadata: CWE metadata
            is_graph_exclusive: Whether this is a graph-exclusive finding
            
        Returns:
            Tuple of (relationship_bonus, relationship_count)
        """
        relationship_count = 0
        
        # Check if this CWE has relationships
        if 'relationships' in metadata:
            relationships = metadata['relationships']
            relationship_count = len(relationships)
        
        # Only apply relationship bonus for graph-exclusive findings
        if is_graph_exclusive and relationship_count > 0:
            # Higher boost for graph-exclusive findings with relationships
            base_rel_boost = 0.15  # 15% per relationship
            relationship_bonus = 1.0 + min(relationship_count * base_rel_boost, 0.45)  # Up to 45% boost
        else:
            relationship_bonus = 1.0
            
        return relationship_bonus, relationship_count
    
    def _calculate_mapping_boost(self, metadata: Dict[str, Any]) -> float:
        """
        Calculate mapping guidance adjustment based on MITRE mapping notes.
        
        Args:
            metadata: CWE metadata
            
        Returns:
            Mapping boost factor
        """
        mapping_notes = metadata.get("mapping_notes", {})
        mapping_usage = mapping_notes.get("usage", "").upper() if isinstance(mapping_notes, dict) else ""
        
        boost_factor = 1.0  # Default no adjustment
        
        if mapping_usage == "ALLOWED":
            boost_factor = 1.1  # 10% boost
        elif mapping_usage == "ALLOWED-WITH-REVIEW":
            boost_factor = 1.05  # 5% boost
        elif mapping_usage == "DISCOURAGED":
            boost_factor = 0.8  # 20% penalty
        elif mapping_usage == "PROHIBITED":
            boost_factor = 0.5  # 50% penalty
        
        logger.debug(f"Mapping usage '{mapping_usage}' gives boost factor {boost_factor}")
        return boost_factor


    def _generate_mapping_usage_table(self, results: List[Dict[str, Any]]) -> str:
        """Generate a table showing mapping usage guidance for CWEs."""
        table = """
| CWE ID | Name | Abstraction | Mapping Usage | Mapping Rationale |
|--------|------|-------------|---------------|-------------------|
"""
        
        for result in results:
            metadata = result.get("metadata", {})
            cwe_id = metadata.get("doc_id", "Unknown")
            name = metadata.get("name", "Unknown")
            cwe_type = metadata.get("type", "Unknown")
            
            # Get mapping notes
            mapping_notes = metadata.get("mapping_notes", {})
            usage = mapping_notes.get("usage", "Not specified") if isinstance(mapping_notes, dict) else "Not specified"
            rationale = mapping_notes.get("rationale", "Not specified") if isinstance(mapping_notes, dict) else "Not specified"
            
            # Truncate long rationale for table display
            if len(rationale) > 100:
                rationale = rationale[:97] + "..."
            
            table += f"| {cwe_id} | {name} | {cwe_type} | {usage} | {rationale} |\n"
        
        return table


    def save_consolidated_results(
            self,
            cve_id: str,
            query: str,
            filtered_keyphrases: Dict[str, str],
            sorted_results: List[Dict[str, Any]],
            k: int
        ) -> None:
            """
            Save consolidated results and generate reports.
            
            Args:
                cve_id: The CVE identifier
                query: The query string
                filtered_keyphrases: Dictionary of filtered keyphrases
                sorted_results: List of sorted results
                k: Number of top results to include in reports
            """
            try:
                # Prepare consolidated results report
                report = {
                    "cve_id": cve_id,
                    "query": query,
                    "keyphrases": filtered_keyphrases,
                    "timestamp": datetime.now().isoformat(),
                    "retriever_weights": self.weights,
                    "results_count": len(sorted_results),
                    "results": [
                        {
                            "cwe_id": r.get("metadata", {}).get("doc_id", "unknown"),
                            "name": r.get("metadata", {}).get("name", "unknown"),
                            "abstraction": r.get("metadata", {}).get("type", "unknown"),  # Renamed to abstraction
                            "score": r.get("similarity", 0.0),
                            "score_info": r.get("metadata", {}).get("score_info", {}),
                            "mapping_notes": r.get("metadata", {}).get("mapping_notes", {})  # Include mapping notes
                        }
                        for r in sorted_results[:10]  # Include top 10 in report
                    ]
                }
                
                # Ensure directory exists
                cve_dir = os.path.join(self.output_dir, cve_id)
                ensure_directory(cve_dir)
                
                # Save JSON report
                report_file = os.path.join(cve_dir, f"{cve_id}_consolidated_results.json")
                save_json(report_file, report)
                logger.debug(f"Saved consolidated results to {report_file}")
                
                # Generate and save markdown table
                md_table = self._generate_results_table(sorted_results[:k])
                md_interpretation = self.generate_retriever_interpretation(sorted_results)
                
                md_content = f"""## Query
{query}            
        
## Keyphrases
{self._format_keyphrases(filtered_keyphrases)}

## Top {len(sorted_results[:k])} Results
{md_table}

{md_interpretation}
"""
                md_file = os.path.join(cve_dir, f"{cve_id}_retriever_results.md")
                save_markdown(md_file, f"CWE Search Results for {cve_id}", md_content)
                logger.debug(f"Saved retriever results markdown to {md_file}")
                
                # Generate and save retriever report for more detailed analysis
                retriever_report = self.generate_retriever_report(query, filtered_keyphrases, k, cve_id)
                logger.debug(f"Generated retriever report with {len(retriever_report.get('results_table', []))} entries")
                
            except Exception as e:
                logger.error(f"Error saving consolidated results: {e}")
                # Don't re-raise to avoid disrupting the search process


    def search(
        self,
        query: str,
        keyphrases: Dict[str, str] = None,
        k: int = 50,
        use_graph: bool = True,
        use_rag: bool = True,
        use_sparse: bool = True,
        rerank: bool = False,
        cve_id: str = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Search using the specified retrieval methods and return raw results."""
        if not self.loaded:
            raise ValueError("Retriever not initialized. Load data first.")
            
        try:
            # 1. Prepare keyphrases
            filtered_keyphrases = self._prepare_keyphrases(keyphrases)
            
            # 2. Perform searches with enabled retrievers
            all_results, result_sources, result_scores, retriever_results = self._execute_searches(
                query, filtered_keyphrases, k, use_graph, use_rag, use_sparse, cve_id, **kwargs
            )
            
            # 3. Enhance all results with mapping information
            all_results = self._enhance_results_with_mapping_info(all_results)
            
            # Also enhance the individual retriever results for logging
            for retriever_type in retriever_results:
                if retriever_results[retriever_type]:
                    retriever_results[retriever_type] = self._enhance_results_with_mapping_info(retriever_results[retriever_type])
            
            # 4. Log and save raw results for inspection if cve_id provided
            if cve_id and cve_id != "unknown":
                self._log_raw_results(cve_id, query, filtered_keyphrases, retriever_results)
            
            # 5. Return all the raw information for processing at a higher level
            return {
                "all_results": all_results,
                "result_sources": result_sources,
                "result_scores": result_scores,
                "retriever_results": retriever_results
            }
            
        except Exception as e:
            logger.error("Error during search: %s", e)
            raise
 

    def generate_consolidated_results(self, query, keyphrases=None, k=50, **kwargs):
        """
        Generate a consolidated view of results for reporting purposes.
        This method assumes that the results have already been consolidated using `consolidate_results`.
        """
        # Get the raw results from the search method
        search_results = self.search(query, keyphrases, k=k, **kwargs)
        
        # Extract the necessary components for consolidation
        all_results = search_results.get("all_results", [])
        result_sources = search_results.get("result_sources", {})
        result_scores = search_results.get("result_scores", {})
        
        # Use consolidate_results to combine and score the results
        consolidated_results = self.consolidate_results(all_results, result_sources, result_scores)
        
        # Sort the consolidated results by their combined score
        sorted_results = sorted(consolidated_results, key=lambda x: x.get("similarity", 0), reverse=True)
        
        # Prepare the final output structure for reporting
        report = {
            "query": query,
            "keyphrases": keyphrases,
            "retriever_weights": self.weights,
            "total_results": len(sorted_results),
            "results": []
        }
        
        # Format results for the report
        for result in sorted_results[:k]:
            metadata = result.get("metadata", {})
            score_info = metadata.get("score_info", {})
            
            report["results"].append({
                "cwe_id": metadata.get("doc_id", "unknown"),
                "name": metadata.get("name", "unknown"),
                "type": metadata.get("type", "unknown"),
                "combined_score": result.get("similarity", 0.0),
                "retrievers": score_info.get("retrievers", []),
                "scores": score_info.get("normalized_scores", {}),
                "retriever_count": score_info.get("retriever_count", 0)
            })
        
        return report

    def generate_retriever_interpretation(self, consolidated_results):
        """Generate the retriever score interpretation section explaining the enhanced scoring methodology."""
        # Start with the standard explanation
        explanation = """
### Retriever Score Interpretation
The scores are calculated with a sophisticated methodology that considers multiple factors:

- **Dense Vector Search**: Measures semantic similarity to the vulnerability description (0-1 scale)
- **Property Graph**: Identifies CWEs with relevant structural relationships (0-1 scale)
- **Sparse Retrieval**: Finds exact keyword matches using BM25, normalized to 0-1 scale (original scores capped at 1000)

The combined score is calculated as follows:

1. **Individual Scores**: Each retriever score is normalized to 0-1 scale and weighted according to retriever weights

2. **Quality-Adjusted Consensus Boost**: When multiple retrievers agree on a CWE:
- The boost is scaled by the average confidence score (higher confidence = higher boost)
- Different retriever combinations receive different boost modifiers:
    - Sparse + Dense (more independent signals): +20% boost
    - Sparse + Graph (partially independent): +10% boost  
    - Dense + Graph (more overlap): -10% boost reduction

3. **Relationship Boosting**: CWEs identified by the graph retriever with explicit relationships receive:
- Additional weight to the graph retriever's score
- A relationship bonus based on the number of relevant relationships

4. **Abstraction Level Adjustment**:
- Base CWEs: +30% boost
- Variant CWEs: +20% boost
- Class CWEs: -20% penalty
- Pillar CWEs: -40% penalty

This approach favors CWEs that are identified by multiple independent retrieval methods, and prioritizes those with explicit structural relationships to other CWEs.
"""

        # Add result-specific insights if results are provided
        if consolidated_results and len(consolidated_results) > 0:
            # Count which retrievers found what
            retriever_counts = {"dense": 0, "sparse": 0, "graph": 0}
            multi_retriever_count = 0
            relationship_count = 0
            
            for result in consolidated_results:
                score_info = result.get("metadata", {}).get("score_info", {})
                retrievers = score_info.get("retrievers", [])
                
                # Count by individual retriever
                for retriever in retrievers:
                    retriever_counts[retriever] = retriever_counts.get(retriever, 0) + 1
                    
                # Count results found by multiple retrievers
                if len(retrievers) > 1:
                    multi_retriever_count += 1
                    
                # Count results with relationship bonuses
                if score_info.get("relationship_bonus", 1.0) > 1.0:
                    relationship_count += 1
            
            # Add insights based on retriever counts
            explanation += "\n\n### Result Analysis\n"
            
            if multi_retriever_count > 0:
                explanation += f"- **{multi_retriever_count}** CWEs were found by multiple retrievers, indicating stronger relevance.\n"
            
            if relationship_count > 0:
                explanation += f"- **{relationship_count}** CWEs have explicit relationship connections in the CWE database, providing structural context.\n"
            
            # Show which retrievers found the most results
            retriever_counts_sorted = sorted(retriever_counts.items(), key=lambda x: x[1], reverse=True)
            if retriever_counts_sorted:
                top_retriever, top_count = retriever_counts_sorted[0]
                explanation += f"- The **{top_retriever}** retriever found the most relevant CWEs ({top_count}).\n"
            
            # Add abstraction level insights
            has_base = False
            has_variant = False
            for result in consolidated_results:
                cwe_type = result.get("metadata", {}).get("type", "").lower()
                if cwe_type == "base":
                    has_base = True
                elif cwe_type == "variant":
                    has_variant = True
                        
            if has_base and has_variant:
                explanation += "- The results include a mix of Base and Variant CWEs, providing good coverage at different abstraction levels.\n"
            elif has_base:
                explanation += "- The results are primarily Base-level CWEs, which balance specificity and generality.\n"
            elif has_variant:
                explanation += "- The results include Variant-level CWEs, which provide highly specific weakness identification.\n"

        explanation += "\nHigher scores indicate stronger relevance. CWEs found by multiple independent retrievers, with explicit relationships, and at appropriate abstraction levels are particularly significant."
        return explanation

        
    def _format_graph_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Format results from the property graph retriever.
        This version doesn't include mapping notes which will be added later.
        """
        formatted_results = []
        
        # Handle different input types or empty/None results
        if results is None:
            logger.warning("Received None for graph results")
            return []
            
        if not isinstance(results, list):
            logger.warning(f"Unexpected type for graph results: {type(results)}")
            if isinstance(results, dict) and "results" in results:
                # Handle case where results is a dict with a "results" key
                results = results["results"]
            else:
                # Cannot process this format
                return []
        
        for result in results:
            # Skip if not a dictionary
            if not isinstance(result, dict):
                logger.warning(f"Skipping non-dictionary result: {result}")
                continue
                
            try:
                formatted_result = result.copy()
                
                # Extract CWE ID for lookup
                cwe_id = result.get("doc_id") or result.get("metadata", {}).get("doc_id")
                
                # Look up additional information from the CWE entries
                if cwe_id and self.cwe_entries:
                    cwe_id_numeric = cwe_id.replace("CWE-", "")
                    cwe_entry = next((cwe for cwe in self.cwe_entries if cwe.ID == cwe_id_numeric), None)
                    
                    if cwe_entry:
                        # Initialize metadata if not present
                        if "metadata" not in formatted_result:
                            formatted_result["metadata"] = {}
                        
                        # Add potential mitigations if available
                        if cwe_entry.PotentialMitigations:
                            mitigations = []
                            for mitigation in cwe_entry.PotentialMitigations:
                                mitigation_data = {
                                    "description": mitigation.Description if hasattr(mitigation, 'Description') else "No description"
                                }
                                
                                # Handle phase being either a string or list of strings
                                if hasattr(mitigation, 'Phase'):
                                    mitigation_data["phase"] = mitigation.Phase  # Store as-is, we'll handle formatting later
                                else:
                                    mitigation_data["phase"] = "Unknown"
                                
                                if hasattr(mitigation, 'Effectiveness'):
                                    mitigation_data["effectiveness"] = mitigation.Effectiveness
                                
                                if hasattr(mitigation, 'Strategy'):
                                    mitigation_data["strategy"] = mitigation.Strategy
                                
                                mitigations.append(mitigation_data)
                            
                            formatted_result["metadata"]["mitigations"] = mitigations
                        
                        # Add notes if available
                        if cwe_entry.Notes:
                            notes = []
                            for note in cwe_entry.Notes:
                                notes.append({
                                    "type": safe_access(note, "Type", "General"),
                                    "content": safe_access(note, "Note", "General")
                                })
                            
                            formatted_result["metadata"]["notes"] = notes
                
                formatted_results.append(formatted_result)
            except Exception as e:
                logger.warning(f"Error formatting graph result: {e}")
                # Try to add the original result if possible
                if isinstance(result, dict):
                    formatted_results.append(result)
        
        return formatted_results


    def _format_rag_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Format results from the RAG/dense retriever.
        This version doesn't include mapping notes which will be added later.
        """
        # For now, assume the results are already in the desired format.
        return results


    def _deduplicate_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicate results by CWE ID, keeping the highest scored entry.
        """
        dedup = {}
        for result in results:
            cwe_id = result.get("metadata", {}).get("doc_id") or result.get("cwe_id")
            if cwe_id is None:
                continue
            if cwe_id not in dedup or result.get("similarity", 0) > dedup[cwe_id].get("similarity", 0):
                dedup[cwe_id] = result
        return list(dedup.values())


    def get_metadata(self) -> Dict[str, Any]:
        """
        Get metadata about the hybrid retriever.
        Aggregates metadata from dense, sparse, and property graph retrievers.
        """
        return {
            "dense_retriever": self.dense_retriever.get_metadata(),
            "sparse_retriever": self.sparse_retriever.get_metadata() if self.sparse_retriever else {},
            "property_graph": self.property_graph.get_metadata(),
            "weights": self.weights
        }

    def _adjust_weights_for_query(self, query: str, keyphrases: Dict[str, str] = None) -> Dict[str, float]:
        """Dynamically adjust weights based on query characteristics."""
        weights = self.weights.copy()
        
        # If keyphrases are provided, increase weight of sparse retriever
        if keyphrases and any(keyphrases.values()):
            # Boost sparse retriever weight while maintaining proportional distribution
            sparse_boost = 0.15  # Adjust as needed
            total = sum(weights.values())
            sparse_weight = weights.get('sparse', 0) + sparse_boost
            remaining = total - sparse_weight
            
            # Redistribute remaining weight proportionally among other retrievers
            other_weights = {k: v for k, v in weights.items() if k != 'sparse'}
            other_total = sum(other_weights.values())
            
            weights = {
                k: (sparse_weight if k == 'sparse' else v * (remaining / other_total))
                for k, v in weights.items()
            }
        
        return weights
    
    def _extract_keyphrases(self, query: str) -> Dict[str, str]:
        """Extract keyphrases from query text if presented in a structured format."""
        keyphrases = {}
        
        # Try to find patterns like "rootcause: missing bounds check"
        keyphrase_patterns = [
            (r"rootcause:\s*([^,\n]+)", "rootcause"),
            (r"weakness:\s*([^,\n]+)", "weakness")
        ]
        
        for pattern, key in keyphrase_patterns:
            matches = re.findall(pattern, query, re.IGNORECASE)
            if matches:
                keyphrases[key] = matches[0].strip()
        
        return keyphrases
    
    def _process_query_for_retrievers(self, query, keyphrases=None):
        """Process query specifically for each retriever type."""
        # Base query for all retrievers
        retriever_queries = {
            "dense": query,  # Dense works well with full natural language
            "sparse": query,  # Sparse will be enhanced with keyphrases
            "graph": query    # Graph query can be simplified
        }
        
        # For sparse retriever, emphasize keyphrases
        if keyphrases:
            # Create a version that emphasizes keyphrases for BM25
            keyphrase_str = " ".join([f"{k}: {v}" for k, v in keyphrases.items() if v])
            retriever_queries["sparse"] = f"{query} {keyphrase_str}"
        
        # For graph retriever, extract potential CWE IDs from query
        cwe_pattern = re.compile(r"CWE[- ]?(\d+)", re.IGNORECASE)
        cwe_matches = cwe_pattern.findall(query)
        if cwe_matches:
            # If query mentions specific CWEs, prioritize those for graph search
            cwe_ids = [f"CWE-{match}" for match in cwe_matches]
            retriever_queries["graph"] = f"Specifically analyze {', '.join(cwe_ids)} and related CWEs: {query}"
        
        return retriever_queries

    def rerank_results(self, query: str, results: List[Dict[str, Any]], k: int = 5) -> List[Dict[str, Any]]:
        """
        Rerank search results using Cohere reranking API or delegate to ContextualHybridRetriever.
        
        Args:
            query: The original query
            results: List of search results to rerank
            k: Number of results to return
        
        Returns:
            Reranked list of results
        """
        try:
            # If we have a ContextualHybridRetriever available, use its reranking
            if hasattr(self, 'rag_retriever') and hasattr(self.rag_retriever, 'rerank_results'):
                return self.rag_retriever.rerank_results(query, results, k)
                
            # Otherwise, implement reranking here
            import cohere
            
            # If we don't have a cohere client, try to create one
            if not hasattr(self, 'cohere_client'):
                try:
                    import os
                    cohere_api_key = os.getenv("COHERE_API_KEY")
                    if not cohere_api_key:
                        logger.warning("No COHERE_API_KEY found, skipping reranking")
                        return results[:k]
                    self.cohere_client = cohere.Client(api_key=cohere_api_key)
                except Exception as e:
                    logger.error(f"Failed to initialize Cohere client: {e}")
                    return results[:k]
            
            # Extract documents and prepare for reranking
            documents = []
            for result in results:
                if 'metadata' in result and 'original_content' in result['metadata']:
                    content = result['metadata']['original_content']
                    documents.append(content)
                elif 'content' in result:
                    documents.append(result['content'])
                else:
                    # Skip results without content
                    logger.warning("Skipping result without content for reranking")
                    continue
            
            if not documents:
                logger.warning("No documents with content found for reranking")
                return results[:k]
                
            # Perform reranking
            rerank_response = self.cohere_client.rerank(
                query=query,
                documents=documents,
                top_n=min(k, len(documents)),
                model="rerank-english-v2.0"
            )
            
            # Update results with new rankings
            reranked_results = []
            for reranked in rerank_response.results:
                original_idx = reranked.index
                if original_idx < len(results):
                    result = results[original_idx].copy()
                    # Update similarity score with reranking score
                    result['similarity'] = reranked.relevance_score
                    reranked_results.append(result)
            
            # Sort by the new scores
            reranked_results.sort(key=lambda x: x.get('similarity', 0), reverse=True)
            return reranked_results[:k]
            
        except Exception as e:
            logger.warning(f"Error during reranking: {e}")
            # Fall back to returning the original results, sorted by similarity
            sorted_results = sorted(
                results, 
                key=lambda x: x.get('similarity', 0),
                reverse=True
            )
            return sorted_results[:k]    
    
  
    def generate_retriever_report(self, query, keyphrases=None, k=50, cve_id=None):
        """Generate a detailed report about how each retriever performed."""
        # Get consolidated results
        consolidated = self.generate_consolidated_results(query, keyphrases, k)
        
        # Create report
        report = {
            "cve_id": cve_id or "unknown",
            "query": query,
            "keyphrases": keyphrases,
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_unique_cwes": len(consolidated["results"]),
                "retrievers_used": {
                    "dense": True,
                    "sparse": True,
                    "graph": True
                },
                "retriever_weights": self.weights
            },
            "retriever_statistics": {
                "dense": {"hit_count": 0, "average_score": 0.0, "unique_finds": 0},
                "sparse": {"hit_count": 0, "average_score": 0.0, "unique_finds": 0},
                "graph": {"hit_count": 0, "average_score": 0.0, "unique_finds": 0}
            },
            "results_table": []
        }
        
        # Calculate statistics
        for result in consolidated["results"]:
            for retriever in ["dense", "sparse", "graph"]:
                if retriever in result["retrievers"]:
                    report["retriever_statistics"][retriever]["hit_count"] += 1
                    report["retriever_statistics"][retriever]["average_score"] += result["scores"].get(retriever, 0)
                    if len(result["retrievers"]) == 1:
                        report["retriever_statistics"][retriever]["unique_finds"] += 1
        
        # Normalize average scores
        for retriever in ["dense", "sparse", "graph"]:
            if report["retriever_statistics"][retriever]["hit_count"] > 0:
                report["retriever_statistics"][retriever]["average_score"] /= report["retriever_statistics"][retriever]["hit_count"]
        
        # Generate results table
        for result in consolidated["results"]:
            # Look up mapping usage for this CWE
            mapping_usage = "Not specified"
            
            # Find the result in the original data
            for original_result in consolidated.get("original_results", []):
                if original_result.get("cwe_id") == result["cwe_id"]:
                    mapping_notes = original_result.get("metadata", {}).get("mapping_notes", {})
                    if isinstance(mapping_notes, dict):
                        mapping_usage = mapping_notes.get("usage", "Not specified")
                    break
            
            table_row = {
                "cwe_id": result["cwe_id"],
                "name": result["name"],
                "abstraction": result["type"],  # Renamed to abstraction
                "mapping_usage": mapping_usage,  # Added mapping usage
                "combined_score": round(result["combined_score"], 4),
                "retriever_count": result["retriever_count"],
                "dense_score": round(result["scores"].get("dense", 0), 4) if "dense" in result["retrievers"] else "-",
                "sparse_score": round(result["scores"].get("sparse", 0), 4) if "sparse" in result["retrievers"] else "-",
                "graph_score": round(result["scores"].get("graph", 0), 4) if "graph" in result["retrievers"] else "-"
            }
            report["results_table"].append(table_row)
        
        # Save report
        if cve_id and cve_id != "unknown":
            report_file = os.path.join(self.output_dir, cve_id, f"{cve_id}_retriever_report.json")
            save_json(report_file, report)
        
        return report

    
    def _generate_results_table(self, results: List[Dict[str, Any]]) -> str:
        """Generate a detailed markdown table of results with all information."""
        # Build the data structure
        table_data = self._build_results_table(results)
        
        # Use the full format for the retriever results
        return self._format_full_results_table(table_data)