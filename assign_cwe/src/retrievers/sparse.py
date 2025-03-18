# src/retrievers/sparse.py

import re
import logging
from typing import List, Dict, Any, Optional
from rank_bm25 import BM25Okapi  # Use rank_bm25 for better control and scoring
from langchain_core.documents import Document

from .base import BaseRetriever
from models.cwe import CWEEntry

logger = logging.getLogger(__name__)

class SparseRetriever(BaseRetriever):
    """Sparse retriever using BM25 algorithm."""
    
    def __init__(self, entries: List[CWEEntry]):
        """
        Initialize the sparse retriever.
        
        Args:
            entries: List of CWE entries to index
        """
        self.entries = {entry.ID: entry for entry in entries}  # Use entry.ID instead of entry.id
        self.bm25 = self._setup_retriever()
        
    def _setup_retriever(self) -> BM25Okapi:
        """Set up the BM25 retriever."""
        logger.info("Setting up BM25 retriever")
        try:
            # Tokenize documents for BM25
            tokenized_docs = []
            self.documents = []  # Store documents for metadata lookup
            
            for entry in self.entries.values():
                searchable_text = entry.to_searchable_text()
                tokens = self._tokenize(searchable_text)  # Tokenize text
                tokenized_docs.append(tokens)
                
                # Store document for metadata lookup
                self.documents.append({
                    "cwe_id": entry.ID,
                    "name": entry.Name,
                    "description": entry.Description,
                    "tokens": tokens
                })
                
            # Initialize BM25 retriever
            bm25 = BM25Okapi(tokenized_docs)
            logger.info(f"Successfully created BM25 retriever with {len(tokenized_docs)} documents")
            return bm25
            
        except Exception as e:
            logger.error(f"Failed to set up BM25 retriever: {e}")
            raise
            
    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text for BM25 with improved preprocessing."""
        # Convert to lowercase
        text = text.lower()
        # Remove punctuation
        text = re.sub(r'[^\w\s]', ' ', text)
        # Split on whitespace and filter empty strings
        tokens = [token for token in text.split() if token]
        # Optional: Remove stopwords if available
        # Optional: Apply stemming/lemmatization
        return tokens


    def search_with_keyphrases(
        self,
        query: str,
        keyphrases: Dict[str, Any],
        k: int = 5,
        keyphrase_boost: float = 1.5,  # Default boost factor
        separate_searches: bool = True,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Search with additional boosting for keyphrases.
        Can perform separate searches on individual keyphrases.
        Handles both string and list keyphrases.
        
        Args:
            query: The search query
            keyphrases: Dictionary of keyphrases (e.g., {'rootcause': 'buffer overflow'} or {'rootcause': ['buffer overflow', 'type confusion']})
            k: Number of results to return
            keyphrase_boost: Boost factor for keyphrase matches
            separate_searches: Whether to perform separate searches for each keyphrase
            **kwargs: Additional search parameters
            
        Returns:
            List of dictionaries containing search results
        """
        # Process keyphrases to handle both string and list formats
        processed_keyphrases = {}
        for key, phrase in keyphrases.items():
            if isinstance(phrase, str) and phrase and phrase.strip():
                processed_keyphrases[key] = phrase.strip()
            elif isinstance(phrase, list):
                # For lists, we'll process each item separately during search
                valid_phrases = [p.strip() for p in phrase if isinstance(p, str) and p and p.strip()]
                if valid_phrases:
                    processed_keyphrases[key] = valid_phrases
        
        # Initialize results dictionary to track separate search results
        all_results = {}
        
        # Start with base query results
        base_results = self.search(query, k=k*2, **kwargs)
        all_results['base'] = base_results
        
        if separate_searches and processed_keyphrases:
            # Define keyphrase-specific boost factors - prioritize rootcause and weakness
            keyphrase_boost_factors = {
                'rootcause': 2.0,  # Higher boost for rootcause
                'weakness': 1.8,   # High boost for weakness
                'default': 1.0     # Default boost for other keyphrases
            }
            
            # Perform separate searches for each keyphrase
            for key, phrase in processed_keyphrases.items():
                if isinstance(phrase, str):
                    # Create a targeted query combining original and the specific keyphrase
                    keyphrase_query = f"{query} {phrase}"
                    logger.info(f"Performing separate search for {key}: '{phrase}'")
                    
                    try:
                        # Search with the enhanced query
                        keyphrase_results = self.search(keyphrase_query, k=k, **kwargs)
                        all_results[key] = keyphrase_results
                    except Exception as e:
                        logger.error(f"Error in separate search for {key}: {e}")
                
                elif isinstance(phrase, list):
                    # For lists, do a separate search for each item
                    for i, item in enumerate(phrase):
                        item_key = f"{key}_{i}"
                        keyphrase_query = f"{query} {item}"
                        logger.info(f"Performing separate search for {key} item {i}: '{item}'")
                        
                        try:
                            # Search with the enhanced query
                            keyphrase_results = self.search(keyphrase_query, k=k, **kwargs)
                            all_results[item_key] = keyphrase_results
                        except Exception as e:
                            logger.error(f"Error in separate search for {key} item {i}: {e}")
        
        # Process combined results
        # Extract all unique results from all searches
        combined_results = {}
        for result_type, results in all_results.items():
            for result in results:
                cwe_id = result["cwe_id"]
                if cwe_id not in combined_results:
                    combined_results[cwe_id] = result.copy()
                    # Track which search found this result
                    combined_results[cwe_id]["sources"] = [result_type]
                else:
                    # Update score if higher
                    if result["score"] > combined_results[cwe_id]["score"]:
                        combined_results[cwe_id]["score"] = result["score"]
                    # Add to sources if not already there
                    if result_type not in combined_results[cwe_id].get("sources", []):
                        combined_results[cwe_id]["sources"].append(result_type)
        
        # Apply additional boosting for matches from specific keyphrases
        for result in combined_results.values():
            sources = result.get("sources", [])
            
            # Calculate boost based on which keyphrases found this result
            boost_factor = 1.0
            
            # Check if result was found by rootcause
            rootcause_match = 'rootcause' in sources or any(s.startswith('rootcause_') for s in sources)
            if rootcause_match:
                boost_factor += keyphrase_boost_factors.get('rootcause', 2.0)
            
            # Check if result was found by weakness
            weakness_match = 'weakness' in sources or any(s.startswith('weakness_') for s in sources)
            if weakness_match:
                boost_factor += keyphrase_boost_factors.get('weakness', 1.8)
            
            # Boost score
            result["score"] *= boost_factor
            
            # Add boosting information to result for transparency
            result["boost_factor"] = boost_factor
            result["boosted"] = boost_factor > 1.0
        
        # Convert back to list and sort by score
        final_results = list(combined_results.values())
        final_results.sort(key=lambda x: x["score"], reverse=True)
        
        logger.info(f"Found {len(final_results)} results with keyphrase boosting")
        if len(final_results) > 0:
            logger.debug(f"Top result: {final_results[0]['cwe_id']} with score {final_results[0]['score']:.2f}")
        
        return final_results[:k]
            
    def search(
        self,
        query: str,
        k: int = 5,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Search for relevant CWE entries using BM25.
        
        Args:
            query: Search query
            k: Number of results to return
            **kwargs: Additional search parameters
            
        Returns:
            List of dictionaries containing search results
        """
        logger.info(f"Performing sparse search for query: {query[:100]}...")
        
        try:
            # Tokenize query
            query_tokens = self._tokenize(query)
            
            # Get BM25 scores
            scores = self.bm25.get_scores(query_tokens)
            
            # Sort documents by score
            sorted_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
            
            # Process results
            results = []
            seen_ids = set()
            
            for idx in sorted_indices:
                doc = self.documents[idx]
                cwe_id = doc["cwe_id"]
                
                # Skip if we've seen this CWE
                if cwe_id in seen_ids:
                    continue
                    
                entry = self.entries[cwe_id]
                
                # Ensure CWE ID is properly formatted with "CWE-" prefix
                formatted_cwe_id = f"CWE-{cwe_id}" if not cwe_id.startswith("CWE-") else cwe_id
                
                results.append({
                    "cwe_id": formatted_cwe_id,
                    "name": entry.Name,
                    "description": entry.Description,
                    "score": scores[idx],  # Use actual BM25 score
                    "matched_text": entry.to_searchable_text(),
                    "type": entry.Abstraction  # Include abstraction level
                })
                
                seen_ids.add(cwe_id)
                
                if len(results) >= k:
                    break
                    
            return results
            
        except Exception as e:
            logger.error(f"Error during sparse search: {e}")
            raise
            
    def get_metadata(self) -> Dict[str, Any]:
        """Get metadata about the sparse retriever."""
        return {
            "type": "sparse",
            "algorithm": "bm25",
            "num_entries": len(self.entries)
        }