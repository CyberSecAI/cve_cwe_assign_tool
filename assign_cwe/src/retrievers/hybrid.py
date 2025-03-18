# src/retrievers/hybrid.py

from utils.logger import get_logger
import time
import json
import os
import logging
import anthropic
from typing import List, Dict, Any, Optional, Tuple, Set
from tqdm import tqdm
import numpy as np
import threading
from functools import lru_cache
from time import sleep
from collections import OrderedDict 
from cohere import Client as CohereClient
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from concurrent.futures import ThreadPoolExecutor, as_completed
from .qdrant_retriever import QdrantDenseRetriever
from .base import BaseRetriever
from models.cwe import CWEEntry

logger = get_logger(__name__)

class ContextualHybridRetriever(BaseRetriever):
    """Contextual hybrid retriever that enhances documents with LLM-generated context and supports reranking."""

    def __init__(
        self,
        name: str = "contextual_hybrid",
        anthropic_api_key: Optional[str] = None,
        cohere_api_key: Optional[str] = None,
        parallel_threads: int = 2,
        qdrant_location: str = "./data/qdrant",
        embedding_client = None,
        cache_size: int = 5000,
        batch_size: int = 100  # Added batch_size parameter
    ):
        self.name = name
        self.parallel_threads = parallel_threads
        self.batch_size = batch_size  # Store batch_size

        # Initialize Qdrant-based dense retriever
        self.dense_retriever = QdrantDenseRetriever(
            name=f"{name}_dense",
            location=qdrant_location,
            embedding_client=embedding_client,
            batch_size=batch_size  # Pass batch_size to QdrantDenseRetriever
        )

        # Initialize API clients
        if anthropic_api_key is None:
            anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
        self.anthropic_client = anthropic.Client(api_key=anthropic_api_key)

        if cohere_api_key is None:
            cohere_api_key = os.getenv("COHERE_API_KEY")
        self.cohere_client = CohereClient(api_key=cohere_api_key)

        # Token usage tracking
        self.token_counts = {
            'input': 0,
            'output': 0
        }
        self.token_lock = threading.Lock()

        # In-memory LRU cache for contexts
        self.context_cache = self.LRUCache(capacity=cache_size)
        logger.info(f"Initialized with {cache_size} context cache capacity")

    def _process_entry(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a single entry from the dataset.

        Args:
            item: Dictionary containing the entry data

        Returns:
            Dictionary containing the processed entry
        """
        try:
            # Extract the entry and doc_id
            entry = item['entry']
            doc_id = item['doc_id']

            # Generate context for the entry
            context, usage = self.generate_context(entry)

            # Prepare the processed entry
            processed_entry = {
                'doc_id': doc_id,
                'content': entry.to_searchable_text(),
                'metadata': {
                    'doc_id': doc_id,
                    'name': entry.Name,
                    'type': entry.Abstraction,
                    'status': entry.Status,
                    'contextualized_content': context,
                    'original_content': entry.Description
                }
            }

            return processed_entry

        except Exception as e:
            logger.error(f"Error processing entry {item.get('doc_id', 'unknown')}: {e}")
            return None

    def search(self, query: str, k: int = 5, rerank: bool = True, **kwargs) -> List[Dict[str, Any]]:
        """Search with optional reranking."""
        logger.info("Performing hybrid search for query: {:.100}...", query)
        
        # Get initial results
        initial_results = self.dense_retriever.search(query, k * 2, **kwargs)
        logger.debug("Retrieved {} initial results", len(initial_results))
        
        # Extract and boost CWE IDs
        cwe_ids = self._extract_cwe_ids(query)
        if cwe_ids:
            logger.debug("Found {} explicit CWE IDs in query", len(cwe_ids))
            initial_results = self._boost_by_cwe_ids(initial_results, cwe_ids)
        
        # Adjust by abstraction
        results = self._adjust_by_abstraction(initial_results)
        
        # Rerank if enabled
        if rerank:
            logger.debug("Reranking {} results", len(results))
            results = self.rerank_results(query, results, k)
        
        final_results = results[:k]
        logger.info("Returning {} final results", len(final_results))
        return final_results

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(anthropic.RateLimitError)
    )
    def generate_context(self, entry: CWEEntry) -> Tuple[str, Any]:
        """Generate context for a CWE entry with in-memory caching."""
        cache_key = f"CWE-{entry.ID}"
        
        # Check in-memory cache first
        if cached_result := self.context_cache.get(cache_key):
            logger.debug(f"Context cache hit for {cache_key}")
            return cached_result

        # Generate new context if not in cache
        prompt = f"""
        Please analyze this CWE entry and provide a concise context that captures its key characteristics:

        ID: CWE-{entry.ID}
        Name: {entry.Name}
        Type: {entry.Abstraction}
        Description: {entry.Description}
        """

        response = self.anthropic_client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=1024,
            temperature=0,
            messages=[{
                "role": "user",
                "content": prompt
            }]
        )
        
        result = (response.content[0].text, response.usage)
        self.context_cache.put(cache_key, result)
        
        # Update token counts
        with self.token_lock:
            self.token_counts['input'] += response.usage.input_tokens
            self.token_counts['output'] += response.usage.output_tokens
        
        return result

    def load_data(self, dataset: List[Dict[str, Any]]):
        """Load and index dataset with context enhancement."""
        logger.info("Processing dataset with batch size {}", self.batch_size)
        
        try:
            # Clear existing data
            self.dense_retriever.clear_data()
            
            processed_entries = []
            hits = 0
            misses = 0
            
            for item in dataset:
                try:
                    # Extract the entry and verify it's a CWEEntry
                    entry = item.get('entry')
                    if not isinstance(entry, CWEEntry):
                        logger.warning(f"Invalid entry type: {type(entry)}")
                        continue
                        
                    # Create processed entry
                    processed_entry = {
                        'doc_id': entry.ID,
                        'content': entry.to_searchable_text(),
                        'metadata': {
                            'doc_id': entry.ID,
                            'name': entry.Name,
                            'type': entry.Abstraction,
                            'status': entry.Status,
                            'original_content': entry.Description
                        }
                    }
                    
                    processed_entries.append(processed_entry)
                    
                    # Update cache stats
                    if self.context_cache.contains(f"CWE-{entry.ID}"):
                        hits += 1
                    else:
                        misses += 1
                        
                except Exception as e:
                    logger.error(f"Error processing entry: {e}")
                    continue
                    
            # Load processed entries into dense retriever
            self.dense_retriever.load_data(processed_entries)
            
            # Log cache statistics
            logger.info(f"Context cache performance - Hits: {hits}, Misses: {misses}")
            logger.info(f"Total contexts in cache: {len(self.context_cache)}")
            
        except Exception as e:
            logger.error(f"Error loading data: {e}")
            raise

    # Helper class for LRU Cache
    class LRUCache:
        def __init__(self, capacity: int):
            self.cache = OrderedDict()
            self.capacity = capacity

        def get(self, key: str) -> Optional[Any]:
            if key not in self.cache:
                return None
            self.cache.move_to_end(key)
            return self.cache[key]

        def put(self, key: str, value: Any) -> None:
            if key in self.cache:
                self.cache.move_to_end(key)
            self.cache[key] = value
            if len(self.cache) > self.capacity:
                self.cache.popitem(last=False)

        def contains(self, key: str) -> bool:
            return key in self.cache

        def __len__(self) -> int:
            return len(self.cache)

    def get_metadata(self) -> Dict[str, Any]:
        """Get metadata about this retriever."""
        metadata = {
            "name": self.name,
            "type": "contextual_hybrid",
            "dense_retriever": self.dense_retriever.get_metadata(),
            "token_counts": self.token_counts.copy(),
            "cache_size": len(self.context_cache),
            "cache_capacity": self.context_cache.capacity,
            "parallel_threads": self.parallel_threads
        }
        return metadata

    def _extract_cwe_ids(self, query: str) -> Set[str]:
        """Extract CWE IDs from the query."""
        import re
        # Match patterns like "CWE-123" or "CWE 123"
        cwe_pattern = re.compile(r"CWE[- ]?(\d+)", re.IGNORECASE)
        matches = cwe_pattern.findall(query)
        return {f"CWE-{match}" for match in matches}    