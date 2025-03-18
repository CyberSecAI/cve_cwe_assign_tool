# src/retrievers/base.py

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

class BaseRetriever(ABC):
    """Base interface for all retriever implementations."""
    
    @abstractmethod
    def search(
        self,
        query: str,
        k: int = 5,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Search for relevant CWE entries based on a query.
        
        Args:
            query: The search query
            k: Number of results to return
            **kwargs: Additional search parameters
            
        Returns:
            List of dictionaries containing search results
        """
        pass
    
    @abstractmethod
    def get_metadata(self) -> Dict[str, Any]:
        """Get metadata about the retriever."""
        pass