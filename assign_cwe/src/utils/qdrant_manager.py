# src/utils/qdrant_manager.py

"""Singleton manager for Qdrant client instance."""

import os
import logging
import atexit
from qdrant_client import QdrantClient

logger = logging.getLogger(__name__)

class QdrantClientManager:
    """Singleton manager for Qdrant client to prevent multiple instances."""
    
    _instance = None
    _client = None
    _current_path = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(QdrantClientManager, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.initialized = True
            atexit.register(self.cleanup)
    
    def get_client(self, location: str = "./data/qdrant", prefer_grpc: bool = True) -> QdrantClient:
        """
        Get or create Qdrant client instance.
        
        Args:
            location: Path for local storage or URL for remote
            prefer_grpc: Whether to prefer gRPC protocol
        """
        is_local = os.path.isdir(location) or not location.startswith(('http://', 'https://'))
        
        # If path changed or client doesn't exist, create new one
        if self._client is None or (is_local and location != self._current_path):
            try:
                # Clean up existing client if needed
                self.cleanup()
                
                # Create new client
                self._client = QdrantClient(
                    path=location if is_local else None,
                    url=None if is_local else location,
                    prefer_grpc=prefer_grpc
                )
                self._current_path = location if is_local else None
                
                logger.info(f"Initialized Qdrant client with {'local path' if is_local else 'remote URL'}: {location}")
            except Exception as e:
                logger.error(f"Failed to initialize Qdrant client: {e}")
                raise RuntimeError(f"Failed to initialize Qdrant client: {e}")
        
        return self._client
    
    def cleanup(self):
        """Clean up Qdrant client resources."""
        if self._client is not None:
            try:
                self._client.close()
                logger.info("Closed Qdrant client connection")
            except Exception as e:
                logger.warning(f"Error closing Qdrant client: {e}")
            self._client = None
            self._current_path = None