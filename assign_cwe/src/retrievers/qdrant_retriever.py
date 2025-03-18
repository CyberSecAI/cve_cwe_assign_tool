# src/retrievers/qdrant_retriever.py

from langchain_qdrant import QdrantVectorStore
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from qdrant_client import QdrantClient
from qdrant_client.http.models import Distance, VectorParams
from typing import List, Dict, Any, Optional
import logging
import os
from models.cwe import CWEEntry

logger = logging.getLogger(__name__)

class QdrantDenseRetriever:
    """Dense retriever using Qdrant through Langchain for vector storage and search."""
    
    def __init__(
        self,
        name: str = "qdrant_retriever",
        location: str = "./data/qdrant",
        collection_name: str = "cwe_chunks",
        vector_size: int = 1536,
        embedding_client: Embeddings = None,
        distance: Distance = Distance.COSINE,
        batch_size: int = 100
    ):
        self.name = name
        self.collection_name = collection_name
        self.vector_size = vector_size
        self.embedding_client = embedding_client
        self.batch_size = batch_size
        self.distance = distance  # Store the distance parameter for reset_collection
        
        if not self.embedding_client:
            raise ValueError("Embedding client must be provided")
        
        # Initialize Qdrant client
        self.client = QdrantClient(
            path=location,
            prefer_grpc=True
        )
        
        # Initialize collection if needed
        self._setup_collection(distance)
        
        # Initialize Langchain vector store
        self.vector_store = QdrantVectorStore(
            client=self.client,
            collection_name=self.collection_name,
            embedding=self.embedding_client
        )
        
    def _setup_collection(self, distance: Distance):
        """Set up the Qdrant collection."""
        try:
            collections = self.client.get_collections().collections
            exists = any(c.name == self.collection_name for c in collections)
            
            if not exists:
                self.client.create_collection(
                    collection_name=self.collection_name,
                    vectors_config=VectorParams(
                        size=self.vector_size,
                        distance=distance
                    )
                )
                logger.info(f"Created collection {self.collection_name}")
            else:
                logger.info(f"Collection {self.collection_name} already exists")
                
        except Exception as e:
            logger.error(f"Error setting up collection: {e}")
            raise
    
    def reset_collection(self):
        """Delete and recreate the collection."""
        try:
            collections = self.client.get_collections().collections
            exists = any(c.name == self.collection_name for c in collections)
            
            if exists:
                self.client.delete_collection(self.collection_name)
                logger.info(f"Deleted existing collection {self.collection_name}")
                
            self.client.create_collection(
                collection_name=self.collection_name,
                vectors_config=VectorParams(
                    size=self.vector_size,
                    distance=self.distance  # Use the stored distance parameter
                )
            )
            logger.info(f"Created fresh collection {self.collection_name}")
            
            # Re-initialize vector store with the new collection
            self.vector_store = QdrantVectorStore(
                client=self.client,
                collection_name=self.collection_name,
                embedding=self.embedding_client
            )
            
        except Exception as e:
            logger.error(f"Error resetting collection: {e}")
            raise
            
    def load_data(self, dataset: List[Dict[str, Any]]):
        """Load and index dataset."""
        try:
            # Convert dataset to Langchain Document format
            documents = []
            for item in dataset:
                if not isinstance(item.get('entry'), CWEEntry):
                    logger.warning("Skipping invalid entry: not a CWEEntry instance")
                    continue
                entry = item['entry']
                documents.append(Document(
                    page_content=entry.to_searchable_text(),
                    metadata={
                        'doc_id': str(item['doc_id']),
                        'name': entry.Name,
                        'type': entry.Abstraction,
                        'status': entry.Status,
                        'original_content': entry.Description
                    }
                ))
            # Add documents to vector store
            self.vector_store.add_documents(documents)
            logger.info(f"Added {len(documents)} documents to vector store")
        except Exception as e:
            logger.error(f"Error loading data: {e}")
            raise
            
    def search(
        self,
        query: str,
        k: int = 5,
        score_threshold: float = 0.3,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """Search for relevant documents."""
        try:
            results = self.vector_store.similarity_search_with_score(
                query,
                k=k,
                score_threshold=score_threshold,
                **kwargs
            )
            formatted_results = []
            for doc, score in results:
                formatted_results.append({
                    "metadata": {
                        "doc_id": doc.metadata["doc_id"],
                        "name": doc.metadata["name"],
                        "type": doc.metadata["type"],
                        "original_content": doc.metadata["original_content"]
                    },
                    "similarity": score
                })
            return formatted_results
        except Exception as e:
            logger.error(f"Error during search: {e}")
            raise

    def get_metadata(self) -> Dict[str, Any]:
        """Get metadata about this retriever."""
        try:
            collection_info = self.client.get_collection(self.collection_name)
            return {
                "name": self.name,
                "type": "qdrant_dense",
                "collection_name": self.collection_name,
                "vector_size": self.vector_size,
                "total_points": collection_info.points_count
            }
        except Exception as e:
            logger.error(f"Error getting metadata: {e}")
            return {
                "name": self.name,
                "type": "qdrant_dense",
                "collection_name": self.collection_name,
                "vector_size": self.vector_size
            }