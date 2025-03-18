# src/config/settings.py
ENV_FILE_PATH = "../../env/.env"
ENV_FILE_ENCODING = 'utf-8'

from utils.logger import get_logger
from typing import Dict, Optional, Any, List
from pydantic_settings import BaseSettings
from pydantic import Field
from functools import lru_cache
import yaml
import os
from pathlib import Path
from dotenv import load_dotenv, dotenv_values

logger = get_logger(__name__)


class EnvSettings(BaseSettings):
    """Environment-specific settings that should come from .env"""
    # API keys for different LLM providers
    openai_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv('OPENAI_API_KEY', ''),
        description="OpenAI API key"
    )
    google_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv('GOOGLE_API_KEY', ''),
        description="Google API key for Gemini models"
    )
    anthropic_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv('ANTHROPIC_API_KEY', ''),
        description="Anthropic API key"
    )
    cohere_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv('COHERE_API_KEY', ''),
        description="Cohere API key"
    )
    voyage_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv('VOYAGE_API_KEY', ''),
        description="Voyage AI API key"
    )

    # Neo4j settings
    neo4j_url: str = Field(
        default_factory=lambda: os.getenv('NEO4J_URL', 'bolt://localhost:7687'),
        description="Neo4j connection URL"
    )
    neo4j_username: str = Field(
        default_factory=lambda: os.getenv('NEO4J_USERNAME', 'neo4j'),
        description="Neo4j username"
    )
    neo4j_password: str = Field(
        default_factory=lambda: os.getenv('NEO4J_PASSWORD', ''),
        description="Neo4j password"
    )

    class Config:
        env_file = ENV_FILE_PATH
        env_file_encoding = ENV_FILE_ENCODING
        extra = 'allow'

    @classmethod
    def load(cls) -> 'EnvSettings':
        """Load environment variables from .env file"""
        env_path = cls.Config.env_file
        if not os.path.exists(env_path):
            raise FileNotFoundError(f"Environment file not found at {env_path}")
        load_dotenv(env_path)
        config = dotenv_values(env_path)
        
        # Check required keys - Neo4j is always required
        if not config.get('NEO4J_PASSWORD'):
            raise ValueError("NEO4J_PASSWORD not set in environment")
        
        # Set environment variables
        for key, value in config.items():
            os.environ[key] = value
        
        return cls(**config)


class AppConfig(BaseSettings):
    """Application configuration that comes from config.yaml"""
    # Data processing settings
    chunk_size: int = Field(default=1000, description="Size of text chunks for processing")
    chunk_overlap: int = Field(default=200, description="Overlap between text chunks")
    
    # Model settings
    llm_config: Dict[str, Any] = Field(..., description="Configuration for the LLM")
    max_iterations: int = Field(default=3, description="Maximum number of iterations for feedback loop")
    
    # Embedding settings - supporting both new and old formats
    embedding_config: Dict[str, Any] = Field(
        default={
            "provider": "openai",
            "model": "text-embedding-3-small",
            "batch_size": 100
        },
        description="Configuration for embeddings"
    )

    # Legacy fields for backward compatibility
    embedding_model: Optional[str] = Field(None, description="Legacy: OpenAI embedding model to use")
    embedding_batch_size: Optional[int] = Field(None, description="Legacy: Batch size for embedding generation")

    # Legacy openai_config for backward compatibility
    openai_config: Optional[Dict[str, Any]] = Field(None, description="Legacy: Configuration for OpenAI")
    
    # Retriever settings
    retriever_weights: Dict[str, float] = Field(
        default={'dense': 0.4, 'sparse': 0.3, 'graph': 0.3},
        description="Weights for different retriever types"
    )
    
    # Database settings
    cwe_database_path: str = Field(
        default="data_in/cwe_trimmed_10.json",
        description="Path to CWE database file"
    )
    
    # Cache settings
    cache_dir: str = Field(
        default="./cache",
        description="Directory for caching embeddings and other data"
    )
    max_cache_size: int = Field(
        default=1000,
        description="Maximum number of items to keep in cache"
    )
    
    # Neo4j storage directory
    neo4j_storage_dir: str = Field(
        default="./data/neo4j/property_graph",
        description="Storage directory for Neo4j property graph data"
    )
    data_dir: str = Field(
        default="./data/neo4j/data",
        description="Directory for general Neo4j data"
    )
            
    agent_config: Dict[str, Any] = Field(
        default={
            'max_input_length': 20000,
            'context_limit': 5
        },
        description="Configuration for agents"
    )      
    
    data_sources: Dict[str, str] = Field(
        default_factory=dict,
        description="Data sources for similarity, CVE info, and CVE references"
    )
    
    # Processor settings
    processor_config: Dict[str, Any] = Field(
        default={
            'save_intermediate_files': True,
            'rate_limit_delay': 1.0
        },
        description="Configuration for vulnerability processors"
    )

    # Legacy openai_config for backward compatibility
    openai_config: Optional[Dict[str, Any]] = Field(None, description="Legacy: Configuration for OpenAI")

    class Config:
        env_file = ENV_FILE_PATH
        env_file_encoding = ENV_FILE_ENCODING
        extra = 'allow'


def load_yaml_config(config_path: str = "assign_cwe/src/config.yaml") -> dict:
    """Load configuration from YAML file"""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


class ConfigManager:
    """Configuration manager handling both YAML config and environment variables"""

    def __init__(self, config_path: str = "assign_cwe/src/config.yaml"):
        logger.info("Initializing configuration from {}", config_path)
        try:
            self.env = EnvSettings.load()
            logger.debug("Environment settings loaded successfully")
        except Exception as e:
            logger.exception("Failed to load environment settings: {}", str(e))
            raise
        
        # Ensure essential API keys are available
        if not os.getenv('ANTHROPIC_API_KEY'):
            logger.error("ANTHROPIC_API_KEY not set in environment")
            raise ValueError("ANTHROPIC_API_KEY not set in environment")
        if not os.getenv('COHERE_API_KEY'):
            logger.error("COHERE_API_KEY not set in environment")
            raise ValueError("COHERE_API_KEY not set in environment")
        if not os.getenv('NEO4J_PASSWORD'):
            logger.error("NEO4J_PASSWORD not set in environment")
            raise ValueError("NEO4J_PASSWORD not set in environment")
        
        # Load YAML config
        yaml_config = load_yaml_config(config_path)
        self.config = AppConfig(**yaml_config)
        
        # Migrate legacy settings
        self._migrate_legacy_settings()
        
        # Validate LLM configuration
        self._validate_llm_config()
        
        logger.success("Configuration initialized successfully")
        self._initialize_environment()
    
    def _migrate_legacy_settings(self):
        """Migrate legacy settings to new structure for backward compatibility"""
        # Handle legacy embedding settings
        if self.config.embedding_model is not None:
            self.config.embedding_config["model"] = self.config.embedding_model
            logger.warning("Using deprecated 'embedding_model' setting. Please update to 'embedding_config.model'")
            
        if self.config.embedding_batch_size is not None:
            self.config.embedding_config["batch_size"] = self.config.embedding_batch_size
            logger.warning("Using deprecated 'embedding_batch_size' setting. Please update to 'embedding_config.batch_size'")
    
    def _validate_llm_config(self):
        """Validate LLM configuration and API keys"""
        llm_type = self.config.llm_config.get("llm_type", "").lower()
        
        # Check if the llm_type is supported
        supported_providers = ["anthropic", "openai", "gemini", "cohere"]
        if llm_type not in supported_providers:
            logger.warning(f"Unsupported llm_type: {llm_type}. Must be one of {supported_providers}")
            logger.warning("Falling back to 'anthropic' provider")
            self.config.llm_config["llm_type"] = "anthropic"
            llm_type = "anthropic"
        
        # API key validation with expected prefixes - just check format without raising errors
        api_key_map = {
            "anthropic": (self.env.anthropic_api_key, "ANTHROPIC_API_KEY", "sk-ant-"),
            "openai": (self.env.openai_api_key, "OPENAI_API_KEY", "sk-"),
            "gemini": (self.env.google_api_key, "GOOGLE_API_KEY", "AI"),
            "cohere": (self.env.cohere_api_key, "COHERE_API_KEY", "")
        }
        
        # Get key for selected provider and do basic format check
        api_key, key_name, expected_prefix = api_key_map[llm_type]
        if expected_prefix and api_key and not api_key.startswith(expected_prefix):
            logger.warning(f"{key_name} may not be valid - doesn't start with expected prefix '{expected_prefix}'")
    
    def _initialize_environment(self):
        """Initialize environment with required settings"""
        os.makedirs(self.config.cache_dir, exist_ok=True)
        os.makedirs(self.config.neo4j_storage_dir, exist_ok=True)
    
    def get_neo4j_config(self) -> Dict:
        """Get Neo4j configuration"""
        if not self.env.neo4j_password:
            raise ValueError("NEO4J_PASSWORD not set in environment")
            
        return {
            "url": self.env.neo4j_url,
            "username": self.env.neo4j_username,
            "password": self.env.neo4j_password,
            "storage_dir": self.config.neo4j_storage_dir,
            "database": "neo4j"  # Explicitly specify default database
        }
    
    def update_retriever_weights(self, new_weights: Dict[str, float]):
        """Update retriever weights with validation"""
        if not new_weights:
            raise ValueError("Weights cannot be empty")
        if not all(0 <= w <= 1 for w in new_weights.values()):
            raise ValueError("All weights must be between 0 and 1")
        if abs(sum(new_weights.values()) - 1.0) > 0.001:
            raise ValueError("Weights must sum to 1")
        self.config.retriever_weights = new_weights
    
    def get_text_splitter_config(self) -> Dict:
        """Get text splitter configuration"""
        return {
            "chunk_size": self.config.chunk_size,
            "chunk_overlap": self.config.chunk_overlap
        }
    
    def get_llm_config(self) -> Dict:
        """Get LLM configuration"""
        llm_config = self.config.llm_config.copy()
        
        # Add the corresponding API key
        llm_type = llm_config.get("llm_type", "anthropic").lower()
        if llm_type == "anthropic":
            llm_config["api_key"] = self.env.anthropic_api_key
        elif llm_type == "openai":
            llm_config["api_key"] = self.env.openai_api_key
        elif llm_type == "gemini":
            llm_config["api_key"] = self.env.google_api_key
        elif llm_type == "cohere":
            llm_config["api_key"] = self.env.cohere_api_key
        
        return {
            "llm_config": llm_config,
            "max_iterations": self.config.max_iterations
        }
    
    def get_embedding_config(self) -> Dict:
        """Get embedding configuration"""
        embedding_config = self.config.embedding_config.copy()
        
        # Add the corresponding API key
        provider = embedding_config.get("provider", "openai").lower()
        if provider == "openai":
            embedding_config["api_key"] = self.env.openai_api_key
        elif provider == "cohere":
            embedding_config["api_key"] = self.env.cohere_api_key
        elif provider == "voyage":
            embedding_config["api_key"] = self.env.voyage_api_key
        
        return embedding_config
    
    def set_llm_provider(self, provider: str):
        """Set the LLM provider to use"""
        if provider not in ["anthropic", "openai", "gemini", "cohere"]:
            raise ValueError(f"Unsupported LLM provider: {provider}")
        
        # Check if API key is available
        key_map = {
            "anthropic": self.env.anthropic_api_key,
            "openai": self.env.openai_api_key, 
            "gemini": self.env.google_api_key,
            "cohere": self.env.cohere_api_key
        }
        
        if not key_map[provider]:
            raise ValueError(f"Cannot set provider to {provider}: API key not available")
        
        self.config.llm_config["llm_type"] = provider