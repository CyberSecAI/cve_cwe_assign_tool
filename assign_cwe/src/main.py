# src/main.py

"""
CWE Knowledge Base Application Entry Point

This script initializes and runs the CWE Knowledge Base application,
setting up the enhanced retrievers, agents, and handling the main application flow.
"""

import logging
from pathlib import Path
import json
import os
import sys
import time
import argparse
from typing import Dict, Any, Optional

# Local imports
from config.settings import ConfigManager
from models.cwe import load_cwe_database
from models.vulnerability_info import VulnerabilityInfo
from utils.reset import reset_storage
from utils.logger import setup_logging, get_logger
from utils.file_ops import ensure_directory, save_json, save_markdown
from utils.vulnerability_retriever import VulnerabilityInfoRetriever
from utils.vulnerability_processor import (
    VulnerabilityProcessor,
    CSVVulnerabilityProcessor
)
from utils.llm_factory import LLMFactory
from agents.enhanced_llm_with_relationships import RelationshipEnhancedLLMAgent
from agents.enhanced_llm import EnhancedLLMAgent

# Set up logging
setup_logging()
logger = get_logger(__name__)



def setup_main_logger(output_dir: str) -> None:
    """
    Set up the main logger to write to a fresh log file.
    
    Args:
        output_dir: Directory to store the log file
    """
    # Ensure directory exists
    ensure_directory(output_dir)
    log_file = os.path.join(output_dir, "processing_main.log")
    
    # Get the root logger from standard logging
    root_logger = logging.getLogger()
    
    # Remove any existing handlers from standard logging root logger
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create a new file handler with mode='w' to start fresh
    file_handler = logging.FileHandler(log_file, mode='w')
    file_formatter = logging.Formatter('%(asctime)s | %(levelname)-8s | %(message)s', '%Y-%m-%d %H:%M:%S')
    file_handler.setFormatter(file_formatter)
    
    # Add the handler and set level
    root_logger.addHandler(file_handler)
    root_logger.setLevel(logging.INFO)
    
    # Handle Loguru logger separately
    # First, import it explicitly
    from loguru import logger as loguru_logger
    
    # Remove all existing Loguru sinks (if possible to do without handlers attribute)
    try:
        import sys
        loguru_logger.remove()  # Remove all existing handlers
        
        # Add a new sink for the file
        loguru_logger.add(
            log_file,
            rotation=None,  # Don't rotate logs
            mode='w',  # Overwrite existing file
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {message}",
            level="INFO"
        )
        
        # Also add console output back
        loguru_logger.add(sys.stderr, level="INFO")
    except Exception as e:
        print(f"Warning: Could not configure Loguru logger: {e}")
    
    # Also set up the custom logger from utils.logger if it's a standard logger
    try:
        from utils.logger import get_logger
        custom_logger = get_logger(__name__)
        
        if hasattr(custom_logger, 'handlers'):
            # It's a standard logger
            for handler in custom_logger.handlers[:]:
                custom_logger.removeHandler(handler)
            custom_logger.addHandler(file_handler)
            custom_logger.setLevel(logging.INFO)
            custom_logger.info(f"Custom logger initialized, writing to {log_file}")
    except Exception as e:
        print(f"Warning: Could not reconfigure custom logger: {e}")
    
    # Log initialization message
    root_logger.info(f"Main logger initialized, writing to {log_file}")
        
        
class CWEKnowledgeBase:
    """Main application class managing the CWE knowledge base and search functionality."""
    
    _cached_entries = None  # Cache for CWE entries
    
    def __init__(self, config_manager: ConfigManager, output_dir: str = "./output", force_reload: bool = False, rebuild_vectors: bool = False):
        """Initialize the knowledge base."""
        self.logger = get_logger(__name__)
        self.config = config_manager
        self.output_dir = output_dir  # Store the output_dir
        self.rebuild_vectors = rebuild_vectors  # Store the rebuild_vectors flag
        
        self._initialize_api_clients()
        
        if CWEKnowledgeBase._cached_entries is None or force_reload:
            self.logger.info("Loading database and initializing components")
            self.entries = self._load_database()
            CWEKnowledgeBase._cached_entries = self.entries
            self.retriever = self._initialize_retriever(rebuild_vectors=self.rebuild_vectors)
        else:
            self.logger.info("Using cached database entries")
            self.entries = CWEKnowledgeBase._cached_entries
            self.retriever = self._initialize_retriever(rebuild_vectors=self.rebuild_vectors)
        
        self.agents = self._initialize_agents()
        self.logger.success("CWE Knowledge Base initialization complete")
    
    def _initialize_api_clients(self):
        """Initialize API clients for different services."""
        self.logger.info("Initializing API clients")
        
        # Initialize embedding model (using OpenAI for embeddings)
        from langchain_openai import OpenAIEmbeddings
        self.embedding_model = OpenAIEmbeddings(
            model="text-embedding-3-small",
            openai_api_key=os.getenv("OPENAI_API_KEY")
        )
        
        # Retrieve llm_config from the configuration
        llm_config = self.config.config.llm_config
        llm_provider = llm_config.get("llm_type", "gemini").lower()
        
        # Determine the correct environment variable based on the provider
        if llm_provider == "anthropic":
            env_key = os.getenv("ANTHROPIC_API_KEY")
            key_name = "ANTHROPIC_API_KEY"
        elif llm_provider == "openai":
            env_key = os.getenv("OPENAI_API_KEY")
            key_name = "OPENAI_API_KEY"
        elif llm_provider == "gemini":
            env_key = os.getenv("GOOGLE_API_KEY")
            key_name = "GOOGLE_API_KEY"
        elif llm_provider == "cohere":
            env_key = os.getenv("COHERE_API_KEY")
            key_name = "COHERE_API_KEY"
        else:
            env_key = None
            key_name = "Unknown"
        
        # If the YAML value is empty, fall back to the environment variable
        llm_config["api_key"] = llm_config.get("api_key") or env_key
        
        if not llm_config["api_key"]:
            raise ValueError(f"No API key provided for {llm_provider} (expected environment variable {key_name})")
        
        # Initialize LLM using the factory
        try:
            self.llm = LLMFactory.create_llm(llm_provider, llm_config)
            self.logger.info(f"Successfully initialized {llm_provider} LLM")
        except Exception as e:
            self.logger.error(f"Failed to initialize LLM: {e}")
            raise


    
    def _load_database(self):
        """Load CWE database."""
        self.logger.info("Loading CWE database from {}", self.config.config.cwe_database_path)
        try:
            entries = load_cwe_database(self.config.config.cwe_database_path)
            self.logger.success("Successfully loaded {} CWE entries", len(entries))
            return entries
        except Exception as e:
            self.logger.exception("Failed to load CWE database: {}", str(e))
            raise


    def _initialize_retriever(self, rebuild_vectors=False):
        """Initialize the enhanced hybrid retriever.
        
        Args:
            rebuild_vectors: If True, recreate the vector database from scratch
        """
        self.logger.info("Initializing enhanced hybrid retriever with Neo4j")
        try:
            neo4j_config = {
                'url': self.config.env.neo4j_url,
                'username': self.config.env.neo4j_username,
                'password': self.config.env.neo4j_password
            }
            
            # Test embedding model
            try:
                _ = self.embedding_model.embed_query("test")
            except Exception as e:
                self.logger.warning(f"OpenAI connection failed, will retry: {e}")
                
            from retrievers.enhanced_hybrid import EnhancedHybridRetriever
            retriever = EnhancedHybridRetriever(
                name="cwe_retriever",
                llm_config=self.config.config.llm_config,  
                embedding_client=self.embedding_model,
                neo4j_config=neo4j_config,
                output_dir=self.output_dir,
                cwe_entries=self.entries
            )
            
            # Check if we need to rebuild the vector database or if it's already loaded
            should_load_data = rebuild_vectors
            
            if not should_load_data:
                # Check if the Qdrant collection exists and has the expected number of entries
                try:
                    # Get access to the dense retriever
                    dense_retriever = getattr(retriever, 'dense_retriever', None)
                    if dense_retriever and hasattr(dense_retriever, 'client'):
                        collection_name = dense_retriever.collection_name
                        client = dense_retriever.client
                        
                        # Check if collection exists
                        collections = client.get_collections().collections
                        exists = any(c.name == collection_name for c in collections)
                        
                        if exists:
                            # Check if collection has the expected number of entries
                            collection_info = client.get_collection(collection_name)
                            expected_entries = len(self.entries)
                            
                            # Allow for slight differences in count
                            if collection_info.points_count > expected_entries * 1.1:
                                self.logger.warning(f"Vector database has {collection_info.points_count} entries but expected ~{expected_entries}. It appears to be duplicating entries. Will reset and reload.")
                                should_load_data = True
                                
                                # Reset the collection using the reset_collection method
                                if hasattr(dense_retriever, 'reset_collection'):
                                    self.logger.info(f"Resetting collection {collection_name}")
                                    dense_retriever.reset_collection()
                                else:
                                    # Fallback if reset_collection not available
                                    self.logger.info(f"Deleting existing collection {collection_name}")
                                    client.delete_collection(collection_name)
                                    # The collection will be recreated when load_data is called
                                    
                            elif abs(collection_info.points_count - expected_entries) < 10:
                                self.logger.info(f"Vector database already contains {collection_info.points_count} entries (expected ~{expected_entries}). Skipping data loading.")
                                should_load_data = False
                            else:
                                self.logger.warning(f"Vector database has {collection_info.points_count} entries but expected {expected_entries}. Will reset and reload.")
                                should_load_data = True
                                
                                # Reset the collection using the reset_collection method
                                if hasattr(dense_retriever, 'reset_collection'):
                                    self.logger.info(f"Resetting collection {collection_name}")
                                    dense_retriever.reset_collection()
                                else:
                                    # Fallback if reset_collection not available
                                    self.logger.info(f"Deleting existing collection {collection_name}")
                                    client.delete_collection(collection_name)
                                    # The collection will be recreated when load_data is called
                        else:
                            self.logger.info("Vector database collection does not exist. Will create and load data.")
                            should_load_data = True
                except Exception as e:
                    self.logger.warning(f"Error checking vector database status: {e}. Will proceed with data loading.")
                    should_load_data = True
            else:
                # If rebuild_vectors is True, use reset_collection if available
                try:
                    dense_retriever = getattr(retriever, 'dense_retriever', None)
                    if dense_retriever and hasattr(dense_retriever, 'reset_collection'):
                        self.logger.info("Forcing vector database rebuild as requested")
                        dense_retriever.reset_collection()
                except Exception as e:
                    self.logger.warning(f"Error resetting collection: {e}. Will proceed with standard data loading.")
            
            # Load data only if needed
            if should_load_data:
                self.logger.info("Loading data into retriever...")
                retriever.load_data(self.entries)
                self.logger.success("Successfully loaded data into retriever")
                
                # Verify the collection size after loading
                try:
                    dense_retriever = getattr(retriever, 'dense_retriever', None)
                    if dense_retriever and hasattr(dense_retriever, 'client'):
                        collection_name = dense_retriever.collection_name
                        client = dense_retriever.client
                        collection_info = client.get_collection(collection_name)
                        self.logger.info(f"Vector database now contains {collection_info.points_count} entries")
                except Exception as e:
                    self.logger.warning(f"Error verifying collection size after loading: {e}")
            else:
                self.logger.info("Using existing vector database, skipping data loading")
            
            if hasattr(retriever, 'ensure_graph_initialized'):
                self.logger.info("Ensuring NetworkX graph is initialized...")
                retriever.ensure_graph_initialized()
                try:
                    # Check if property_graph attribute exists and initialize its graph too
                    if hasattr(retriever, 'property_graph'):
                        self.logger.info("Ensuring Neo4j property graph NetworkX representation is initialized...")
                        retriever.property_graph.ensure_graph_initialized()
                except Exception as e:
                    self.logger.warning(f"Error initializing property graph NetworkX representation: {e}")
                
            self.logger.success("Successfully initialized enhanced hybrid retriever with Neo4j")
            return retriever
        except Exception as e:
            self.logger.exception("Failed to initialize retriever: {}", str(e))
            raise
        
    def _initialize_agents(self):
        """Initialize the LLM agents with the loaded database entries."""
        self.logger.info("Initializing enhanced LLM agents")
        try:
            shared_retriever = self.retriever
            
            # Ensure The Retriever Is Marked As Loaded
            if hasattr(shared_retriever, 'loaded') and not shared_retriever.loaded:
                self.logger.info("Setting retriever loaded flag to True")
                shared_retriever.loaded = True
            
            cwe_database_path = self.config.config.cwe_database_path
            
            # Get LLM provider and config from settings; gemini default
            llm_provider = self.config.config.llm_config.get("llm_type", "gemini")
            llm_config = self.config.config.llm_config
            
            self.logger.info(f"Using {llm_provider} LLM provider for agents")
            self.logger.info(f"Using CWE database from: {cwe_database_path}")
            
            #Make entries available directly on the knowledge base
            self.cwe_entries = self.entries
            
            # Use RelationshipEnhancedLLMAgent instead of EnhancedLLMAgent
            agents = {
                'analyzer': RelationshipEnhancedLLMAgent(
                    role="analyzer",
                    llm_provider=llm_provider,
                    llm_config=llm_config,
                    max_iterations=self.config.config.max_iterations,
                    max_input_length=self.config.config.agent_config["max_input_length"], 
                    context_limit=self.config.config.agent_config["context_limit"],  
                    embedding_client=self.embedding_model,
                    retriever=shared_retriever,
                    cwe_database_path=cwe_database_path
                ),
                'critic': RelationshipEnhancedLLMAgent(
                    role="critic",
                    llm_provider=llm_provider,
                    llm_config=llm_config,
                    max_iterations=self.config.config.max_iterations,
                    max_input_length=self.config.config.agent_config["max_input_length"], 
                    context_limit=self.config.config.agent_config["context_limit"],  
                    embedding_client=self.embedding_model,
                    retriever=shared_retriever,
                    cwe_database_path=cwe_database_path
                ),
                'resolver': RelationshipEnhancedLLMAgent(
                    role="resolver",
                    llm_provider=llm_provider,
                    llm_config=llm_config,
                    max_iterations=self.config.config.max_iterations,
                    max_input_length=self.config.config.agent_config["max_input_length"], 
                    context_limit=self.config.config.agent_config["context_limit"],  
                    embedding_client=self.embedding_model,
                    retriever=shared_retriever,
                    cwe_database_path=cwe_database_path
                )
            }
            
            # ADDITIONAL FIX: Manually set cwe_entries on each agent if they're empty
            for role, agent in agents.items():
                if not hasattr(agent, 'cwe_entries') or not agent.cwe_entries:
                    self.logger.warning(f"{role} agent missing CWE entries, setting them manually")
                    agent.cwe_entries = self.entries
                
                if hasattr(agent, 'cwe_entries') and agent.cwe_entries:
                    self.logger.info(f"{role} agent initialized with {len(agent.cwe_entries)} CWE entries")
                else:
                    self.logger.warning(f"{role} agent still missing CWE entries after fix attempt")
                    
            self.logger.info("Successfully initialized all relationship-enhanced agents")
            return agents
            
        except Exception as e:
            self.logger.exception("Failed to initialize agents: {}", str(e))
            raise


    def _log_analysis_metrics(self, vuln_info: VulnerabilityInfo):
        """Log metrics for the analysis."""
        try:
            retriever_metrics = self.retriever.get_metadata()
            metrics = {
                'cve_id': vuln_info.cve_id,
                'num_relevant_cwes': len(vuln_info.relevant_cwes),
                'retriever_stats': {
                    'rag_metrics': retriever_metrics.get('rag_retriever', {}),
                    'graph_metrics': retriever_metrics.get('property_graph', {})
                }
            }
            logger.info(f"Analysis metrics: {json.dumps(metrics, indent=2)}")
        except Exception as e:
            logger.error(f"Error logging metrics: {e}")


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='CWE Knowledge Base')
    parser.add_argument('--reset', action='store_true', help='Reset all storage and cache before running')
    parser.add_argument('--csv', type=str, help='Path to CSV file containing CVE IDs and descriptions')
    parser.add_argument('--output-dir', type=str, default='./cve_results', help='Directory to store CVE analysis results')
    parser.add_argument('--llm-provider', type=str, default=None, help='LLM provider to use (anthropic, gemini, openai)')
    parser.add_argument('--rebuild-vectors', action='store_true', help='Force rebuilding the vector database even if it exists')

    return parser.parse_args()



def process_single_cve(kb, cve_path, config, output_dir):
    """Process a single CVE."""
    if not os.path.exists(cve_path):
        logger.error(f"CVE folder not found: {cve_path}")
        return
        
    logger.info(f"Processing single CVE from: {cve_path}")
    cve_id = os.path.basename(cve_path)
    
    # Create processor for this CVE
    processor = VulnerabilityProcessor(kb, output_dir, config)
    
    # Set up info retriever
    info_retriever = VulnerabilityInfoRetriever(config, output_dir)
    
    try:
        # Get vulnerability info as markdown
        cve_content = info_retriever.get_markdown(cve_id)
        
        if not cve_content:
            logger.warning(f"No content found for {cve_id}, using minimal description")
            cve_content = f"CVE {cve_id} - No description available"
        
        # Process the vulnerability
        result = processor.process_vulnerability(
            cve_id=cve_id,
            description=cve_content
        )
        
        if result.is_success:
            logger.success(f"Successfully processed {cve_id}. Results saved to {os.path.join(output_dir, cve_id)}")
        else:
            logger.error(f"Error processing {cve_id}: {result.error}")
            
    except Exception as e:
        logger.exception(f"Error processing {cve_id}: {e}")




def main():
    """Main application entry point."""
    args = parse_arguments()
    
    try:
        # Initialize configuration
        force_reload = False
        if args.reset:
            logger.info("Resetting storage...")
            reset_storage()
            force_reload = True
        
        # Load configuration
        config_path = Path("assign_cwe/src/config.yaml")
        if not config_path.exists():
            raise FileNotFoundError("config.yaml not found. Please create a configuration file.")
            
        config_manager = ConfigManager(str(config_path))
        
        # Override LLM provider if specified
        if args.llm_provider:
            logger.info(f"Overriding LLM provider to: {args.llm_provider}")
            config_manager.config.llm_config["llm_type"] = args.llm_provider
        
        # Ensure output directory exists
        output_dir = ensure_directory(args.output_dir)
        
        # Set up main logger with fresh log file
        setup_main_logger(output_dir)
        
        # Pass rebuild_vectors flag to knowledge base initialization
        if args.rebuild_vectors:
            logger.info("Force rebuilding vector database as requested")
        
        # Initialize knowledge base
        kb = CWEKnowledgeBase(config_manager, output_dir=output_dir, 
                              force_reload=force_reload, 
                              rebuild_vectors=args.rebuild_vectors)
        
        # Load CWE database
        cwe_entries = load_cwe_database(config_manager.config.cwe_database_path)
        
        # Process CSV file
        if args.csv:
            if not os.path.exists(args.csv):
                logger.error(f"CSV file not found: {args.csv}")
                return
                
            logger.info(f"Processing vulnerabilities from CSV file: {args.csv}")
            processor = CSVVulnerabilityProcessor(kb, output_dir, config_manager)
            results = processor.process_csv(args.csv)
            
            logger.info(f"CSV processing complete:")
            logger.info(f"- Processed: {results['processed_count']} vulnerabilities")
            logger.info(f"- Errors: {results['error_count']}")
            logger.info(f"- Results saved to: {results['output_directory']}")
            
            return
        

        
    except FileNotFoundError as e:
        logger.error(f"Configuration error: {e}")
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
    except Exception as e:
        logger.exception(f"Application error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()