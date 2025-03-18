# src/retrievers/neo4j_property_graph.py

from typing import List, Dict, Any, Optional, Set, Tuple
from utils.logger import get_logger
from neo4j import GraphDatabase
import numpy as np
import networkx as nx
from collections import defaultdict, Counter
import re
import time
import datetime

# Initialize logger first
logger = get_logger(__name__)

# Simple constants without complex type validation
CWE_ENTITY_TYPES = ["Pillar", "Class", "Base", "Variant", "Compound"]
CWE_RELATION_TYPES = [
    "ChildOf", "ParentOf", "CanPrecede", "CanFollow", "PeerOf", "CanAlsoBe", 
    "Requires", "RequiredBy", "StartsWith", "StartsFrom"
]

# Define relationship categories for prioritization
CHAIN_RELATIONSHIPS = ["CanPrecede", "CanFollow", "Requires", "RequiredBy"]
HIERARCHICAL_RELATIONSHIPS = ["ChildOf", "ParentOf"]
PEER_RELATIONSHIPS = ["PeerOf", "CanAlsoBe"]
STARTER_RELATIONSHIPS = ["StartsWith", "StartsFrom"]

# Define relationship weights for path scoring
RELATIONSHIP_WEIGHTS = {
    "CanPrecede": 1.5,    # High weight for vulnerability progression
    "CanFollow": 1.5,     # High weight for vulnerability progression
    "Requires": 1.6,      # Very high weight for dependency relationships
    "RequiredBy": 1.6,    # Very high weight for dependency relationships
    "ChildOf": 1.0,       # Medium weight for hierarchical relationships
    "ParentOf": 1.0,      # Medium weight for hierarchical relationships
    "PeerOf": 0.8,        # Lower weight for peer relationships
    "CanAlsoBe": 0.8,     # Lower weight for peer relationships
    "StartsWith": 1.2,    # Medium-high weight for starting relationships
    "StartsFrom": 1.2     # Medium-high weight for starting relationships
}

class CWEPropertyGraph:
    """Enhanced Neo4j-backed Property Graph implementation for CWE knowledge base."""
    
    def __init__(
        self, 
        name="cwe_graph",
        url="bolt://localhost:7687",
        username="neo4j",
        password=None,
        llm_config=None,
        embedding_client=None,
        embedding_dimension=1536,
        storage_dir=None
    ):
        self.name = name
        self.url = url
        self.username = username
        self.password = password
        self.llm_config = llm_config
        self.embedding_client = embedding_client
        self.embedding_dimension = embedding_dimension
        self.storage_dir = storage_dir
        
        self.driver = None
        self._initialize_neo4j()
        
        # Initialize NetworkX graph for path-based analysis and caching
        self.nx_graph = None
        self.path_cache = {}
        self.meta_path_cache = {}

    def _initialize_neo4j(self):
        """Initialize Neo4j connection."""
        try:
            # Validate required inputs
            if not self.password:
                raise ValueError("Neo4j password must be provided")
            if not self.username:
                raise ValueError("Neo4j username must be provided")

            # Connect to Neo4j
            self.driver = GraphDatabase.driver(
                self.url, 
                auth=(self.username, self.password)
            )
            
            # Test connection
            with self.driver.session() as session:
                # Create fulltext index if it doesn't exist
                try:
                    session.run("""
                    CALL db.index.fulltext.createNodeIndex(
                        "cwe_text", 
                        ["CWE"], 
                        ["name", "description", "alternate_terms"]
                    )
                    """)
                except Exception as e:
                    # Index might already exist
                    pass
                
                result = session.run("RETURN 1 as test")
                if result.single()["test"] == 1:
                    logger.info(f"Successfully initialized Neo4j connection at {self.url}")
                
        except Exception as e:
            logger.error(f"Failed to initialize Neo4j connection: {str(e)}")
            raise

    #Neo4j can't store complex objects (like maps or dictionaries) directly as node properties 
    # - it only accepts primitive types or arrays of primitive types. 
    # this alternate_terms is mainly to help the vector search find related terms. 
    # i.e. don't need to read or parse it - so flat array is best
    def _format_alternate_terms(self, alternate_terms):
        """Format alternate terms as a simple array of strings for Neo4j storage."""
        if not alternate_terms:
            return []
        
        return [term.Term for term in alternate_terms]

    def load_data(self, cwe_entries):
        """Load CWE entries into Neo4j with proper relationship types."""
        logger.info(f"Loading {len(cwe_entries)} CWE entries")
        
        try:
            with self.driver.session() as session:
                # Clear existing data
                session.run("MATCH (n) DETACH DELETE n")
                
                # Create CWE nodes
                for entry in cwe_entries:
                    # Create node with metadata
                    create_node_query = """
                    CREATE (c:CWE {
                        id: $id,
                        name: $name,
                        type: $type,
                        description: $description,
                        extended_description: $extended_description,
                        alternate_terms: $alternate_terms
                    })
                    """
                    
                    session.run(
                        create_node_query, 
                        {
                            "id": entry.ID,  # No "CWE-" prefix
                            "name": entry.Name,
                            "type": entry.Abstraction,
                            "description": entry.Description,
                            "extended_description": entry.ExtendedDescription,
                            "alternate_terms": self._format_alternate_terms(entry.AlternateTerms)
                        }
                    )                    
                
                # Create relationships with specific types
                for entry in cwe_entries:
                    if not entry.RelatedWeaknesses:
                        continue
                    
                    for rel in entry.RelatedWeaknesses:
                        # Use the relationship nature (type) as the relationship label
                        rel_type = rel.Nature.upper()  # Make sure it's uppercase for Neo4j convention
                        
                        create_rel_query = f"""
                        MATCH (source:CWE {{id: $source_id}})
                        MATCH (target:CWE {{id: $target_id}})
                        CREATE (source)-[r:{rel_type} {{
                            view_id: $view_id,
                            ordinal: $ordinal
                        }}]->(target)
                        """
                        
                        try:
                            session.run(
                                create_rel_query,
                                {
                                    "source_id": entry.ID,  # No "CWE-" prefix
                                    "target_id": rel.CweID,  # No "CWE-" prefix
                                    "view_id": rel.ViewID if hasattr(rel, "ViewID") else None,
                                    "ordinal": rel.Ordinal if hasattr(rel, "Ordinal") else None
                                }
                            )
                            logger.info(f"Created relationship: {entry.ID} -{rel.Nature}-> {rel.CweID}")
                        except Exception as e:
                            logger.warning(f"Error creating relationship: {e}")
            
            # Create text embeddings for search
            if self.embedding_client:
                self._create_embeddings(cwe_entries)
            
            # Initialize NetworkX graph for path-based analysis
            self._initialize_nx_graph()
                
            logger.info("Successfully loaded CWE entries into Neo4j")
            
        except Exception as e:
            logger.error(f"Error loading CWE entries: {str(e)}")
            raise

    def ensure_graph_initialized(self):
        """Ensure the NetworkX graph is initialized even if data loading was skipped."""
        if self.nx_graph is None:
            logger.info("NetworkX graph not initialized; initializing now...")
            self._initialize_nx_graph()
        return self.nx_graph is not None

    def _initialize_nx_graph(self):
        """Initialize NetworkX graph from Neo4j data for path-based analysis."""
        try:
            # Create a new directed graph
            G = nx.DiGraph()
            
            # Get all nodes and their properties
            with self.driver.session() as session:
                # Query all CWE nodes
                nodes_query = """
                MATCH (c:CWE)
                RETURN c.id as id, c.name as name, c.type as type
                """
                nodes = session.run(nodes_query)
                
                # Add nodes to graph
                for node in nodes:
                    G.add_node(
                        node["id"], 
                        name=node["name"], 
                        type=node["type"]
                    )
                
                # Query all relationships
                rels_query = """
                MATCH (source:CWE)-[r]->(target:CWE)
                RETURN source.id as source_id, type(r) as rel_type, target.id as target_id
                """
                relationships = session.run(rels_query)
                
                # Add edges to graph with weights based on relationship type
                for rel in relationships:
                    source_id = rel["source_id"]
                    target_id = rel["target_id"]
                    rel_type = rel["rel_type"]
                    
                    # Get weight for this relationship type (default to 1.0)
                    weight = RELATIONSHIP_WEIGHTS.get(rel_type, 1.0)
                    
                    G.add_edge(
                        source_id,
                        target_id,
                        rel_type=rel_type,
                        weight=weight
                    )
            
            # Store the NetworkX graph
            self.nx_graph = G
            logger.info(f"Initialized NetworkX graph with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges for path-based analysis")
            
            # Pre-compute meta-paths for common relationship patterns
            self._precompute_meta_paths()
            
        except Exception as e:
            logger.error(f"Error initializing NetworkX graph: {e}")
            self.nx_graph = None
    
    def _precompute_meta_paths(self):
        """Precompute and cache common meta-paths for faster retrieval."""
        try:
            if not self.nx_graph:
                logger.warning("NetworkX graph not initialized; skipping meta-path precomputation")
                return
            
            # Clear existing cache
            self.meta_path_cache = {
                "childof_chains": {},       # CWE chains along ChildOf relationships
                "canprecede_chains": {},    # CWE chains along CanPrecede relationships
                "requires_chains": {},      # CWE chains along Requires relationships
                "peer_groups": {},          # CWE groups connected by peer relationships
                "abstraction_paths": {}     # Paths across abstraction levels
            }
            
            # Compute common ChildOf chains (for abstraction hierarchies)
            for node in self.nx_graph.nodes():
                # Find ancestry path to highest level (typically Pillar)
                ancestors = []
                current = node
                visited = set([current])
                
                while True:
                    parents = []
                    for src, tgt, data in self.nx_graph.out_edges(current, data=True):
                        if data.get("rel_type") == "CHILDOF" and tgt not in visited:
                            parents.append(tgt)
                            visited.add(tgt)
                    
                    if not parents:
                        break
                    
                    # Add top parent to ancestors
                    current = parents[0]  # Just take first parent if multiple exist
                    ancestors.append(current)
                
                if ancestors:
                    self.meta_path_cache["childof_chains"][node] = ancestors
            
            # Compute common CanPrecede chains (for attack patterns)
            for node in self.nx_graph.nodes():
                # Find paths of consecutive CanPrecede relationships (max depth 3)
                followers = []
                queue = [(node, 0)]
                visited = set([node])
                
                while queue:
                    current, depth = queue.pop(0)
                    
                    if depth >= 3:
                        continue
                    
                    for src, tgt, data in self.nx_graph.out_edges(current, data=True):
                        if data.get("rel_type") == "CANPRECEDE" and tgt not in visited:
                            followers.append((tgt, depth + 1))
                            visited.add(tgt)
                            queue.append((tgt, depth + 1))
                
                if followers:
                    self.meta_path_cache["canprecede_chains"][node] = [f for f, _ in followers]
            
            # Compute peer groups (for alternative CWEs)
            peer_groups = {}
            visited_for_peers = set()
            
            for node in self.nx_graph.nodes():
                if node in visited_for_peers:
                    continue
                
                peers = set([node])
                queue = [node]
                visited_for_peers.add(node)
                
                while queue:
                    current = queue.pop(0)
                    
                    for src, tgt, data in self.nx_graph.edges(current, data=True):
                        rel_type = data.get("rel_type")
                        other_node = tgt if src == current else src
                        
                        if rel_type in ["PEEROF", "CANALSOBE"] and other_node not in visited_for_peers:
                            peers.add(other_node)
                            visited_for_peers.add(other_node)
                            queue.append(other_node)
                
                if len(peers) > 1:
                    group_id = min(peers)  # Use smallest CWE ID as group identifier
                    peer_groups[group_id] = list(peers)
                    
                    # Add all peers to the same group
                    for peer in peers:
                        self.meta_path_cache["peer_groups"][peer] = list(peers)
            
            # Compute abstraction paths (Variant -> Base -> Class -> Pillar)
            for node in self.nx_graph.nodes():
                node_type = self.nx_graph.nodes[node].get("type", "").lower()
                
                if node_type == "variant":
                    # Find path to Base, Class, and Pillar CWEs
                    abstraction_path = {"base": [], "class": [], "pillar": []}
                    
                    # First find immediate Base parents
                    for src, tgt, data in self.nx_graph.out_edges(node, data=True):
                        if data.get("rel_type") == "CHILDOF":
                            target_type = self.nx_graph.nodes[tgt].get("type", "").lower()
                            if target_type == "base":
                                abstraction_path["base"].append(tgt)
                                
                                # From each Base, find Class parents
                                for base_src, base_tgt, base_data in self.nx_graph.out_edges(tgt, data=True):
                                    if base_data.get("rel_type") == "CHILDOF":
                                        class_type = self.nx_graph.nodes[base_tgt].get("type", "").lower()
                                        if class_type == "class":
                                            abstraction_path["class"].append(base_tgt)
                                            
                                            # From each Class, find Pillar parents
                                            for class_src, class_tgt, class_data in self.nx_graph.out_edges(base_tgt, data=True):
                                                if class_data.get("rel_type") == "CHILDOF":
                                                    pillar_type = self.nx_graph.nodes[class_tgt].get("type", "").lower()
                                                    if pillar_type == "pillar":
                                                        abstraction_path["pillar"].append(class_tgt)
                    
                    if any(abstraction_path.values()):
                        self.meta_path_cache["abstraction_paths"][node] = abstraction_path
                        
            logger.info(f"Precomputed meta-paths: {', '.join(k + ': ' + str(len(v)) for k, v in self.meta_path_cache.items())}")
            
        except Exception as e:
            logger.error(f"Error precomputing meta-paths: {e}")
            self.meta_path_cache = {}
        
    def _get_node_relationships(self, node_id):
        """Get relationships for a specific node with proper relationship types."""
        relationships = []
        
        try:
            with self.driver.session() as session:
                # Get outgoing relationships of any type
                outgoing_query = """
                MATCH (source:CWE {id: $node_id})-[r]->(target:CWE)
                RETURN source.id as source_id, type(r) as label, target.id as target_id,
                    properties(r) as properties
                """
                
                records = session.run(outgoing_query, {"node_id": node_id})
                for record in records:
                    relationship = {
                        "source_id": record["source_id"],
                        "target_id": record["target_id"],
                        "label": record["label"],  # This will be the actual relationship type
                        "properties": record["properties"]
                    }
                    relationships.append(relationship)
                
                # Get incoming relationships of any type
                incoming_query = """
                MATCH (source:CWE)-[r]->(target:CWE {id: $node_id})
                RETURN source.id as source_id, type(r) as label, target.id as target_id,
                    properties(r) as properties
                """
                
                records = session.run(incoming_query, {"node_id": node_id})
                for record in records:
                    relationship = {
                        "source_id": record["source_id"],
                        "target_id": record["target_id"],
                        "label": record["label"],  # This will be the actual relationship type
                        "properties": record["properties"]
                    }
                    relationships.append(relationship)
                
            return relationships
            
        except Exception as e:
            logger.error(f"Error getting node relationships: {e}")
            return []

    def get_metadata(self):
        """Get metadata about the property graph including relationship types."""
        try:
            with self.driver.session() as session:
                # Count nodes
                node_count_query = "MATCH (n:CWE) RETURN count(n) as count"
                node_count = session.run(node_count_query).single()["count"]
                
                # Count relationships
                rel_count_query = "MATCH (:CWE)-[r]->(:CWE) RETURN count(r) as count"
                rel_count = session.run(rel_count_query).single()["count"]
                
                # Get unique relationship types
                rel_types_query = """
                MATCH ()-[r]->() 
                RETURN DISTINCT type(r) as rel_type, count(r) as count
                ORDER BY count DESC
                """
                rel_types = [(record["rel_type"], record["count"]) for record in session.run(rel_types_query)]
                
                # Get meta-path statistics
                meta_path_stats = {}
                for path_type, paths in self.meta_path_cache.items():
                    meta_path_stats[path_type] = len(paths)
                
                return {
                    "name": self.name,
                    "type": "neo4j_property_graph",
                    "num_nodes": node_count,
                    "num_relationships": rel_count,
                    "relationship_types": [rt for rt, _ in rel_types],
                    "relationship_counts": {rt: count for rt, count in rel_types},
                    "schema": {
                        "entity_types": CWE_ENTITY_TYPES,
                        "relation_types": CWE_RELATION_TYPES
                    },
                    "meta_path_stats": meta_path_stats
                }
        except Exception as e:
            logger.error(f"Error getting graph metadata: {e}")
            return {
                "name": self.name,
                "type": "neo4j_property_graph",
                "schema": {
                    "entity_types": CWE_ENTITY_TYPES,
                    "relation_types": CWE_RELATION_TYPES
                }
            }


    def _create_embeddings(self, cwe_entries):
        """Create embeddings for CWE entries with API compatibility."""
        try:
            # Create embeddings in batches
            batch_size = 10
            for i in range(0, len(cwe_entries), batch_size):
                batch = cwe_entries[i:i+batch_size]
                texts = [entry.to_searchable_text() for entry in batch]
                
                # Try different embedding client APIs
                try:
                    # Try embed_documents first (LangChain style)
                    embeddings = self.embedding_client.embed_documents(texts)
                except (AttributeError, NotImplementedError):
                    try:
                        # Try OpenAI-style client
                        embeddings = []
                        for text in texts:
                            response = self.embedding_client.embeddings.create(input=[text], model="text-embedding-3-small")
                            embeddings.append(response.data[0].embedding)
                    except (AttributeError, NotImplementedError):
                        # Try other embedding client styles
                        embeddings = []
                        for text in texts:
                            embeddings.append(self.embedding_client.embed_query(text))
                
                # Store embeddings in Neo4j
                with self.driver.session() as session:
                    for j, entry in enumerate(batch):
                        embedding = embeddings[j]
                        
                        # Update query to store embedding
                        update_query = """
                        MATCH (c:CWE {id: $id})
                        SET c.embedding = $embedding
                        """
                        
                        session.run(
                            update_query,
                            {
                                "id": entry.ID,  # No "CWE-" prefix
                                "embedding": embedding
                            }
                        )
                        
            logger.info(f"Created embeddings for {len(cwe_entries)} CWE entries")
            
        except Exception as e:
            logger.error(f"Error creating embeddings: {e}", exc_info=True)
            # Continue without embeddings
            logger.warning("Continuing without vector search capability")   




    def search(self, query, k=5, include_text=True, keyphrases=None, dense_results=None, sparse_results=None):
        """
        Search using Neo4j for relevant CWEs with enhanced graph-based relationship awareness.
        This implementation focuses on relationship-specific traversal strategies, path-based
        relevance scoring, and meta-path analysis to find CWEs that complement semantic similarity.
        
        Args:
            query: The search query
            k: Number of results to return
            include_text: Whether to include the full text in results
            keyphrases: Dictionary of keyphrases (e.g., {'rootcause': 'command injection'})
            dense_results: Results from dense retriever to use as starting points
            sparse_results: Results from sparse retriever to use as starting points
            
        Returns:
            List of relevant CWEs with combined scores
        """
        # Log the search inputs
        dense_count = len(dense_results) if dense_results else 0
        sparse_count = len(sparse_results) if sparse_results else 0
        
        logger.info(f"Starting enhanced Neo4j search with {dense_count} dense results and {sparse_count} sparse results as inputs")
        start_time = time.time()
        try:
            # Initialize results
            vector_results = []
            graph_results = []
            
            # 1. Get graph traversal results - this leverages the graph structure using new relationship-focused approach
            # Now passes dense and sparse results as starting points
            graph_results = self._graph_traversal_search(
                query, 
                k*2, 
                keyphrases=keyphrases,
                dense_results=dense_results,
                sparse_results=sparse_results
            )
            
            # 2. Get vector similarity results if embedding_client is available
            if self.embedding_client:
                try:
                    # Get vector embedding for query
                    try:
                        query_embedding = self.embedding_client.embed_query(query)
                    except AttributeError:
                        # Try OpenAI style API
                        try:
                            response = self.embedding_client.embeddings.create(input=[query], model="text-embedding-3-small")
                            query_embedding = response.data[0].embedding
                        except Exception as e:
                            logger.error(f"Failed to generate query embedding: {e}")
                            query_embedding = None
                    
                    if query_embedding:
                        with self.driver.session() as session:
                            # Get all CWEs with embeddings
                            get_nodes_query = """
                            MATCH (c:CWE)
                            RETURN c.id as doc_id, c.name as name, c.type as type, 
                                c.description as description, c.extended_description as extended_description,
                                c.alternate_terms as alternate_terms,
                                c.embedding as embedding
                            """                        
                            records = list(session.run(get_nodes_query))
                            
                            # Calculate similarities
                            similarities = []
                            for record in records:
                                if record["embedding"]:
                                    embedding = record["embedding"]
                                    # Calculate cosine similarity
                                    similarity = self._cosine_similarity(query_embedding, embedding)
                                    similarities.append((record, similarity))
                            
                            # Sort by similarity and take top k*2
                            similarities.sort(key=lambda x: x[1], reverse=True)
                            top_results = similarities[:k*2]
                            
                            # Format results
                            for record, similarity in top_results:
                                # Get relationships with specific types
                                relationships = self._get_node_relationships(record["doc_id"])
                                result = {
                                    "doc_id": record["doc_id"],
                                    "text": record["description"] if include_text else None,
                                    "score": similarity,
                                    "metadata": {
                                        "doc_id": record["doc_id"],
                                        "name": record["name"],
                                        "type": record["type"],
                                        "extended_description": record["extended_description"],
                                        "alternate_terms": record["alternate_terms"],
                                        "original_content": record["description"],
                                        "relationships": relationships,
                                        "source": "vector"
                                    },
                                    "similarity": float(similarity)
                                }                            
                                vector_results.append(result)
                except Exception as e:
                    logger.warning(f"Vector similarity search failed: {e}")
            
            # 3. Fall back to keyword search if no embedding client or embedding fails
            if not self.embedding_client or not vector_results:
                with self.driver.session() as session:
                    search_query = """
                    MATCH (c:CWE)
                    WHERE c.name CONTAINS $query OR c.description CONTAINS $query
                    RETURN c.id as doc_id, c.name as name, c.type as type, 
                        c.description as description, c.status as status,
                        1.0 as score
                    ORDER BY score DESC
                    LIMIT $limit
                    """
                    
                    records = session.run(
                        search_query,
                        {"query": query, "limit": k*2}
                    )
                    
                    for record in records:
                        # Get relationships with specific types
                        relationships = self._get_node_relationships(record["doc_id"])

                        result = {
                            "doc_id": record["doc_id"],
                            "text": record["description"] if include_text else None,
                            "score": record["score"],
                            "metadata": {
                                "doc_id": record["doc_id"],
                                "name": record["name"],
                                "type": record["type"],
                                "extended_description": record.get("extended_description"),
                                "alternate_terms": record.get("alternate_terms"),
                                "original_content": record["description"],
                                "relationships": relationships,
                                "source": "keyword"
                            },
                            "similarity": float(record["score"])
                        }
                        
                        vector_results.append(result)
            
            # 4. Combine and rank results from both approaches
            combined_results = self._combine_search_results(vector_results, graph_results)
            
            # Ensure we have results
            if not combined_results:
                logger.warning("No search results found from any method")
                return []
                
            # Log overall search performance
            elapsed_time = time.time() - start_time
            logger.info(f"Combined search returned {len(combined_results)} results (vector: {len(vector_results)}, graph: {len(graph_results)}) in {elapsed_time:.2f}s")
            
            # Log top results
            if combined_results:
                logger.info("Top combined results:")
                for i, result in enumerate(combined_results[:3]):
                    cwe_id = result.get("metadata", {}).get("doc_id", "Unknown")
                    name = result.get("metadata", {}).get("name", "Unknown")
                    similarity = result.get("similarity", 0.0)
                    sources = result.get("metadata", {}).get("sources", [])
                    logger.info(f"  #{i+1}: CWE-{cwe_id} ({name}) - Score: {similarity:.4f} - Sources: {sources}")
            
            return combined_results[:k]
            
        except Exception as e:
            logger.error(f"Error during search: {e}", exc_info=True)
            return []


    def _graph_traversal_search(self, query, k=10, keyphrases=None, dense_results=None, sparse_results=None):
        """
        Enhanced search using graph algorithms and meta-paths to find relevant CWEs
        that complement what vector similarity would find.
        
        This implementation focuses on relationship-specific traversal strategies
        and path-based relevance scoring. It now accepts results from dense and sparse
        retrievers as additional starting points.
        
        Args:
            query: The search query
            k: Number of results to return
            keyphrases: Dictionary of keyphrases (optional)
            dense_results: Results from dense retriever (optional)
            sparse_results: Results from sparse retriever (optional)
            
        Returns:
            List of search results
        """
        # Extract potential CWE IDs from query
        cwe_ids = self._extract_cwe_ids(query)
        
        self.ensure_graph_initialized()
        
        # Process dense_results if provided
        if dense_results:
            for result in dense_results:
                if 'metadata' in result and 'doc_id' in result['metadata']:
                    doc_id = result['metadata']['doc_id']
                    # Add CWE- prefix if not present
                    if not doc_id.startswith("CWE-"):
                        doc_id = f"CWE-{doc_id}"
                    if doc_id not in cwe_ids:
                        cwe_ids.append(doc_id)
        
        # Process sparse_results if provided
        if sparse_results:
            for result in sparse_results:
                if 'cwe_id' in result:
                    doc_id = result['cwe_id']
                    # Add CWE- prefix if not present
                    if not doc_id.startswith("CWE-"):
                        doc_id = f"CWE-{doc_id}"
                    if doc_id not in cwe_ids:
                        cwe_ids.append(doc_id)
        
        # Use provided keyphrases or extract them as fallback
        if keyphrases is None:
            keyphrases = self._extract_keyphrases(query)
            
        logger.info(f"Graph traversal search for '{query}' with extracted CWE IDs: {cwe_ids} and keyphrases: {keyphrases}")
        
        # Initialize results dictionary to track scores by source
        result_scores = defaultdict(dict)
        result_paths = defaultdict(list)
        result_meta = defaultdict(dict)
        
        try:
            # STRATEGY 1: Direct relationship traversal from mentioned CWEs
            if cwe_ids:
                self._traverse_from_explicit_cwes(cwe_ids, result_scores, result_paths, result_meta)
            
            # STRATEGY 2: Meta-path analysis
            self._analyze_meta_paths(query, keyphrases, result_scores, result_paths, result_meta)
            
            # STRATEGY 3: Chain analysis based on keyphrases
            self._analyze_vulnerability_chains(keyphrases, result_scores, result_paths, result_meta)
            
            # STRATEGY 4: Keyword search with relationship boost
            self._keyword_with_relationship_boost(query, result_scores, result_paths, result_meta)
            
            # Calculate final scores and create result objects
            results = self._create_final_graph_results(result_scores, result_paths, result_meta, k)
            
            return results
            
        except Exception as e:
            logger.error(f"Error in graph traversal search: {e}", exc_info=True)
            return []
        
    def _combine_search_results(self, vector_results, graph_results):
        """
        Combine and deduplicate results from vector and graph search approaches.
        
        Args:
            vector_results: Results from vector-based search
            graph_results: Results from graph-based search
            
        Returns:
            Combined and ranked results list
        """
        # Create mapping of CWE ID to result
        combined_map = {}
        
        # Process vector results first
        for result in vector_results:
            doc_id = result["metadata"]["doc_id"]
            combined_map[doc_id] = result.copy()
            combined_map[doc_id]["metadata"]["sources"] = ["vector"]
            
        # Process graph results and combine with vector results where needed
        for result in graph_results:
            doc_id = result["metadata"]["doc_id"]
            
            if doc_id in combined_map:
                # This CWE was found by both methods - combine scores
                existing_result = combined_map[doc_id]
                
                # Average the scores with emphasis on graph score
                vector_score = existing_result["similarity"]
                graph_score = result["similarity"]
                
                # Give more weight to graph score (60/40 split)
                combined_score = (graph_score * 0.6) + (vector_score * 0.4)
                
                # Update the existing result
                existing_result["similarity"] = combined_score
                existing_result["metadata"]["sources"].append("graph")
                existing_result["metadata"]["vector_score"] = vector_score
                existing_result["metadata"]["graph_score"] = graph_score
                
                # Add graph-specific metadata
                for key, value in result["metadata"].items():
                    if key not in existing_result["metadata"] and key != "doc_id":
                        existing_result["metadata"][key] = value
                        
                # Specially merge relationship information
                if "graph_path_info" in result["metadata"] and "graph_path_info" not in existing_result["metadata"]:
                    existing_result["metadata"]["graph_path_info"] = result["metadata"]["graph_path_info"]
            else:
                # This CWE was found only by graph search
                result["metadata"]["sources"] = ["graph"]
                combined_map[doc_id] = result
        
        # Convert back to list and sort by combined score
        combined_results = list(combined_map.values())
        combined_results.sort(key=lambda x: x["similarity"], reverse=True)
        
        return combined_results
            
    def _cosine_similarity(self, a, b):
        """Calculate cosine similarity between two vectors."""
        import numpy as np
        return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))
    

    
    def _traverse_from_explicit_cwes(self, cwe_ids, result_scores, result_paths, result_meta):
        """
        Traverse the graph from explicitly mentioned CWEs with a focus on relationship chains.
        
        Args:
            cwe_ids: List of CWE IDs explicitly mentioned in the query
            result_scores: Dictionary to update with scores
            result_paths: Dictionary to update with path information
            result_meta: Dictionary to update with metadata
        """
        if not self.nx_graph:
            logger.warning("NetworkX graph not initialized; skipping CWE traversal")
            return
            
        logger.debug(f"Traversing from explicit CWEs: {cwe_ids}")
        normalized_cwe_ids = [cid.replace("CWE-", "") for cid in cwe_ids]
        
        # Define relationship types to prioritize for this strategy
        # Focus on relationship chains rather than hierarchical relationships
        priority_rels = {
            "CANPRECEDE": 1.0,    # High weight for vulnerability progression
            "CANFOLLOW": 1.0,     # High weight for vulnerability progression
            "REQUIRES": 0.9,      # High weight for dependency relationships
            "REQUIREDBY": 0.9,    # High weight for dependency relationships
            "PEEROF": 0.7,        # Medium weight for peer relationships
            "CANALSOBE": 0.7,     # Medium weight for peer relationships
            "CHILDOF": 0.3,       # Lower weight for hierarchical relationships
            "PARENTOF": 0.3       # Lower weight for hierarchical relationships
        }
        
        self.ensure_graph_initialized()
        
        max_depth = 3  # Maximum traversal depth
        
        for cwe_id in normalized_cwe_ids:
            if cwe_id not in self.nx_graph:
                logger.warning(f"CWE-{cwe_id} not found in graph")
                continue
                
            # Mark this CWE as an explicit starting point
            result_scores[cwe_id]["explicit_mention"] = 1.0
            result_meta[cwe_id]["is_explicit"] = True
                
            # Perform a multi-relationship traversal with prioritized edge types
            visited = {cwe_id: 0}  # Maps node to its distance from start
            queue = [(cwe_id, 0, [])]  # (node, depth, path_so_far)
            
            while queue:
                current, depth, path = queue.pop(0)
                
                if depth >= max_depth:
                    continue
                
                # For all outgoing edges
                for _, target, edge_data in self.nx_graph.out_edges(current, data=True):
                    rel_type = edge_data.get("rel_type")
                    if not rel_type:
                        continue
                        
                    # Skip if not a priority relationship or already visited at same/lower depth
                    if rel_type not in priority_rels or (target in visited and visited[target] <= depth + 1):
                        continue
                        
                    # Calculate score based on relationship type and depth
                    rel_weight = priority_rels[rel_type]
                    depth_penalty = max(0.5, 1.0 - (depth * 0.2))  # Penalize by depth
                    path_score = rel_weight * depth_penalty
                    
                    # Store or update score
                    current_score = result_scores[target].get("relationship_chain", 0)
                    if path_score > current_score:
                        result_scores[target]["relationship_chain"] = path_score
                        
                        # Store path information
                        new_path = path + [(current, target, rel_type)]
                        result_paths[target].append({
                            "path": new_path,
                            "score": path_score,
                            "type": "relationship_chain",
                            "source": cwe_id
                        })
                        
                        # Mark visited and add to queue
                        visited[target] = depth + 1
                        queue.append((target, depth + 1, new_path))
                
                # For all incoming edges
                for source, _, edge_data in self.nx_graph.in_edges(current, data=True):
                    rel_type = edge_data.get("rel_type")
                    if not rel_type:
                        continue
                        
                    # Skip if not a priority relationship or already visited at same/lower depth
                    if rel_type not in priority_rels or (source in visited and visited[source] <= depth + 1):
                        continue
                        
                    # Calculate score based on relationship type and depth
                    rel_weight = priority_rels[rel_type]
                    depth_penalty = max(0.5, 1.0 - (depth * 0.2))  # Penalize by depth
                    path_score = rel_weight * depth_penalty
                    
                    # Store or update score
                    current_score = result_scores[source].get("relationship_chain", 0)
                    if path_score > current_score:
                        result_scores[source]["relationship_chain"] = path_score
                        
                        # Store path information
                        new_path = path + [(source, current, rel_type)]
                        result_paths[source].append({
                            "path": new_path,
                            "score": path_score,
                            "type": "relationship_chain",
                            "source": cwe_id
                        })
                        
                        # Mark visited and add to queue
                        visited[source] = depth + 1
                        queue.append((source, depth + 1, new_path))
            
            # For each visited node, record node type for abstraction level adjustment
            for node in visited:
                if node in self.nx_graph:
                    node_type = self.nx_graph.nodes[node].get("type", "").lower()
                    result_meta[node]["type"] = node_type
                    result_meta[node]["name"] = self.nx_graph.nodes[node].get("name", "Unknown")
            
            logger.debug(f"Traversal from CWE-{cwe_id} found {len(visited) - 1} related CWEs")
            
    def _analyze_meta_paths(self, query, keyphrases, result_scores, result_paths, result_meta):
        """
        Apply meta-path analysis to find CWEs connected through specific patterns of relationships.
        
        Args:
            query: The search query
            keyphrases: Dictionary of keyphrases from the query
            result_scores: Dictionary to update with scores
            result_paths: Dictionary to update with path information
            result_meta: Dictionary to update with metadata
        """
        if not self.nx_graph or not self.meta_path_cache:
            logger.warning("Meta-path cache not initialized; skipping meta-path analysis")
            return
        
        # Create a list of potential starting CWEs from textual match
        starting_cwes = self._get_potential_starting_cwes(query, keyphrases)
        
        if not starting_cwes:
            logger.debug("No viable starting CWEs found for meta-path analysis")
            return
            
        logger.debug(f"Analyzing meta-paths from {len(starting_cwes)} starting CWEs")
        
        # 1. Analyze abstraction paths (Variant -> Base -> Class)
        self._analyze_abstraction_paths(starting_cwes, result_scores, result_paths, result_meta)
        
        # 2. Analyze vulnerability chains (CanPrecede, CanFollow)
        self._analyze_vulnerability_sequence_paths(starting_cwes, result_scores, result_paths, result_meta)
        
        # 3. Analyze peer group connections
        self._analyze_peer_groups(starting_cwes, result_scores, result_paths, result_meta)
        
    def _get_potential_starting_cwes(self, query, keyphrases):
        """Get potential starting CWEs based on text and keyword matching."""
        starting_cwes = set()
        
        # Method 1: Start with any mentioned CWE IDs
        cwe_ids = self._extract_cwe_ids(query)
        for cwe_id in cwe_ids:
            normalized_id = cwe_id.replace("CWE-", "")
            if normalized_id in self.nx_graph:
                starting_cwes.add(normalized_id)
        
        # Method 2: Use CWEs related to keyphrases
        if keyphrases:
            with self.driver.session() as session:
                # Use the values from the keyphrases dictionary
                for key, term in keyphrases.items():
                    if not term:
                        continue
                        
                    try:
                        # Use fulltext search if available
                        search_query = """
                        CALL db.index.fulltext.queryNodes("cwe_text", $term) 
                        YIELD node, score
                        WHERE score > 0.5
                        RETURN node.id as id, score
                        ORDER BY score DESC
                        LIMIT 5
                        """
                        
                        results = session.run(search_query, {"term": term})
                        for record in results:
                            starting_cwes.add(record["id"])
                    except Exception:
                        # Fall back to simpler pattern matching
                        search_query = """
                        MATCH (c:CWE)
                        WHERE toLower(c.name) CONTAINS toLower($term) 
                           OR toLower(c.description) CONTAINS toLower($term)
                        RETURN c.id as id
                        LIMIT 5
                        """
                        
                        results = session.run(search_query, {"term": term})
                        for record in results:
                            starting_cwes.add(record["id"])
        
        # Method 3: If still empty, get CWEs generally related to the query
        if not starting_cwes:
            try:
                with self.driver.session() as session:
                    search_query = """
                    MATCH (c:CWE)
                    WHERE toLower(c.name) CONTAINS toLower($term) 
                       OR toLower(c.description) CONTAINS toLower($term)
                    RETURN c.id as id
                    LIMIT 10
                    """
                    
                    results = session.run(search_query, {"term": query})
                    for record in results:
                        starting_cwes.add(record["id"])
            except Exception as e:
                logger.warning(f"Error finding starting CWEs: {e}")
                
        return list(starting_cwes)
    
    def _analyze_abstraction_paths(self, starting_cwes, result_scores, result_paths, result_meta):
        """
        Analyze paths connecting CWEs across abstraction levels (Variant -> Base -> Class).
        
        Args:
            starting_cwes: List of CWE IDs to start from
            result_scores: Dictionary to update with scores
            result_paths: Dictionary to update with path information
            result_meta: Dictionary to update with metadata
        """
        # Analyze in both directions: 
        # 1. From starting CWEs to more abstract ones
        # 2. From starting CWEs to more specific ones
        
        for cwe_id in starting_cwes:
            cwe_type = self.nx_graph.nodes[cwe_id].get("type", "").lower() if cwe_id in self.nx_graph else ""
            
            # 1. Find more abstract CWEs (Base -> Class -> Pillar)
            if cwe_type in ["variant", "base"]:
                # Navigate up the abstraction hierarchy
                ancestry_path = []
                current = cwe_id
                visited = set([current])
                
                # Record the starting CWE
                result_meta[cwe_id]["abstraction_level"] = cwe_type
                
                # Traverse up the hierarchy via ChildOf relationships
                for _ in range(3):  # Maximum 3 levels up
                    parents = []
                    for src, tgt, data in self.nx_graph.out_edges(current, data=True):
                        if data.get("rel_type") == "CHILDOF" and tgt not in visited:
                            parents.append((tgt, data))
                            visited.add(tgt)
                    
                    if not parents:
                        break
                    
                    # Take first parent (if multiple exist)
                    next_parent, edge_data = parents[0]
                    parent_type = self.nx_graph.nodes[next_parent].get("type", "").lower()
                    
                    # Add to ancestry path
                    ancestry_path.append((current, next_parent, "CHILDOF"))
                    
                    # Update meta information
                    result_meta[next_parent]["abstraction_level"] = parent_type
                    result_meta[next_parent]["name"] = self.nx_graph.nodes[next_parent].get("name", "Unknown")
                    
                    # Score based on abstraction level and proximity
                    # Higher score for immediate parents
                    base_score = 0.8
                    depth_penalty = 0.7 ** len(ancestry_path)  # 0.7, 0.49, 0.343 for each level
                    path_score = base_score * depth_penalty
                    
                    # Store or update score
                    current_score = result_scores[next_parent].get("abstraction_path", 0)
                    if path_score > current_score:
                        result_scores[next_parent]["abstraction_path"] = path_score
                        
                        # Store path information
                        result_paths[next_parent].append({
                            "path": ancestry_path.copy(),
                            "score": path_score,
                            "type": "abstraction_path_up",
                            "source": cwe_id
                        })
                    
                    current = next_parent
            
            # 2. Find more specific CWEs (Class -> Base -> Variant)
            if cwe_type in ["class", "pillar", "base"]:
                # Navigate down the abstraction hierarchy
                visited = set()
                for depth in range(3):  # Maximum 3 levels down
                    children_to_process = [(cwe_id, [])] if depth == 0 else []
                    
                    # For depth > 0, gather all children of previous level
                    if depth > 0:
                        for parent, path in processed_at_prev_depth:
                            for parent_src, parent_tgt, parent_data in self.nx_graph.in_edges(parent, data=True):
                                if parent_data.get("rel_type") == "CHILDOF" and parent_tgt == parent:
                                    if parent_src not in visited:
                                        new_path = path + [(parent, parent_src, "PARENTOF")]
                                        children_to_process.append((parent_src, new_path))
                                        visited.add(parent_src)
                    
                    processed_at_prev_depth = []
                    
                    # Process children at current depth
                    for child, descent_path in children_to_process:
                        # Get child type
                        child_type = self.nx_graph.nodes[child].get("type", "").lower() if child in self.nx_graph else ""
                        
                        # Update meta information
                        result_meta[child]["abstraction_level"] = child_type
                        result_meta[child]["name"] = self.nx_graph.nodes[child].get("name", "Unknown") if child in self.nx_graph else "Unknown"
                        
                        # Score based on abstraction level and proximity
                        base_score = 0.9 if child_type == "base" else (0.95 if child_type == "variant" else 0.7)
                        depth_penalty = 0.8 ** len(descent_path) if descent_path else 1.0  # Penalty for deeper levels
                        path_score = base_score * depth_penalty
                        
                        # Store or update score
                        current_score = result_scores[child].get("abstraction_path", 0)
                        if path_score > current_score:
                            result_scores[child]["abstraction_path"] = path_score
                            
                            # Store path information
                            if descent_path:  # Skip for the starting node itself
                                result_paths[child].append({
                                    "path": descent_path,
                                    "score": path_score,
                                    "type": "abstraction_path_down",
                                    "source": cwe_id
                                })
                        
                        # Add to processed nodes for next depth
                        processed_at_prev_depth.append((child, descent_path))
    
    def _analyze_vulnerability_sequence_paths(self, starting_cwes, result_scores, result_paths, result_meta):
        """
        Analyze vulnerability sequence paths (CanPrecede, CanFollow) to build chains.
        
        Args:
            starting_cwes: List of CWE IDs to start from
            result_scores: Dictionary to update with scores
            result_paths: Dictionary to update with path information
            result_meta: Dictionary to update with metadata
        """
        sequence_relationships = ["CANPRECEDE", "CANFOLLOW", "REQUIRES", "REQUIREDBY"]
        
        for cwe_id in starting_cwes:
            if cwe_id not in self.nx_graph:
                continue
                
            # 1. Find subsequent CWEs (what can follow this CWE)
            visited_forward = set([cwe_id])
            forward_queue = [(cwe_id, [], 0)]  # (node, path, depth)
            
            while forward_queue:
                current, path, depth = forward_queue.pop(0)
                
                if depth >= 3:  # Maximum depth of 3
                    continue
                    
                for src, tgt, data in self.nx_graph.out_edges(current, data=True):
                    rel_type = data.get("rel_type")
                    
                    if rel_type in sequence_relationships and tgt not in visited_forward:
                        # This is a subsequent CWE in the chain
                        new_path = path + [(current, tgt, rel_type)]
                        
                        # Score based on relationship type and path length
                        rel_weight = 1.0 if rel_type in ["CANPRECEDE", "REQUIRES"] else 0.9
                        depth_penalty = 0.8 ** depth  # Penalize by depth
                        path_score = rel_weight * depth_penalty
                        
                        # Store or update score
                        current_score = result_scores[tgt].get("sequence_path", 0)
                        if path_score > current_score:
                            result_scores[tgt]["sequence_path"] = path_score
                            
                            # Store path information
                            result_paths[tgt].append({
                                "path": new_path,
                                "score": path_score,
                                "type": "vulnerability_sequence_forward",
                                "source": cwe_id
                            })
                        
                        # Add metadata
                        result_meta[tgt]["name"] = self.nx_graph.nodes[tgt].get("name", "Unknown")
                        result_meta[tgt]["type"] = self.nx_graph.nodes[tgt].get("type", "").lower()
                        result_meta[tgt]["position"] = "after"
                        
                        # Mark visited and add to queue
                        visited_forward.add(tgt)
                        forward_queue.append((tgt, new_path, depth + 1))
            
            # 2. Find prerequisite CWEs (what must precede this CWE)
            visited_backward = set([cwe_id])
            backward_queue = [(cwe_id, [], 0)]  # (node, path, depth)
            
            while backward_queue:
                current, path, depth = backward_queue.pop(0)
                
                if depth >= 3:  # Maximum depth of 3
                    continue
                    
                for src, tgt, data in self.nx_graph.in_edges(current, data=True):
                    rel_type = data.get("rel_type")
                    
                    # Look for incoming CanPrecede or outgoing CanFollow
                    is_prerequisite = (rel_type == "CANPRECEDE") or (rel_type == "REQUIRES")
                    
                    if is_prerequisite and src not in visited_backward:
                        # This is a prerequisite CWE in the chain
                        new_path = path + [(src, current, rel_type)]
                        
                        # Score based on relationship type and path length
                        rel_weight = 1.0
                        depth_penalty = 0.8 ** depth  # Penalize by depth
                        path_score = rel_weight * depth_penalty
                        
                        # Store or update score
                        current_score = result_scores[src].get("sequence_path", 0)
                        if path_score > current_score:
                            result_scores[src]["sequence_path"] = path_score
                            
                            # Store path information
                            result_paths[src].append({
                                "path": new_path,
                                "score": path_score,
                                "type": "vulnerability_sequence_backward",
                                "source": cwe_id
                            })
                        
                        # Add metadata
                        result_meta[src]["name"] = self.nx_graph.nodes[src].get("name", "Unknown")
                        result_meta[src]["type"] = self.nx_graph.nodes[src].get("type", "").lower()
                        result_meta[src]["position"] = "before"
                        
                        # Mark visited and add to queue
                        visited_backward.add(src)
                        backward_queue.append((src, new_path, depth + 1))
    
    def _analyze_peer_groups(self, starting_cwes, result_scores, result_paths, result_meta):
        """
        Analyze peer groups (PeerOf, CanAlsoBe) to find alternative CWEs.
        
        Args:
            starting_cwes: List of CWE IDs to start from
            result_scores: Dictionary to update with scores
            result_paths: Dictionary to update with path information
            result_meta: Dictionary to update with metadata
        """
        peer_relationships = ["PEEROF", "CANALSOBE"]
        
        for cwe_id in starting_cwes:
            if cwe_id not in self.nx_graph:
                continue
                
            # Find peer CWEs through direct or 2-hop relationships
            visited = set([cwe_id])
            queue = [(cwe_id, [], 0)]  # (node, path, depth)
            
            while queue:
                current, path, depth = queue.pop(0)
                
                if depth >= 2:  # Maximum depth of 2 for peer relationships
                    continue
                
                # Check both outgoing and incoming peer relationships
                for edge_direction in ["out", "in"]:
                    if edge_direction == "out":
                        edges = self.nx_graph.out_edges(current, data=True)
                    else:
                        edges = self.nx_graph.in_edges(current, data=True)
                    
                    for u, v, data in edges:
                        rel_type = data.get("rel_type")
                        
                        # Determine the peer node based on direction
                        peer = v if edge_direction == "out" else u
                        
                        if rel_type in peer_relationships and peer not in visited:
                            # This is a peer CWE
                            if edge_direction == "out":
                                new_path = path + [(current, peer, rel_type)]
                            else:
                                new_path = path + [(peer, current, rel_type)]
                            
                            # Score based on relationship type and path length
                            rel_weight = 0.9  # Slightly lower weight for peer relationships
                            depth_penalty = 0.7 ** depth  # Steeper penalty for peers
                            path_score = rel_weight * depth_penalty
                            
                            # Store or update score
                            current_score = result_scores[peer].get("peer_group", 0)
                            if path_score > current_score:
                                result_scores[peer]["peer_group"] = path_score
                                
                                # Store path information
                                result_paths[peer].append({
                                    "path": new_path,
                                    "score": path_score,
                                    "type": "peer_relationship",
                                    "source": cwe_id
                                })
                            
                            # Add metadata
                            result_meta[peer]["name"] = self.nx_graph.nodes[peer].get("name", "Unknown")
                            result_meta[peer]["type"] = self.nx_graph.nodes[peer].get("type", "").lower()
                            
                            # Mark visited and add to queue
                            visited.add(peer)
                            queue.append((peer, new_path, depth + 1))
            
            logger.debug(f"Found {len(visited) - 1} peers for CWE-{cwe_id}")
    
    def _analyze_vulnerability_chains(self, keyphrases, result_scores, result_paths, result_meta):
        """
        Analyze vulnerability chains based on keyphrases for better attack pattern recognition.
        This implementation avoids hardcoded vulnerability types and focuses on direct keyphrase matching.
        
        Args:
            keyphrases: Extracted keyphrases from the query
            result_scores: Dictionary to update with scores
            result_paths: Dictionary to update with path information
            result_meta: Dictionary to update with metadata
        """
        if not keyphrases or not self.nx_graph:
            return
            
        logger.debug(f"Analyzing vulnerability chains using keyphrases: {keyphrases}")
        
        # Find potential starting points by directly matching keyphrases to CWE descriptions
        relevant_cwes = []
        
        with self.driver.session() as session:
            for keyphrase in keyphrases.values():  # Use values from keyphrases dict
                if not keyphrase:
                    continue
                    
                # Find CWEs that match this keyphrase
                try:
                    # Use fulltext search if available
                    search_query = """
                    CALL db.index.fulltext.queryNodes("cwe_text", $term) 
                    YIELD node, score
                    WHERE score > 0.4
                    RETURN node.id as id, node.name as name, node.type as type, score
                    ORDER BY score DESC
                    LIMIT 5
                    """
                    
                    results = session.run(search_query, {"term": keyphrase})
                    for record in results:
                        relevant_cwes.append((record["id"], record["name"], record["type"], record["score"]))
                except Exception:
                    # Fall back to basic text matching
                    search_query = """
                    MATCH (c:CWE)
                    WHERE toLower(c.name) CONTAINS toLower($term) 
                       OR toLower(c.description) CONTAINS toLower($term)
                    RETURN c.id as id, c.name as name, c.type as type, 1.0 as score
                    LIMIT 5
                    """
                    
                    results = session.run(search_query, {"term": keyphrase})
                    for record in results:
                        relevant_cwes.append((record["id"], record["name"], record["type"], record["score"]))
                        
        if not relevant_cwes:
            logger.debug("No relevant CWEs found for keyphrases")
            return
            
        # For each relevant CWE, analyze forward and backward vulnerability chains
        for cwe_id, name, cwe_type, match_score in relevant_cwes:
            # Score this CWE as a potential chain starting point
            result_scores[cwe_id]["chain_starting_point"] = match_score * 0.8
            result_meta[cwe_id]["chain_role"] = "starting_point"
            result_meta[cwe_id]["keyphrase_match"] = True
            
            # Find subsequent vulnerabilities in the chain
            self._find_chain_progression(cwe_id, result_scores, result_paths, result_meta, "keyphrase_chain")
    
    def _find_chain_progression(self, cwe_id, result_scores, result_paths, result_meta, vulnerability_type):
        """
        Find progression of the vulnerability chain from a starting point.
        
        Args:
            cwe_id: Starting CWE ID
            result_scores: Dictionary to update with scores
            result_paths: Dictionary to update with path information
            result_meta: Dictionary to update with metadata
            vulnerability_type: Type of vulnerability chain
        """
        # Define relationships to follow for chain progression
        chain_relationships = ["CANPRECEDE", "REQUIRES"]
        
        # For forward chain (what this vulnerability enables)
        visited_forward = set([cwe_id])
        forward_queue = [(cwe_id, [], 0)]  # (node, path, depth)
        
        while forward_queue:
            current, path, depth = forward_queue.pop(0)
            
            if depth >= 3:  # Maximum depth of 3
                continue
                
            for src, tgt, data in self.nx_graph.out_edges(current, data=True):
                rel_type = data.get("rel_type")
                
                if rel_type in chain_relationships and tgt not in visited_forward:
                    # This is part of the vulnerability chain
                    new_path = path + [(current, tgt, rel_type)]
                    
                    # Score based on position in chain and relationship
                    position_factor = 0.9 - (depth * 0.1)  # 0.9, 0.8, 0.7 for depths 0,1,2
                    path_score = position_factor
                    
                    # Store or update score
                    current_score = result_scores[tgt].get("vulnerability_chain", 0)
                    if path_score > current_score:
                        result_scores[tgt]["vulnerability_chain"] = path_score
                        
                        # Store path information
                        result_paths[tgt].append({
                            "path": new_path,
                            "score": path_score,
                            "type": "vulnerability_chain_forward",
                            "source": cwe_id,
                            "chain_type": vulnerability_type
                        })
                    
                    # Add metadata
                    result_meta[tgt]["name"] = self.nx_graph.nodes[tgt].get("name", "Unknown")
                    result_meta[tgt]["type"] = self.nx_graph.nodes[tgt].get("type", "").lower()
                    result_meta[tgt]["chain_role"] = f"consequence_depth_{depth+1}"
                    result_meta[tgt]["vulnerability_type"] = vulnerability_type
                    
                    # Mark visited and add to queue
                    visited_forward.add(tgt)
                    forward_queue.append((tgt, new_path, depth + 1))
    
    def _keyword_with_relationship_boost(self, query, result_scores, result_paths, result_meta):
        """
        Perform keyword search with additional relationship-based boosting.
        This enhances traditional keyword retrieval with graph relationship context.
        
        Args:
            query: The search query
            result_scores: Dictionary to update with scores
            result_paths: Dictionary to update with path information
            result_meta: Dictionary to update with metadata
        """
        try:
            # First, find CWEs using keyword matching
            with self.driver.session() as session:
                # Try using the fulltext index if available
                try:
                    search_query = """
                    CALL db.index.fulltext.queryNodes("cwe_text", $query) YIELD node, score
                    WHERE score > 0.3
                    RETURN node.id as id, node.name as name, node.type as type, score
                    ORDER BY score DESC
                    LIMIT 20
                    """
                    
                    results = session.run(search_query, {"query": query})
                    keyword_matches = [(record["id"], record["name"], record["type"], record["score"]) 
                                      for record in results]
                except Exception:
                    # Fall back to basic text match if fulltext index isn't available
                    search_query = """
                    MATCH (c:CWE)
                    WHERE toLower(c.name) CONTAINS toLower($term) 
                       OR toLower(c.description) CONTAINS toLower($term)
                    RETURN c.id as id, c.name as name, c.type as type, 1.0 as score
                    LIMIT 20
                    """
                    
                    results = session.run(search_query, {"term": query})
                    keyword_matches = [(record["id"], record["name"], record["type"], record["score"]) 
                                      for record in results]
            
            if not keyword_matches:
                logger.debug("No keyword matches found")
                return
                
            logger.debug(f"Found {len(keyword_matches)} keyword matches")
            
            # Process keyword matches
            for cwe_id, name, cwe_type, score in keyword_matches:
                # Store basic score from keyword match
                result_scores[cwe_id]["keyword_match"] = min(score, 1.0)  # Normalize to 0-1
                
                # Add metadata
                result_meta[cwe_id]["name"] = name
                result_meta[cwe_id]["type"] = cwe_type.lower() if cwe_type else ""
                
                # Now enhance these results with relationship context
                self._enhance_with_relationships(cwe_id, result_scores, result_paths, result_meta)
                
        except Exception as e:
            logger.error(f"Error in keyword search with relationship boost: {e}")
    
    def _enhance_with_relationships(self, cwe_id, result_scores, result_paths, result_meta):
        """
        Enhance a keyword match with relationship context.
        
        Args:
            cwe_id: The CWE ID to enhance
            result_scores: Dictionary to update with scores
            result_paths: Dictionary to update with path information
            result_meta: Dictionary to update with metadata
        """
        if not self.nx_graph or cwe_id not in self.nx_graph:
            return
            
        # Get relationship counts by type
        relationship_counts = defaultdict(int)
        relationships_by_type = defaultdict(list)
        
        # Count outgoing relationships
        for _, _, data in self.nx_graph.out_edges(cwe_id, data=True):
            rel_type = data.get("rel_type", "UNKNOWN")
            relationship_counts[rel_type] += 1
            
        # Count incoming relationships
        for _, _, data in self.nx_graph.in_edges(cwe_id, data=True):
            rel_type = data.get("rel_type", "UNKNOWN")
            relationship_counts[rel_type] += 1
            
        # Calculate relationship richness score
        # CWEs with diverse relationship types are more significant in the graph
        rel_type_count = len(relationship_counts)
        total_rels = sum(relationship_counts.values())
        
        # Calculate relationship richness score
        if total_rels > 0:
            # Complex CWEs will have more relationship types and more total relationships
            richness_score = min(0.3, 0.1 * rel_type_count + 0.005 * total_rels)
            result_scores[cwe_id]["relationship_richness"] = richness_score
            
            # Store relationship context in metadata
            result_meta[cwe_id]["relationship_counts"] = dict(relationship_counts)
            result_meta[cwe_id]["total_relationships"] = total_rels
            result_meta[cwe_id]["relationship_types"] = rel_type_count
            
    def _create_final_graph_results(self, result_scores, result_paths, result_meta, k):
        """
        Create final graph search results from all search strategies.
        
        Args:
            result_scores: Dictionary with scores from different strategies
            result_paths: Dictionary with path information
            result_meta: Dictionary with metadata
            k: Number of results to return
            
        Returns:
            List of result dictionaries
        """
        # Calculate final scores
        final_scores = {}
        for cwe_id in result_scores:
            # Base score is 0
            final_scores[cwe_id] = 0.0
            
            # Add contributions from different search strategies
            # Weight the contributions based on strategy importance
            strategy_weights = {
                # Strategies focused on explicit mentions and direct matches
                "explicit_mention": 1.0,
                "keyword_match": 0.8,
                
                # Strategies focused on relationship structure
                "relationship_chain": 0.9,
                "chain_starting_point": 0.85,
                "vulnerability_chain": 0.9,
                
                # Strategies focused on abstraction levels
                "abstraction_path": 0.7,
                
                # Strategies focused on alternatives and sequence
                "sequence_path": 0.8,
                "peer_group": 0.6,
                
                # Supplementary strategies
                "relationship_richness": 0.5
            }
            
            # Sum weighted scores from all strategies
            for strategy, weight in strategy_weights.items():
                if strategy in result_scores[cwe_id]:
                    contribution = result_scores[cwe_id][strategy] * weight
                    final_scores[cwe_id] += contribution
        
        # Create result objects with path info and metadata
        results = []
        for cwe_id, score in final_scores.items():
            # Skip if score is too low
            if score < 0.05:  # Minimum threshold to filter noise
                continue
                
            # Normalize score to 0-1 range - not necessary here as weights ensure this
            
            # Get CWE type for abstraction level adjustment
            cwe_type = result_meta[cwe_id].get("type", "unknown").lower()
            
            # Apply abstraction level adjustment directly in final results
            abstraction_factor = 1.0
            if cwe_type == "base":
                abstraction_factor = 1.3  # Favor Base CWEs
            elif cwe_type == "variant":
                abstraction_factor = 1.2  # Also favor Variant CWEs
            elif cwe_type == "class":
                abstraction_factor = 0.8  # Discourage Class CWEs
            elif cwe_type == "pillar":
                abstraction_factor = 0.6  # Strongly discourage Pillar CWEs
                
            # Apply abstraction adjustment
            adjusted_score = score * abstraction_factor
            
            # Compile path information
            path_info = result_paths.get(cwe_id, [])
            
            # Find best paths for visualization (one per type)
            best_paths_by_type = {}
            for path_data in path_info:
                path_type = path_data["type"]
                if path_type not in best_paths_by_type or path_data["score"] > best_paths_by_type[path_type]["score"]:
                    best_paths_by_type[path_type] = path_data
                    
            # Add CWE attributes
            name = result_meta[cwe_id].get("name", "Unknown")
            
            # Create result object
            result = {
                "doc_id": cwe_id,
                "text": f"CWE-{cwe_id}: {name}",  # Basic text representation
                "score": adjusted_score,
                "metadata": {
                    "doc_id": cwe_id,
                    "name": name,
                    "type": cwe_type,
                    "original_content": f"CWE-{cwe_id}: {name}",
                    "relationships": self._get_node_relationships(cwe_id),
                    "score_components": result_scores[cwe_id],
                    "abstraction_factor": abstraction_factor,
                    "graph_path_info": {
                        "path_types": list(best_paths_by_type.keys()),
                        "best_paths": best_paths_by_type
                    }
                },
                "similarity": float(adjusted_score)  # Use adjusted score as similarity
            }
            
            # Add any additional metadata we have
            for key, value in result_meta.get(cwe_id, {}).items():
                if key not in result["metadata"]:
                    result["metadata"][key] = value
            
            results.append(result)
        
        # Sort by score and return top k
        results.sort(key=lambda x: x["similarity"], reverse=True)
        return results[:k]
    
    def _extract_cwe_ids(self, query: str) -> List[str]:
        """Extract CWE-IDs mentioned in the query text."""
        import re
        cwe_pattern = re.compile(r"CWE-?(\d+)", re.IGNORECASE)
        matches = cwe_pattern.findall(query)
        return [f"CWE-{match}" for match in matches]
    
    def _extract_keyphrases(self, query: str) -> Dict[str, str]:
        """
        Extract keyphrases from the query text if presented in structured format.
        Returns a dictionary of keyphrase types to their values.
        Note: This is just a backup in case keyphrases aren't explicitly passed to search methods.
        """
        keyphrases = {}
        
        # Look for explicit keyphrases in structured format
        keyphrase_patterns = [
            (r"rootcause:\s*([^,\n]+)", "rootcause"),
            (r"weakness:\s*([^,\n]+)", "weakness")
        ]
        
        for pattern, key in keyphrase_patterns:
            matches = re.findall(pattern, query, re.IGNORECASE)
            if matches and matches[0].strip():
                keyphrases[key] = matches[0].strip()
        
        return keyphrases