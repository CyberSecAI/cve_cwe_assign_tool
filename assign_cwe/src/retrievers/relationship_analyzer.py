# src/retrievers/relationship_analyzer.py

from typing import List, Dict, Any, Optional, Set, Tuple
import logging
import networkx as nx
import matplotlib.pyplot as plt
import io
import base64
from pathlib import Path
import os

from utils.logger import get_logger
from models.cwe import CWEEntry

from utils.cwe_relationship_utils import build_bidirectional_relationships

logger = get_logger(__name__)

class CWERelationshipAnalyzer:
    """Analyzer for CWE relationships to enhance vulnerability mapping."""
    
    def __init__(
        self,
        property_graph,
        cwe_entries: Optional[List[CWEEntry]] = None,
        output_dir: str = "./output/relationship_analysis",
        abstraction_hierarchy: List[str] = None
    ):
        """
        Initialize the relationship analyzer.
        
        Args:
            property_graph: Neo4j property graph instance
            cwe_entries: List of CWE entries (optional)
            output_dir: Directory for saving visualizations
            abstraction_hierarchy: Hierarchy of CWE abstraction levels
        """
        self.property_graph = property_graph
        
        # Apply bidirectional relationship enhancement if cwe_entries is provided
        if cwe_entries:
            logger.info("Enhancing CWE entries with bidirectional relationships")
            self.cwe_entries = build_bidirectional_relationships(cwe_entries)
        else:
            self.cwe_entries = []
            
        self.cwe_map = {f"CWE-{entry.ID}": entry for entry in self.cwe_entries} if self.cwe_entries else {}
        self.output_dir = output_dir
        self.abstraction_hierarchy = abstraction_hierarchy or ["Pillar", "Class", "Base", "Variant"]
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialize in-memory graph
        self.graph = self._initialize_graph()
        
    def _initialize_graph(self) -> nx.DiGraph:
        """Initialize a NetworkX graph from the property graph."""
        G = nx.DiGraph()
        
        try:
            # Get all nodes from property graph
            with self.property_graph.driver.session() as session:
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
                RETURN source.id as source_id, target.id as target_id, type(r) as rel_type
                """
                relationships = session.run(rels_query)
                
                # Add edges to graph
                for rel in relationships:
                    G.add_edge(
                        rel["source_id"],
                        rel["target_id"],
                        rel_type=rel["rel_type"]
                    )
            
            # Log initial relationship statistics
            self._log_relationship_statistics(G, "Initial graph from Neo4j")
            
            # Apply bidirectional relationship enhancement to the graph
            G = self._enhance_graph_with_bidirectional_relationships(G)
            
            logger.info(f"Initialized enhanced graph with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges")
            return G
            
        except Exception as e:
            logger.error(f"Failed to initialize graph: {str(e)}")
            # Return empty graph on error
            return G
    
    def _log_relationship_statistics(self, graph: nx.DiGraph, message: str = ""):
        """Log statistics about relationship types in the graph."""
        if message:
            logger.info(message)
            
        rel_counts = {}
        for _, _, data in graph.edges(data=True):
            rel_type = data.get("rel_type", "Unknown")
            rel_counts[rel_type] = rel_counts.get(rel_type, 0) + 1
            
        logger.info("Relationship type counts:")
        for rel_type, count in sorted(rel_counts.items()):
            logger.info(f"  {rel_type}: {count}")
    
    def _enhance_graph_with_bidirectional_relationships(self, graph: nx.DiGraph) -> nx.DiGraph:
        """
        Add reciprocal relationships to the graph that aren't explicitly defined in the source data.
        
        Args:
            graph: The original graph with one-way relationships
            
        Returns:
            Enhanced graph with bidirectional relationships
        """
        # Map of relationship types to their reciprocals
        reciprocal_map = {
            "ChildOf": "ParentOf",
            "CanPrecede": "CanFollow", 
            "Requires": "RequiredBy",
        }
        
        # Create a new graph to hold the enhanced version
        enhanced_graph = graph.copy()
        
        # Dictionary to track edges we've already processed to avoid duplicates
        processed_edges = set()
        
        # Iterate through all existing edges
        for source, target, data in graph.edges(data=True):
            rel_type = data.get("rel_type", "Unknown")
            processed_edges.add((source, target, rel_type))
            
            # Skip if this relationship doesn't have a defined reciprocal
            if rel_type not in reciprocal_map:
                continue
                
            # Get the reciprocal relationship type
            reciprocal_type = reciprocal_map[rel_type]
            
            # Skip self-loops for symmetric relationships
            if source == target and rel_type == reciprocal_type:
                continue
                
            # Check if the reciprocal edge already exists
            if (target, source, reciprocal_type) in processed_edges:
                continue
                
            # Add the reciprocal edge
            enhanced_graph.add_edge(target, source, rel_type=reciprocal_type)
            processed_edges.add((target, source, reciprocal_type))
        
        # Log relationship statistics after enhancement
        self._log_relationship_statistics(enhanced_graph, "After bidirectional enhancement")
        
        return enhanced_graph

    def generate_vulnerability_chain(self, cwe_id: str, max_depth: int = 3) -> List[Dict[str, Any]]:
        """
        Generate a vulnerability chain based on a starting CWE.
        Enhanced to use bidirectional relationships for better chain detection.
        
        Args:
            cwe_id: Starting CWE ID
            max_depth: Maximum depth of the chain
            
        Returns:
            List of dictionaries containing chain elements
        """
        # Change this check:
        if cwe_id not in self.graph:
            # Strip "CWE-" prefix if present
            numeric_id = cwe_id.replace("CWE-", "")
            if numeric_id in self.graph:
                cwe_id = numeric_id
            else:
                logger.warning(f"CWE {cwe_id} not found in graph")
                return []
            
        # Make sure graph is initialized
        if not self.graph:
            self.graph = self._initialize_graph()
            
        # Check if CWE exists in graph
        if cwe_id not in self.graph:
            logger.warning(f"CWE {cwe_id} not found in graph")
            return []
            
        chain = []
        visited = set()
        
        # Perform DFS to find chain relationships - enhanced for bidirectional traversal
        def dfs(current_id, depth, chain_type):
            if depth > max_depth or current_id in visited:
                return
                
            visited.add(current_id)
            
            # Add current CWE to chain if not already present
            if not any(item["cwe_id"] == current_id for item in chain):
                # Get CWE details
                name = self.graph.nodes[current_id].get("name", "Unknown")
                node_type = self.graph.nodes[current_id].get("type", "Unknown")
                
                chain.append({
                    "cwe_id": current_id,
                    "name": name,
                    "type": node_type,
                    "chain_position": chain_type
                })
            
            # Find outgoing edges based on chain relationship types - now includes bidirectional
            chain_relations = ["CanPrecede", "CanFollow", "Requires", "RequiredBy"]
            
            for successor in self.graph.successors(current_id):
                edge_data = self.graph.get_edge_data(current_id, successor)
                rel_type = edge_data.get("rel_type")
                
                if rel_type in chain_relations:
                    # Determine chain position based on relationship type
                    if rel_type == "CanPrecede":
                        next_type = "EFFECT"
                    elif rel_type == "CanFollow":
                        next_type = "PREREQUISITE"
                    elif rel_type == "Requires":
                        next_type = "DEPENDENCY"
                    elif rel_type == "RequiredBy":
                        next_type = "REQUIRED_BY"
                    else:
                        next_type = "RELATED"
                        
                    dfs(successor, depth + 1, next_type)
        
        # Start DFS from initial CWE
        dfs(cwe_id, 0, "ROOT")
        
        # If chain is very short, try exploring in the other direction
        # This helps when the initial CWE is in the middle of a vulnerability chain
        if len(chain) <= 2:
            # Reset for a new search from dependencies
            prereq_ids = []
            for item in chain:
                if item["chain_position"] in ["PREREQUISITE", "DEPENDENCY"]:
                    prereq_ids.append(item["cwe_id"])
            
            # Explore from prerequisites
            for prereq_id in prereq_ids:
                if prereq_id != cwe_id:  # Don't revisit the root
                    dfs(prereq_id, 0, "PREREQUISITE_ROOT")
        
        return chain
        
        # Perform DFS to find chain relationships
        def dfs(current_id, depth, chain_type):
            if depth > max_depth or current_id in visited:
                return
                
            visited.add(current_id)
            
            # Add current CWE to chain if not already present
            if not any(item["cwe_id"] == current_id for item in chain):
                # Get CWE details
                name = self.graph.nodes[current_id].get("name", "Unknown")
                node_type = self.graph.nodes[current_id].get("type", "Unknown")
                
                chain.append({
                    "cwe_id": current_id,
                    "name": name,
                    "type": node_type,
                    "chain_position": chain_type
                })
            
            # Find outgoing edges based on chain relationship types
            chain_relations = ["CanPrecede", "CanFollow", "Requires", "RequiredBy"]
            
            for successor in self.graph.successors(current_id):
                edge_data = self.graph.get_edge_data(current_id, successor)
                rel_type = edge_data.get("rel_type")
                
                if rel_type in chain_relations:
                    # Determine chain position based on relationship type
                    if rel_type == "CanPrecede":
                        next_type = "EFFECT"
                    elif rel_type == "CanFollow":
                        next_type = "PREREQUISITE"
                    elif rel_type == "Requires":
                        next_type = "DEPENDENCY"
                    elif rel_type == "RequiredBy":
                        next_type = "REQUIRED_BY"
                    else:
                        next_type = "RELATED"
                        
                    dfs(successor, depth + 1, next_type)
        
        # Start DFS from initial CWE
        dfs(cwe_id, 0, "ROOT")
        
        return chain
    
    def suggest_abstraction_level(self, cwe_ids: List[str], description: str = "") -> Dict[str, Any]:
        """
        Enhanced method to suggest better abstraction level CWEs based on provided CWEs.
        Now leverages bidirectional relationships for both hierarchical and chain analysis.
        
        Args:
            cwe_ids: List of CWE IDs to analyze
            description: Vulnerability description for context
            
        Returns:
            Dictionary with suggestions and reasoning
        """
        suggestions = {
            "more_specific": [],  # More specific (child) CWEs
            "more_general": [],   # More general (parent) CWEs
            "alternatives": [],   # Peer CWEs
            "reasoning": ""
        }
        
        if not cwe_ids:
            return suggestions
            
        # Make sure graph is initialized
        if not self.graph:
            self.graph = self._initialize_graph()
            
        all_alternatives = set()
        relevant_specifics = set()
        relevant_generals = set()
        prerequisites = set()
        consequences = set()
        
        for cwe_id in cwe_ids:
            if not cwe_id or not cwe_id.startswith("CWE-") or cwe_id not in self.graph:
                continue
                
            # Get node data
            node_data = self.graph.nodes[cwe_id]
            current_type = node_data.get("type")
            
            # Get more specific CWEs (children) - using ParentOf relationship
            children = self._get_related_cwes(cwe_id, ["ParentOf"], is_incoming=False)
            relevant_specifics.update(children)
            
            # Get more general CWEs (parents) - using ChildOf relationship
            parents = self._get_related_cwes(cwe_id, ["ChildOf"], is_incoming=False)
            relevant_generals.update(parents)
            
            # Get peer CWEs - using peer relationships
            peers = self._get_related_cwes(cwe_id, ["PeerOf", "CanAlsoBe"], is_incoming=None)
            all_alternatives.update(peers)
            
            # Get potential prerequisite CWEs - using CanFollow/Requires relationships
            prereqs = self._get_related_cwes(cwe_id, ["CanFollow", "Requires"], is_incoming=False)
            prerequisites.update(prereqs)
            
            # Get potential consequence CWEs - using CanPrecede/RequiredBy relationships
            conseqs = self._get_related_cwes(cwe_id, ["CanPrecede", "RequiredBy"], is_incoming=False)
            consequences.update(conseqs)
        
        # Generate suggestions based on vulnerability description
        if description:
            # Filter more specific CWEs based on description keywords
            specific_matches = self._filter_by_description(relevant_specifics, description)
            suggestions["more_specific"] = [
                {
                    "cwe_id": cwe_id,
                    "name": self.graph.nodes[cwe_id].get("name", "Unknown"),
                    "type": self.graph.nodes[cwe_id].get("type", "Unknown"),
                    "relevance": score
                }
                for cwe_id, score in specific_matches
            ]
            
            # Filter alternatives based on description keywords
            alt_matches = self._filter_by_description(all_alternatives, description)
            suggestions["alternatives"] = [
                {
                    "cwe_id": cwe_id,
                    "name": self.graph.nodes[cwe_id].get("name", "Unknown"),
                    "type": self.graph.nodes[cwe_id].get("type", "Unknown"),
                    "relevance": score
                }
                for cwe_id, score in alt_matches
            ]
            
            # Filter prerequisites based on description keywords
            if prerequisites:
                prereq_matches = self._filter_by_description(prerequisites, description)
                suggestions["prerequisites"] = [
                    {
                        "cwe_id": cwe_id,
                        "name": self.graph.nodes[cwe_id].get("name", "Unknown"),
                        "type": self.graph.nodes[cwe_id].get("type", "Unknown"),
                        "relevance": score
                    }
                    for cwe_id, score in prereq_matches
                ]
            
            # Filter consequences based on description keywords
            if consequences:
                conseq_matches = self._filter_by_description(consequences, description)
                suggestions["consequences"] = [
                    {
                        "cwe_id": cwe_id,
                        "name": self.graph.nodes[cwe_id].get("name", "Unknown"),
                        "type": self.graph.nodes[cwe_id].get("type", "Unknown"),
                        "relevance": score
                    }
                    for cwe_id, score in conseq_matches
                ]
        else:
            # Without description, just add all options
            suggestions["more_specific"] = [
                {
                    "cwe_id": cwe_id,
                    "name": self.graph.nodes[cwe_id].get("name", "Unknown"),
                    "type": self.graph.nodes[cwe_id].get("type", "Unknown"),
                    "relevance": 0.5  # Default relevance
                }
                for cwe_id in relevant_specifics
            ]
            
            suggestions["alternatives"] = [
                {
                    "cwe_id": cwe_id,
                    "name": self.graph.nodes[cwe_id].get("name", "Unknown"),
                    "type": self.graph.nodes[cwe_id].get("type", "Unknown"),
                    "relevance": 0.5  # Default relevance
                }
                for cwe_id in all_alternatives
            ]
            
            # Add prerequisites without relevance filtering
            if prerequisites:
                suggestions["prerequisites"] = [
                    {
                        "cwe_id": cwe_id,
                        "name": self.graph.nodes[cwe_id].get("name", "Unknown"),
                        "type": self.graph.nodes[cwe_id].get("type", "Unknown"),
                        "relevance": 0.5  # Default relevance
                    }
                    for cwe_id in prerequisites
                ]
            
            # Add consequences without relevance filtering
            if consequences:
                suggestions["consequences"] = [
                    {
                        "cwe_id": cwe_id,
                        "name": self.graph.nodes[cwe_id].get("name", "Unknown"),
                        "type": self.graph.nodes[cwe_id].get("type", "Unknown"),
                        "relevance": 0.5  # Default relevance
                    }
                    for cwe_id in consequences
                ]
        
        # Always include parent CWEs
        suggestions["more_general"] = [
            {
                "cwe_id": cwe_id,
                "name": self.graph.nodes[cwe_id].get("name", "Unknown"),
                "type": self.graph.nodes[cwe_id].get("type", "Unknown"),
                "relevance": 0.5  # Default relevance
            }
            for cwe_id in relevant_generals
        ]
        
        # Sort all suggestion lists by relevance (descending)
        for key in ["more_specific", "more_general", "alternatives", "prerequisites", "consequences"]:
            if key in suggestions and suggestions[key]:
                suggestions[key] = sorted(suggestions[key], key=lambda x: x.get("relevance", 0), reverse=True)
        
        # Generate enhanced reasoning for suggestions with all relationship types
        reasoning = self._generate_abstraction_reasoning(
            cwe_ids, 
            suggestions["more_specific"],
            suggestions["more_general"],
            suggestions.get("prerequisites", []),
            suggestions.get("consequences", [])
        )
        suggestions["reasoning"] = reasoning
        
        return suggestions
    
    def _filter_by_description(self, cwe_ids: Set[str], description: str) -> List[Tuple[str, float]]:
        """
        Filter CWEs by relevance to description.
        
        Args:
            cwe_ids: Set of CWE IDs to filter
            description: Vulnerability description
            
        Returns:
            List of (cwe_id, relevance_score) tuples
        """
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
        import numpy as np
        
        if not cwe_ids or not description:
            return []
            
        # Prepare documents
        documents = [description]
        cwe_texts = []
        valid_cwe_ids = []
        
        for cwe_id in cwe_ids:
            if cwe_id in self.graph:
                # Get CWE text from graph
                name = self.graph.nodes[cwe_id].get("name", "")
                cwe_text = f"{name}"
                
                # Try to get more detailed description from cwe_entries
                if cwe_id in self.cwe_map:
                    entry = self.cwe_map[cwe_id]
                    cwe_text = f"{entry.Name}. {entry.Description}"
                
                cwe_texts.append(cwe_text)
                valid_cwe_ids.append(cwe_id)
                documents.append(cwe_text)
            
        if not valid_cwe_ids:
            return []
            
        # Calculate TF-IDF and cosine similarity
        vectorizer = TfidfVectorizer(stop_words='english')
        try:
            tfidf_matrix = vectorizer.fit_transform(documents)
            
            # Calculate similarity between vulnerability description and each CWE
            desc_vector = tfidf_matrix[0:1]
            cwe_vectors = tfidf_matrix[1:]
            
            similarities = cosine_similarity(desc_vector, cwe_vectors).flatten()
            
            # Sort CWEs by similarity
            sorted_cwes = [(valid_cwe_ids[i], float(similarities[i])) 
                          for i in np.argsort(-similarities)]
            
            # Filter out very low relevance
            return [(cwe_id, score) for cwe_id, score in sorted_cwes if score > 0.1]
            
        except Exception as e:
            logger.error(f"Error filtering by description: {e}")
            return [(cwe_id, 0.5) for cwe_id in valid_cwe_ids]  # Default on error
    
    
    def _generate_abstraction_reasoning(
        self, 
        initial_cwes: List[str],
        specific_suggestions: List[Dict[str, Any]],
        general_suggestions: List[Dict[str, Any]],
        prerequisite_suggestions: List[Dict[str, Any]] = None,
        consequence_suggestions: List[Dict[str, Any]] = None
    ) -> str:
        """
        Enhanced reasoning generation for abstraction level suggestions that accounts
        for bidirectional relationships and chain analysis.
        """
        # Start with basic reasoning template
        reasoning = []
        
        if not initial_cwes:
            return "Insufficient data to provide abstraction level reasoning."
            
        # Analyze initial CWEs
        try:
            initial_types = [self.graph.nodes[cwe_id].get("type", "Unknown") for cwe_id in initial_cwes if cwe_id in self.graph]
            initial_type_counts = {}
            for t in initial_types:
                initial_type_counts[t] = initial_type_counts.get(t, 0) + 1
                
            # Generate reasoning based on abstraction levels
            if "Base" in initial_type_counts and initial_type_counts["Base"] > 0:
                if specific_suggestions:
                    reasoning.append(
                        "Your selected Base weakness(es) can be refined to more specific Variant-level CWEs "
                        "for greater precision. Consider these more specific alternatives."
                    )
                    
            if "Class" in initial_type_counts and initial_type_counts["Class"] > 0:
                reasoning.append(
                    "You've selected Class-level CWEs which are fairly abstract. For more precise mapping, "
                    "consider Base or Variant level CWEs from the suggestions."
                )
                
            if "Variant" in initial_type_counts and initial_type_counts["Variant"] > 0:
                reasoning.append(
                    "Your selection includes specific Variant-level CWEs, which provides good precision. "
                    "However, ensure these aren't too specific for the vulnerability context."
                )
                
            # If we have both specific and general suggestions
            if specific_suggestions and general_suggestions:
                reasoning.append(
                    "Consider the tradeoff between specificity and generality. More specific CWEs provide "
                    "better precision but may miss broader patterns, while more general CWEs capture wider "
                    "categories but sacrifice detail."
                )
            
            # Add reasoning for prerequisite and consequence relationships
            if prerequisite_suggestions:
                prereq_cwes = [f"{item['cwe_id']} ({item['name']})" for item in prerequisite_suggestions[:3]]
                if prereq_cwes:
                    reasoning.append(
                        f"Consider these potential prerequisite weaknesses that may lead to your identified CWEs: {', '.join(prereq_cwes)}."
                    )
                
            if consequence_suggestions:
                conseq_cwes = [f"{item['cwe_id']} ({item['name']})" for item in consequence_suggestions[:3]]
                if conseq_cwes:
                    reasoning.append(
                        f"These weaknesses may be consequences that follow from your identified CWEs: {', '.join(conseq_cwes)}."
                    )
            
            # Add quantitative reasoning
            total_initial = len(initial_cwes)
            total_specific = len(specific_suggestions)
            total_general = len(general_suggestions)
            
            if total_specific > 0:
                reasoning.append(
                    f"Found {total_specific} more specific CWEs that could provide better precision."
                )
                
            if total_general > 0:
                reasoning.append(
                    f"Found {total_general} more general CWEs that could provide better abstraction."
                )
                
            return " ".join(reasoning)
            
        except Exception as e:
            logger.error(f"Error generating abstraction reasoning: {e}")
            return "Error generating abstraction level reasoning."
    
    def _get_related_cwes(self, cwe_id: str, rel_types: List[str], is_incoming: Optional[bool] = None) -> Set[str]:
        """
        Get related CWEs based on relationship types.
        
        Args:
            cwe_id: Base CWE ID
            rel_types: List of relationship types to follow
            is_incoming: If True, get incoming relationships; if False, get outgoing;
                        if None, get both
                        
        Returns:
            Set of related CWE IDs
        """
        related = set()
        
        if not cwe_id or not rel_types or cwe_id not in self.graph:
            return related
            
        # Helper function to check if edge matches rel_types
        def matches_rel_type(edge_data):
            return edge_data.get("rel_type") in rel_types
            
        # Get outgoing relations if not explicitly incoming only
        if is_incoming is None or is_incoming is False:
            for successor in self.graph.successors(cwe_id):
                edge_data = self.graph.get_edge_data(cwe_id, successor)
                if matches_rel_type(edge_data):
                    related.add(successor)
                    
        # Get incoming relations if not explicitly outgoing only
        if is_incoming is None or is_incoming is True:
            for predecessor in self.graph.predecessors(cwe_id):
                edge_data = self.graph.get_edge_data(predecessor, cwe_id)
                if matches_rel_type(edge_data):
                    related.add(predecessor)
                    
        return related
    
    def visualize_relationships(
        self, 
        cwe_ids: List[str], 
        highlight_types: List[str] = None,
        max_depth: int = 2,
        filename: Optional[str] = None,
        format: str = "png",
        show_labels: bool = True
    ) -> str:
        """
        Generate a visualization of CWE relationships.
        
        Args:
            cwe_ids: List of CWE IDs to visualize
            highlight_types: Types of relationships to highlight
            max_depth: Maximum depth of relationships to show
            filename: Output filename (optional)
            format: Output format ('png', 'svg', etc.)
            show_labels: Whether to show relationship labels
            
        Returns:
            Path to saved visualization or base64 encoded image
        """
        if not cwe_ids:
            logger.warning("No CWEs provided for visualization")
            return ""
            
        # Set defaults
        # Include all bidirectional relationship types in the default highlight list
        highlight_types = highlight_types or ["ChildOf", "ParentOf", "PeerOf", "CanPrecede", 
                                              "CanFollow", "Requires", "RequiredBy"]
        
        # Make sure graph is initialized
        if not self.graph:
            self.graph = self._initialize_graph()
            
        # Create subgraph centered on the provided CWEs
        subgraph = nx.DiGraph()
        
        # Normalize CWE IDs by removing "CWE-" prefix
        normalized_cwe_ids = []
        for cwe_id in cwe_ids:
            normalized_id = cwe_id.replace("CWE-", "") if cwe_id.startswith("CWE-") else cwe_id
            normalized_cwe_ids.append(normalized_id)
        
        # First, add the central nodes
        for cwe_id, original_id in zip(normalized_cwe_ids, cwe_ids):
            if cwe_id in self.graph:
                node_data = self.graph.nodes[cwe_id]
                subgraph.add_node(
                    cwe_id,
                    name=node_data.get("name", "Unknown"),
                    type=node_data.get("type", "Unknown"),
                    central=True,  # Mark as central node
                    original_id=original_id  # Store original ID for reference
                )
            else:
                logger.warning(f"CWE {original_id} not found in graph")
                
        # BFS to add related nodes up to max_depth
        frontier = list(normalized_cwe_ids)
        visited = set(normalized_cwe_ids)
        
        for depth in range(max_depth):
            next_frontier = []
            
            for node in frontier:
                if node not in self.graph:
                    continue
                    
                # Add successors (outgoing edges)
                for successor in self.graph.successors(node):
                    edge_data = self.graph.get_edge_data(node, successor)
                    rel_type = edge_data.get("rel_type")
                    
                    if successor not in visited and rel_type in highlight_types:
                        # Add node
                        if successor in self.graph:
                            successor_data = self.graph.nodes[successor]
                            subgraph.add_node(
                                successor,
                                name=successor_data.get("name", "Unknown"),
                                type=successor_data.get("type", "Unknown"),
                                central=False
                            )
                        
                        # Add edge
                        subgraph.add_edge(node, successor, rel_type=rel_type)
                        
                        visited.add(successor)
                        next_frontier.append(successor)
                
                # Add predecessors (incoming edges)
                for predecessor in self.graph.predecessors(node):
                    edge_data = self.graph.get_edge_data(predecessor, node)
                    rel_type = edge_data.get("rel_type")
                    
                    if predecessor not in visited and rel_type in highlight_types:
                        # Add node
                        if predecessor in self.graph:
                            predecessor_data = self.graph.nodes[predecessor]
                            subgraph.add_node(
                                predecessor,
                                name=predecessor_data.get("name", "Unknown"),
                                type=predecessor_data.get("type", "Unknown"),
                                central=False
                            )
                        
                        # Add edge
                        subgraph.add_edge(predecessor, node, rel_type=rel_type)
                        
                        visited.add(predecessor)
                        next_frontier.append(predecessor)
            
            frontier = next_frontier

        logger.info(f"Generated subgraph with {subgraph.number_of_nodes()} nodes and {subgraph.number_of_edges()} edges")
        if subgraph.number_of_edges() == 0:
            logger.warning("No edges found between CWEs in the graph")
            # List central CWEs for debugging
            for cwe_id in normalized_cwe_ids:
                if cwe_id in self.graph:
                    outgoing = list(self.graph.successors(cwe_id))
                    incoming = list(self.graph.predecessors(cwe_id))
                    logger.debug(f"CWE {cwe_id} has {len(outgoing)} outgoing and {len(incoming)} incoming relationships in main graph")
                        
        # Generate the visualization
        return self._render_graph(
            subgraph, 
            filename=filename, 
            format=format,
            show_labels=show_labels,
            cwe_ids=cwe_ids  # Pass original IDs for display purposes
        )
    
    def _render_graph(
        self,
        graph: nx.DiGraph,
        filename: Optional[str] = None,
        format: str = "png",
        show_labels: bool = True,
        cwe_ids: Optional[List[str]] = None
    ) -> str:
        """
        Render a graph to an image file.
        
        Args:
            graph: NetworkX graph to render
            filename: Output filename (optional)
            format: Output format ('png', 'svg', etc.)
            show_labels: Whether to show relationship labels
            cwe_ids: List of central CWE IDs to highlight
            
        Returns:
            Path to saved visualization or base64 encoded image
        """
        if not graph or graph.number_of_nodes() == 0:
            logger.warning("Empty graph, nothing to render")
            return ""
            
        plt.figure(figsize=(12, 8))
        plt.title("CWE Relationship Graph")
        
        # Define node positions using spring layout
        pos = nx.spring_layout(graph, seed=42)
        
        # Prepare node lists by type for different colors
        central_nodes = [node for node, attr in graph.nodes(data=True) if attr.get('central', False)]
        pillar_nodes = [node for node, attr in graph.nodes(data=True) 
                      if attr.get('type') == 'Pillar' and node not in central_nodes]
        class_nodes = [node for node, attr in graph.nodes(data=True) 
                      if attr.get('type') == 'Class' and node not in central_nodes]
        base_nodes = [node for node, attr in graph.nodes(data=True) 
                     if attr.get('type') == 'Base' and node not in central_nodes]
        variant_nodes = [node for node, attr in graph.nodes(data=True) 
                       if attr.get('type') == 'Variant' and node not in central_nodes]
        other_nodes = [node for node, attr in graph.nodes(data=True) 
                      if node not in central_nodes + pillar_nodes + class_nodes + base_nodes + variant_nodes]
        
        # Create node labels
        node_labels = {}
        for node in graph.nodes():
            name = graph.nodes[node].get('name', '')
            # Truncate long names
            if len(name) > 30:
                name = name[:27] + "..."
            node_labels[node] = f"{node}\n{name}"
        
        # Draw nodes by type
        nx.draw_networkx_nodes(graph, pos, nodelist=central_nodes, node_color='red', node_size=700, alpha=0.8)
        nx.draw_networkx_nodes(graph, pos, nodelist=pillar_nodes, node_color='purple', node_size=600, alpha=0.8)
        nx.draw_networkx_nodes(graph, pos, nodelist=class_nodes, node_color='blue', node_size=500, alpha=0.8)
        nx.draw_networkx_nodes(graph, pos, nodelist=base_nodes, node_color='green', node_size=400, alpha=0.8)
        nx.draw_networkx_nodes(graph, pos, nodelist=variant_nodes, node_color='orange', node_size=300, alpha=0.8)
        nx.draw_networkx_nodes(graph, pos, nodelist=other_nodes, node_color='gray', node_size=200, alpha=0.8)
        
        # Draw node labels
        nx.draw_networkx_labels(graph, pos, labels=node_labels, font_size=8)
        
        # Group edges by type for different colors and styles
        edge_types = {}
        for u, v, data in graph.edges(data=True):
            rel_type = data.get('rel_type', 'Unknown')
            if rel_type not in edge_types:
                edge_types[rel_type] = []
            edge_types[rel_type].append((u, v))
        
        # Define edge styles for different relationship types
        edge_styles = {
            'ChildOf': {'color': 'blue', 'style': 'solid', 'width': 1.5},
            'ParentOf': {'color': 'green', 'style': 'solid', 'width': 1.5},
            'PeerOf': {'color': 'purple', 'style': 'dashed', 'width': 1.0},
            'CanAlsoBe': {'color': 'purple', 'style': 'dotted', 'width': 1.0},
            'CanPrecede': {'color': 'red', 'style': 'solid', 'width': 1.0},
            'CanFollow': {'color': 'orange', 'style': 'solid', 'width': 1.0},
            'Requires': {'color': 'brown', 'style': 'solid', 'width': 1.0},
            'RequiredBy': {'color': 'brown', 'style': 'dashed', 'width': 1.0},
            'Default': {'color': 'gray', 'style': 'dotted', 'width': 0.5}
        }
        
        # Draw edges by type
        for rel_type, edge_list in edge_types.items():
            style = edge_styles.get(rel_type, edge_styles['Default'])
            nx.draw_networkx_edges(
                graph, pos, 
                edgelist=edge_list,
                edge_color=style['color'],
                style=style['style'],
                width=style['width'],
                alpha=0.7,
                connectionstyle='arc3,rad=0.1'  # Curved edges
            )
        
        # Add edge labels if requested
        if show_labels:
            edge_labels = {}
            for u, v, data in graph.edges(data=True):
                edge_labels[(u, v)] = data.get('rel_type', '')
            nx.draw_networkx_edge_labels(
                graph, pos,
                edge_labels=edge_labels,
                font_size=7
            )
        
        # Add legend
        legend_elements = [
            plt.Line2D([0], [0], color='red', marker='o', linestyle='', markersize=10, label='Central'),
            plt.Line2D([0], [0], color='purple', marker='o', linestyle='', markersize=10, label='Pillar'),
            plt.Line2D([0], [0], color='blue', marker='o', linestyle='', markersize=10, label='Class'),
            plt.Line2D([0], [0], color='green', marker='o', linestyle='', markersize=10, label='Base'),
            plt.Line2D([0], [0], color='orange', marker='o', linestyle='', markersize=10, label='Variant')
        ]
        
        # Add relationship types to legend
        for rel_type, style in edge_styles.items():
            if rel_type != 'Default' and rel_type in edge_types:
                legend_elements.append(
                    plt.Line2D([0], [0], color=style['color'], 
                               linestyle=style['style'], lw=style['width'],
                               label=rel_type)
                )
        
        plt.legend(handles=legend_elements, loc='best')
        plt.axis('off')
        
        # Save or return as base64
        if filename:
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
            plt.savefig(filename, format=format, dpi=300, bbox_inches='tight')
            plt.close()
            return filename
        else:
            # Return as base64
            buffer = io.BytesIO()
            plt.savefig(buffer, format=format, dpi=300, bbox_inches='tight')
            plt.close()
            
            # Get base64 encoded image
            buffer.seek(0)
            image_base64 = base64.b64encode(buffer.read()).decode('utf-8')
            return image_base64
    
    def generate_mermaid_diagram(self, cwe_ids: List[str], highlight_relationships: bool = True) -> str:
        """
        Generate a Mermaid diagram for CWE relationships.
        
        Args:
            cwe_ids: List of CWE IDs to include in diagram
            highlight_relationships: Whether to highlight relationship types with colors
            
        Returns:
            Mermaid diagram string
        """
        if not cwe_ids:
            return "graph TD\n    empty[\"No CWEs provided\"]"
            
        # Make sure graph is initialized
        if not self.graph:
            self.graph = self._initialize_graph()
            
        # Prepare diagram nodes and edges
        nodes = []
        edges = []
        processed_edges = set()
        
        # Create subgraph with central nodes and direct relationships
        subgraph = nx.DiGraph()
        
        # Add central nodes
        for cwe_id in cwe_ids:
            if cwe_id in self.graph:
                node_data = self.graph.nodes[cwe_id]
                name = node_data.get("name", "Unknown")
                node_type = node_data.get("type", "Unknown")
                
                # Add to diagram
                safe_name = name.replace('"', '\\"')
                node_id = cwe_id.replace('-', '')  # Remove hyphens for Mermaid compatibility
                nodes.append(f'    {node_id}["{cwe_id}: {safe_name}"]')
                
                # Mark as primary
                if cwe_id in cwe_ids:
                    nodes.append(f'    class {node_id} primary')
                
                # Add to subgraph
                subgraph.add_node(cwe_id, name=name, type=node_type, central=True)
                
                # Add direct neighbors
                for successor in self.graph.successors(cwe_id):
                    if successor not in subgraph:
                        if successor in self.graph:
                            successor_data = self.graph.nodes[successor]
                            successor_name = successor_data.get("name", "Unknown")
                            successor_type = successor_data.get("type", "Unknown")
                            
                            # Add to subgraph
                            subgraph.add_node(successor, name=successor_name, type=successor_type, central=False)
                            
                            # Add to diagram
                            safe_succ_name = successor_name.replace('"', '\\"')
                            succ_node_id = successor.replace('-', '')
                            nodes.append(f'    {succ_node_id}["{successor}: {safe_succ_name}"]')
                            
                            # Mark as secondary
                            nodes.append(f'    class {succ_node_id} secondary')
                    
                    # Add edge
                    edge_data = self.graph.get_edge_data(cwe_id, successor)
                    rel_type = edge_data.get("rel_type", "Unknown")
                    
                    # Add to subgraph
                    subgraph.add_edge(cwe_id, successor, rel_type=rel_type)
                    
                    # Add to diagram
                    edge_key = (cwe_id, successor)
                    if edge_key not in processed_edges:
                        processed_edges.add(edge_key)
                        
                        source_id = cwe_id.replace('-', '')
                        target_id = successor.replace('-', '')
                        edges.append(f'    {source_id} -->|{rel_type}| {target_id}')
                
                # Add incoming edges
                for predecessor in self.graph.predecessors(cwe_id):
                    if predecessor not in subgraph:
                        if predecessor in self.graph:
                            predecessor_data = self.graph.nodes[predecessor]
                            predecessor_name = predecessor_data.get("name", "Unknown")
                            predecessor_type = predecessor_data.get("type", "Unknown")
                            
                            # Add to subgraph
                            subgraph.add_node(predecessor, name=predecessor_name, type=predecessor_type, central=False)
                            
                            # Add to diagram
                            safe_pred_name = predecessor_name.replace('"', '\\"')
                            pred_node_id = predecessor.replace('-', '')
                            nodes.append(f'    {pred_node_id}["{predecessor}: {safe_pred_name}"]')
                            
                            # Mark as secondary
                            nodes.append(f'    class {pred_node_id} secondary')
                    
                    # Add edge
                    edge_data = self.graph.get_edge_data(predecessor, cwe_id)
                    rel_type = edge_data.get("rel_type", "Unknown")
                    
                    # Add to subgraph
                    subgraph.add_edge(predecessor, cwe_id, rel_type=rel_type)
                    
                    # Add to diagram
                    edge_key = (predecessor, cwe_id)
                    if edge_key not in processed_edges:
                        processed_edges.add(edge_key)
                        
                        source_id = predecessor.replace('-', '')
                        target_id = cwe_id.replace('-', '')
                        edges.append(f'    {source_id} -->|{rel_type}| {target_id}')
        
        # Build the Mermaid diagram
        mermaid = ["graph TD"]
        mermaid.extend(nodes)
        mermaid.extend(edges)
        
        # Add CSS classes
        if highlight_relationships:
            mermaid.append("    classDef primary fill:#f96,stroke:#333,stroke-width:2px")
            mermaid.append("    classDef secondary fill:#69f,stroke:#333")
            mermaid.append("    classDef tertiary fill:#9e9,stroke:#333")
        
        return "\n".join(mermaid)
    
    def incorporate_into_analysis(self, cwe_ids: List[str], vulnerability_description: str) -> Dict[str, Any]:
        """
        Generate comprehensive relationship analysis for incorporation into CWE analysis.
        
        Args:
            cwe_ids: List of CWE IDs under consideration
            vulnerability_description: Description of the vulnerability
            
        Returns:
            Dictionary with relationship analysis and visualizations
        """
        result = {
            "abstraction_analysis": {},
            "chain_analysis": {},
            "mermaid_diagram": "",
            "visualization_base64": "",
            "suggested_alternatives": [],
            "relationship_summary": ""
        }
        
        if not cwe_ids:
            return result
        
        # Generate abstraction level analysis
        result["abstraction_analysis"] = self.suggest_abstraction_level(cwe_ids, vulnerability_description)
        
        # Generate chain analysis for each CWE
        chains = []
        for cwe_id in cwe_ids:
            chain = self.generate_vulnerability_chain(cwe_id)
            if chain:
                chains.append({
                    "base_cwe": cwe_id,
                    "chain": chain
                })
        result["chain_analysis"] = {"chains": chains}
        
        # Generate Mermaid diagram
        result["mermaid_diagram"] = self.generate_mermaid_diagram(cwe_ids)
        
        # Generate visualization
        try:
            result["visualization_base64"] = self.visualize_relationships(cwe_ids, format="png")
        except Exception as e:
            logger.error(f"Error generating visualization: {e}")
        
        # Generate relationship summary
        summary = self._generate_relationship_summary(cwe_ids, result["abstraction_analysis"], chains)
        result["relationship_summary"] = summary
        
        return result
    
    def _generate_relationship_summary(
        self, 
        cwe_ids: List[str], 
        abstraction_analysis: Dict[str, Any],
        chains: List[Dict[str, Any]]
    ) -> str:
        """Generate a text summary of relationship analysis."""
        summary_parts = []
        
        # Summarize abstraction levels
        if abstraction_analysis:
            # Check what abstraction levels are present
            current_abstractions = []
            for cwe_id in cwe_ids:
                if cwe_id in self.graph:
                    node_type = self.graph.nodes[cwe_id].get("type", "Unknown")
                    if node_type not in current_abstractions:
                        current_abstractions.append(node_type)
            
            summary_parts.append(f"Current CWEs represent these abstraction levels: {', '.join(current_abstractions)}.")
            
            # Add recommendations from abstraction analysis
            if abstraction_analysis.get("reasoning"):
                summary_parts.append(abstraction_analysis["reasoning"])
                
            # Recommend more specific CWEs if available
            if abstraction_analysis.get("more_specific"):
                top_specifics = sorted(
                    abstraction_analysis["more_specific"], 
                    key=lambda x: x.get("relevance", 0), 
                    reverse=True
                )[:3]  # Get top 3
                
                if top_specifics:
                    specific_cwes = [f"{item['cwe_id']} ({item['name']})" for item in top_specifics]
                    summary_parts.append(f"Consider these more specific CWEs: {', '.join(specific_cwes)}.")
        
        # Summarize chain relationships
        if chains:
            chain_insights = []
            
            for chain_info in chains:
                chain = chain_info.get("chain", [])
                if len(chain) > 1:
                    base_cwe = chain_info.get("base_cwe", "Unknown")
                    chain_cwes = [item["cwe_id"] for item in chain if item["cwe_id"] != base_cwe]
                    
                    if chain_cwes:
                        chain_insights.append(f"{base_cwe} has relationships with: {', '.join(chain_cwes)}")
            
            if chain_insights:
                summary_parts.append("Chain Analysis:")
                summary_parts.extend(chain_insights)
        
        return "\n\n".join(summary_parts)