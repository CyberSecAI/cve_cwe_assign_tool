#!/usr/bin/env python3
# src/tools/visualize_cwe_relationships.py

import argparse
import os
import sys
import json
from pathlib import Path
import matplotlib.pyplot as plt
from typing import List, Dict, Any, Optional

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).resolve().parent.parent))

from utils.logger import get_logger
from models.cwe import load_cwe_database
from retrievers.neo4j_property_graph import CWEPropertyGraph
from retrievers.relationship_analyzer import CWERelationshipAnalyzer
from config.settings import ConfigManager

logger = get_logger(__name__)

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="CWE Relationship Visualization Tool")
    
    parser.add_argument("--config", type=str, default="config.yaml",
                        help="Path to configuration file")
    
    parser.add_argument("--cwe", type=str, required=False,
                        help="Comma-separated list of CWE IDs to visualize (e.g., 'CWE-79,CWE-89')")
    
    parser.add_argument("--cve", type=str, required=False,
                        help="CVE ID for lookup and visualization")
    
    parser.add_argument("--output-dir", type=str, default="./output/visualizations",
                        help="Output directory for visualizations")
    
    parser.add_argument("--depth", type=int, default=2,
                        help="Depth of relationships to visualize (default: 2)")
    
    parser.add_argument("--format", type=str, default="png",
                        choices=["png", "svg", "pdf"],
                        help="Output format for visualizations")
    
    parser.add_argument("--chain", action="store_true",
                        help="Generate vulnerability chain analysis")
    
    parser.add_argument("--mermaid", action="store_true",
                        help="Generate Mermaid diagram")
    
    parser.add_argument("--abstraction", action="store_true",
                        help="Perform abstraction level analysis")
                        
    parser.add_argument("--analyze-all", action="store_true",
                        help="Analyze all CWEs from database")
    
    return parser.parse_args()

def setup_relationship_analyzer(config_manager, cwe_entries=None):
    """Set up CWE relationship analyzer with Neo4j property graph."""
    try:
        # Get Neo4j configuration
        neo4j_config = config_manager.get_neo4j_config()
        
        # Initialize property graph
        property_graph = CWEPropertyGraph(
            name="cwe_graph",
            url=neo4j_config.get("url"),
            username=neo4j_config.get("username"),
            password=neo4j_config.get("password"),
            storage_dir=neo4j_config.get("storage_dir")
        )
        
        # Initialize relationship analyzer
        analyzer = CWERelationshipAnalyzer(
            property_graph=property_graph,
            cwe_entries=cwe_entries,
            output_dir=args.output_dir
        )
        
        return analyzer
    except Exception as e:
        logger.error(f"Error setting up relationship analyzer: {e}")
        return None

def load_cve_data(cve_id, output_dir):
    """Load CWE data for a specific CVE from output files."""
    cve_dir = os.path.join(output_dir, cve_id)
    
    if not os.path.exists(cve_dir):
        logger.error(f"No data directory found for {cve_id}")
        return None
    
    # Try to find resolution file
    resolution_file = os.path.join(cve_dir, f"{cve_id}_resolution.json")
    if not os.path.exists(resolution_file):
        logger.error(f"No resolution file found for {cve_id}")
        return None
    
    try:
        with open(resolution_file, 'r') as f:
            resolution_data = json.load(f)
            
        # Extract CWE IDs
        cwe_ids = []
        if "identified_cwes" in resolution_data:
            analyzer_cwes = resolution_data.get("identified_cwes", {}).get("analyzer", [])
            critic_cwes = resolution_data.get("identified_cwes", {}).get("critic_additional", [])
            cwe_ids = list(set(analyzer_cwes + critic_cwes))
        
        return {
            "cve_id": cve_id,
            "description": resolution_data.get("description", ""),
            "cwe_ids": cwe_ids
        }
    except Exception as e:
        logger.error(f"Error loading CVE data: {e}")
        return None

def visualize_cwe_relationships(analyzer, cwe_ids, output_dir, depth, format, generate_chain, generate_mermaid, analyze_abstraction):
    """Visualize CWE relationships and generate analyses."""
    if not cwe_ids:
        logger.error("No CWE IDs provided for visualization")
        return False
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate unique output filename based on CWE IDs
    cwe_string = "_".join([cwe_id.replace("CWE-", "") for cwe_id in cwe_ids])
    base_filename = os.path.join(output_dir, f"cwe_{cwe_string}")
    
    results = {}
    
    # Generate visualization
    try:
        logger.info(f"Generating visualization for {len(cwe_ids)} CWEs with depth {depth}")
        viz_file = f"{base_filename}_relationships.{format}"
        
        # Generate the visualization
        analyzer.visualize_relationships(
            cwe_ids=cwe_ids,
            max_depth=depth,
            filename=viz_file,
            format=format,
            show_labels=True
        )
        
        logger.info(f"Saved visualization to {viz_file}")
        results["visualization"] = viz_file
    except Exception as e:
        logger.error(f"Error generating visualization: {e}")
    
    # Generate Mermaid diagram if requested
    if generate_mermaid:
        try:
            logger.info("Generating Mermaid diagram")
            mermaid_diagram = analyzer.generate_mermaid_diagram(cwe_ids, highlight_relationships=True)
            
            # Save Mermaid diagram to file
            mermaid_file = f"{base_filename}_diagram.mmd"
            with open(mermaid_file, 'w') as f:
                f.write(mermaid_diagram)
                
            logger.info(f"Saved Mermaid diagram to {mermaid_file}")
            results["mermaid"] = mermaid_file
        except Exception as e:
            logger.error(f"Error generating Mermaid diagram: {e}")
    
    # Generate vulnerability chain if requested
    if generate_chain:
        try:
            logger.info("Generating vulnerability chain analysis")
            chains = []
            
            for cwe_id in cwe_ids:
                chain = analyzer.generate_vulnerability_chain(cwe_id, max_depth=3)
                if chain:
                    chains.append({
                        "base_cwe": cwe_id,
                        "chain": chain
                    })
            
            # Save chain analysis to file
            chain_file = f"{base_filename}_chain.json"
            with open(chain_file, 'w') as f:
                json.dump(chains, f, indent=2)
                
            logger.info(f"Saved vulnerability chain analysis to {chain_file}")
            results["chain"] = chain_file
        except Exception as e:
            logger.error(f"Error generating vulnerability chain: {e}")
    
    # Perform abstraction level analysis if requested
    if analyze_abstraction:
        try:
            logger.info("Performing abstraction level analysis")
            
            # Use a dummy description for now - ideally this would come from CVE data
            dummy_description = ""
            abstraction_analysis = analyzer.suggest_abstraction_level(cwe_ids, dummy_description)
            
            # Save abstraction analysis to file
            abstraction_file = f"{base_filename}_abstraction.json"
            with open(abstraction_file, 'w') as f:
                json.dump(abstraction_analysis, f, indent=2)
                
            logger.info(f"Saved abstraction level analysis to {abstraction_file}")
            results["abstraction"] = abstraction_file
        except Exception as e:
            logger.error(f"Error performing abstraction level analysis: {e}")
    
    return results

def analyze_all_cwes(analyzer, output_dir, format):
    """Analyze all CWEs in the database to identify key hubs and chains."""
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        # Analyze graph structure
        G = analyzer.graph
        
        # Find CWEs with highest degree (most connected)
        degrees = sorted([(node, G.degree(node)) for node in G.nodes()], 
                        key=lambda x: x[1], reverse=True)
        top_hubs = degrees[:20]  # Top 20 hubs
        
        # Find CWEs with highest betweenness centrality (bridges between communities)
        import networkx as nx
        betweenness = nx.betweenness_centrality(G)
        top_bridges = sorted([(node, betweenness[node]) for node in betweenness], 
                           key=lambda x: x[1], reverse=True)[:20]
        
        # Generate visualizations for top hubs
        hub_results = []
        for cwe_id, degree in top_hubs[:5]:  # Visualize top 5 hubs
            try:
                results = visualize_cwe_relationships(
                    analyzer=analyzer,
                    cwe_ids=[cwe_id],
                    output_dir=os.path.join(output_dir, "hubs"),
                    depth=2,
                    format=format,
                    generate_chain=True,
                    generate_mermaid=True,
                    analyze_abstraction=True
                )
                
                hub_results.append({
                    "cwe_id": cwe_id,
                    "degree": degree,
                    "results": results
                })
            except Exception as e:
                logger.error(f"Error visualizing hub CWE {cwe_id}: {e}")
        
        # Save analysis results
        analysis_file = os.path.join(output_dir, "cwe_network_analysis.json")
        with open(analysis_file, 'w') as f:
            json.dump({
                "top_hubs": [{"cwe_id": cwe_id, "degree": degree} for cwe_id, degree in top_hubs],
                "top_bridges": [{"cwe_id": cwe_id, "centrality": centrality} for cwe_id, centrality in top_bridges],
                "hub_visualizations": hub_results
            }, f, indent=2)
            
        logger.info(f"Saved CWE network analysis to {analysis_file}")
        
        # Generate global graph visualization
        top_cwes = [cwe_id for cwe_id, _ in top_hubs[:10]]  # Top 10 hubs
        
        try:
            viz_file = os.path.join(output_dir, f"cwe_network_top_hubs.{format}")
            
            # Generate the visualization
            analyzer.visualize_relationships(
                cwe_ids=top_cwes,
                max_depth=1,
                filename=viz_file,
                format=format,
                show_labels=True
            )
            
            logger.info(f"Saved hub network visualization to {viz_file}")
        except Exception as e:
            logger.error(f"Error generating hub network visualization: {e}")
        
        return True
    except Exception as e:
        logger.error(f"Error analyzing all CWEs: {e}")
        return False

if __name__ == "__main__":
    # Parse arguments
    args = parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Load configuration
    config_manager = ConfigManager(args.config)
    
    # Load CWE database
    cwe_entries = load_cwe_database(config_manager.config.cwe_database_path)
    logger.info(f"Loaded {len(cwe_entries)} CWE entries")
    
    # Set up relationship analyzer
    analyzer = setup_relationship_analyzer(config_manager, cwe_entries)
    
    if not analyzer:
        logger.error("Failed to set up relationship analyzer. Exiting.")
        sys.exit(1)
    
    if args.analyze_all:
        # Analyze all CWEs in the database
        logger.info("Analyzing all CWEs in the database")
        analyze_all_cwes(analyzer, args.output_dir, args.format)
    elif args.cwe:
        # Parse CWE IDs
        cwe_ids = [cwe_id.strip() for cwe_id in args.cwe.split(",")]
        
        # Add CWE- prefix if not present
        cwe_ids = [cwe_id if cwe_id.startswith("CWE-") else f"CWE-{cwe_id}" for cwe_id in cwe_ids]
        
        logger.info(f"Visualizing relationships for {len(cwe_ids)} CWEs: {', '.join(cwe_ids)}")
        
        # Visualize relationships
        visualize_cwe_relationships(
            analyzer=analyzer,
            cwe_ids=cwe_ids,
            output_dir=args.output_dir,
            depth=args.depth,
            format=args.format,
            generate_chain=args.chain,
            generate_mermaid=args.mermaid,
            analyze_abstraction=args.abstraction
        )
    elif args.cve:
        # Load CWE IDs for CVE
        cve_data = load_cve_data(args.cve, os.path.dirname(args.output_dir))
        
        if not cve_data or not cve_data.get("cwe_ids"):
            logger.error(f"No CWE data found for {args.cve}")
            sys.exit(1)
        
        cwe_ids = cve_data.get("cwe_ids", [])
        
        logger.info(f"Visualizing relationships for {args.cve} with {len(cwe_ids)} CWEs: {', '.join(cwe_ids)}")
        
        # Create CVE-specific output directory
        cve_output_dir = os.path.join(args.output_dir, args.cve)
        os.makedirs(cve_output_dir, exist_ok=True)
        
        # Visualize relationships
        results = visualize_cwe_relationships(
            analyzer=analyzer,
            cwe_ids=cwe_ids,
            output_dir=cve_output_dir,
            depth=args.depth,
            format=args.format,
            generate_chain=args.chain,
            generate_mermaid=args.mermaid,
            analyze_abstraction=args.abstraction
        )
        
        # Generate comprehensive report
        if results:
            try:
                report_file = os.path.join(cve_output_dir, f"{args.cve}_relationship_report.md")
                
                with open(report_file, 'w') as f:
                    f.write(f"# CWE Relationship Analysis for {args.cve}\n\n")
                    
                    # Add CVE description
                    f.write("## Vulnerability Description\n\n")
                    f.write(f"{cve_data.get('description', 'No description available.')}\n\n")
                    
                    # Add identified CWEs
                    f.write("## Identified CWEs\n\n")
                    for cwe_id in cwe_ids:
                        f.write(f"- {cwe_id}\n")
                    f.write("\n")
                    
                    # Add visualization
                    if "visualization" in results:
                        viz_file = os.path.basename(results["visualization"])
                        f.write("## Relationship Visualization\n\n")
                        f.write(f"![CWE Relationships]({viz_file})\n\n")
                    
                    # Add Mermaid diagram
                    if "mermaid" in results:
                        with open(results["mermaid"], 'r') as mmd:
                            mermaid_content = mmd.read()
                            
                        f.write("## Relationship Diagram\n\n")
                        f.write("```mermaid\n")
                        f.write(mermaid_content)
                        f.write("\n```\n\n")
                    
                    # Add chain analysis
                    if "chain" in results:
                        with open(results["chain"], 'r') as chain_file:
                            chains = json.load(chain_file)
                            
                        f.write("## Vulnerability Chain Analysis\n\n")
                        
                        for chain_info in chains:
                            base_cwe = chain_info.get("base_cwe", "Unknown")
                            chain = chain_info.get("chain", [])
                            
                            f.write(f"### Chain starting from {base_cwe}\n\n")
                            
                            for item in chain:
                                cwe_id = item.get("cwe_id", "Unknown")
                                name = item.get("name", "Unknown")
                                chain_position = item.get("chain_position", "Unknown")
                                
                                f.write(f"- **{cwe_id}**: {name} ({chain_position})\n")
                            
                            f.write("\n")
                    
                    # Add abstraction analysis
                    if "abstraction" in results:
                        with open(results["abstraction"], 'r') as abstraction_file:
                            abstraction = json.load(abstraction_file)
                            
                        f.write("## Abstraction Level Analysis\n\n")
                        
                        if "reasoning" in abstraction:
                            f.write(f"{abstraction['reasoning']}\n\n")
                        
                        # Add more specific CWEs
                        if "more_specific" in abstraction and abstraction["more_specific"]:
                            f.write("### More Specific CWEs\n\n")
                            
                            for item in abstraction["more_specific"]:
                                cwe_id = item.get("cwe_id", "Unknown")
                                name = item.get("name", "Unknown")
                                cwe_type = item.get("type", "Unknown")
                                relevance = item.get("relevance", 0)
                                
                                f.write(f"- **{cwe_id}**: {name} ({cwe_type}) - Relevance: {relevance:.2f}\n")
                            
                            f.write("\n")
                        
                        # Add alternative CWEs
                        if "alternatives" in abstraction and abstraction["alternatives"]:
                            f.write("### Alternative CWEs\n\n")
                            
                            for item in abstraction["alternatives"]:
                                cwe_id = item.get("cwe_id", "Unknown")
                                name = item.get("name", "Unknown")
                                cwe_type = item.get("type", "Unknown")
                                relevance = item.get("relevance", 0)
                                
                                f.write(f"- **{cwe_id}**: {name} ({cwe_type}) - Relevance: {relevance:.2f}\n")
                            
                            f.write("\n")
                
                logger.info(f"Generated comprehensive report: {report_file}")
            except Exception as e:
                logger.error(f"Error generating report: {e}")
    else:
        logger.error("No CWE IDs or CVE ID provided. Use --cwe or --cve argument.")
        sys.exit(1)