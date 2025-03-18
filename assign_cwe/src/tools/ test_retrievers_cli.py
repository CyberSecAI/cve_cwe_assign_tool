# Test with just a query
#./test_retrievers_cli.py "A buffer overflow vulnerability in the kernel"

# Test with query and keyphrases
#./test_retrievers_cli.py "A buffer overflow vulnerability in the kernel" --keyphrases "rootcause:buffer overflow,weakness:bounds check"

# Specify custom output directory
#./test_retrievers_cli.py "SQL injection due to improper sanitization" --output-dir "./retriever_tests"

# Enable verbose logging
#./test_retrievers_cli.py "Command injection vulnerability" -v

#!/usr/bin/env python3
# test_retrievers_cli.py

import os
import sys
import json
import argparse
import logging
from typing import Dict, List, Any
from datetime import datetime
from pathlib import Path

# Configure logging
from utils.logger import get_logger, setup_logging
logger = get_logger("retriever_tester")

# Import necessary components
from config.settings import ConfigManager
from models.cwe import load_cwe_database
from retrievers.enhanced_hybrid import EnhancedHybridRetriever

def setup_retriever(config_path: str = "assign_cwe/src/config.yaml"):
    """Initialize the retriever with configuration."""
    # Load configuration
    config_manager = ConfigManager(config_path)
    
    # Initialize embedding client
    from utils.embeddings import initialize_embedding_client
    embedding_client = initialize_embedding_client(config_manager)
    
    # Load Neo4j configuration
    neo4j_config = config_manager.get_neo4j_config()
    
    # Initialize the retriever
    retriever = EnhancedHybridRetriever(
        name="test_retriever",
        llm_config=config_manager.get_llm_config()["llm_config"],
        embedding_client=embedding_client,
        neo4j_config=neo4j_config,
        output_dir="./output/retriever_tests"
    )
    
    # Load CWE database
    cwe_database_path = config_manager.config.cwe_database_path
    cwe_entries = load_cwe_database(cwe_database_path)
    retriever.load_data(cwe_entries)
    
    return retriever, config_manager

def test_retrievers(retriever, query: str) -> Dict[str, Any]:
    """Test each retriever independently with a query and return detailed results."""
    results = {
        "query": query,
        "timestamp": datetime.now().isoformat(),
        "dense": [],
        "sparse": [],
        "graph": [],
        "combined": []
    }
    
    # Test dense retriever
    try:
        logger.info("Testing dense retriever...")
        dense_results = retriever.search(
            query, k=5, use_graph=False, use_rag=True, use_sparse=False
        )
        results["dense"] = [
            {
                "cwe_id": r.get("metadata", {}).get("doc_id", "unknown"),
                "name": r.get("metadata", {}).get("name", "unknown"),
                "score": r.get("similarity", 0.0)
            }
            for r in dense_results
        ]
        logger.info(f"Dense retriever returned {len(results['dense'])} results")
    except Exception as e:
        logger.error(f"Dense retriever test failed: {e}")
        
    # Test sparse retriever
    try:
        logger.info("Testing sparse retriever...")
        sparse_results = retriever.search(
            query, k=5, use_graph=False, use_rag=False, use_sparse=True
        )
        results["sparse"] = [
            {
                "cwe_id": r.get("metadata", {}).get("doc_id", "unknown"),
                "name": r.get("metadata", {}).get("name", "unknown"),
                "score": r.get("similarity", 0.0)
            }
            for r in sparse_results
        ]
        logger.info(f"Sparse retriever returned {len(results['sparse'])} results")
    except Exception as e:
        logger.error(f"Sparse retriever test failed: {e}")
        
    # Test graph retriever
    try:
        logger.info("Testing graph retriever...")
        graph_results = retriever.search(
            query, k=5, use_graph=True, use_rag=False, use_sparse=False
        )
        results["graph"] = [
            {
                "cwe_id": r.get("metadata", {}).get("doc_id", "unknown"),
                "name": r.get("metadata", {}).get("name", "unknown"),
                "score": r.get("similarity", 0.0)
            }
            for r in graph_results
        ]
        logger.info(f"Graph retriever returned {len(results['graph'])} results")
    except Exception as e:
        logger.error(f"Graph retriever test failed: {e}")
        
    # Get combined results
    try:
        logger.info("Testing combined retriever...")
        combined_results = retriever.search(
            query, k=5, use_graph=True, use_rag=True, use_sparse=True
        )
        results["combined"] = [
            {
                "cwe_id": r.get("metadata", {}).get("doc_id", "unknown"),
                "name": r.get("metadata", {}).get("name", "unknown"),
                "score": r.get("similarity", 0.0),
                "retriever_info": r.get("metadata", {}).get("score_info", {})
            }
            for r in combined_results
        ]
        logger.info(f"Combined retriever returned {len(results['combined'])} results")
    except Exception as e:
        logger.error(f"Combined retriever test failed: {e}")
        
    return results

def get_unique_cwes(retriever_name: str, test_results: Dict[str, Any]) -> List[str]:
    """Get CWEs found only by a specific retriever."""
    target_cwes = set(r['cwe_id'] for r in test_results[retriever_name])
    
    # Get CWEs from other retrievers
    other_retrievers = [r for r in ['dense', 'sparse', 'graph'] if r != retriever_name]
    other_cwes = set()
    for retriever in other_retrievers:
        other_cwes.update(r['cwe_id'] for r in test_results[retriever])
        
    # Return CWEs unique to this retriever
    return list(target_cwes - other_cwes)

def get_cwes_found_by_all(test_results: Dict[str, Any]) -> List[str]:
    """Get CWEs found by all retrievers."""
    dense_cwes = set(r['cwe_id'] for r in test_results['dense'])
    sparse_cwes = set(r['cwe_id'] for r in test_results['sparse'])
    graph_cwes = set(r['cwe_id'] for r in test_results['graph'])
    
    return list(dense_cwes.intersection(sparse_cwes, graph_cwes))

def generate_comparison_report(test_results: Dict[str, Any]) -> str:
    """Generate a markdown comparison report of all retrievers for a query."""
    query = test_results["query"]
    
    report = [
        f"# Retriever Comparison for Query\n",
        f"Query: `{query}`\n",
        f"\n## Dense Vector Search Results\n",
        f"| Rank | CWE ID | Name | Score |",
        f"|------|--------|------|-------|"
    ]
    
    # Add dense results
    for i, result in enumerate(test_results["dense"]):
        report.append(f"| {i+1} | {result['cwe_id']} | {result['name']} | {result['score']:.4f} |")
    
    # Add sparse results
    report.extend([
        f"\n## Sparse (BM25) Search Results\n",
        f"| Rank | CWE ID | Name | Score |",
        f"|------|--------|------|-------|"
    ])
    
    for i, result in enumerate(test_results["sparse"]):
        report.append(f"| {i+1} | {result['cwe_id']} | {result['name']} | {result['score']:.4f} |")
    
    # Add graph results
    report.extend([
        f"\n## Property Graph Search Results\n",
        f"| Rank | CWE ID | Name | Score |",
        f"|------|--------|------|-------|"
    ])
    
    for i, result in enumerate(test_results["graph"]):
        report.append(f"| {i+1} | {result['cwe_id']} | {result['name']} | {result['score']:.4f} |")
    
    # Add combined results with detailed information
    report.extend([
        f"\n## Combined Search Results (with boosting)\n",
        f"| Rank | CWE ID | Name | Dense | Sparse | Graph | Combined |",
        f"|------|--------|------|-------|--------|-------|----------|"
    ])
    
    for i, result in enumerate(test_results["combined"]):
        cwe_id = result['cwe_id']
        name = result['name']
        combined_score = result['score']
        
        # Get individual retriever scores if available
        retriever_info = result.get('retriever_info', {})
        individual_scores = retriever_info.get('individual_scores', {})
        
        dense_score = individual_scores.get('dense', '-')
        if dense_score != '-': dense_score = f"{dense_score:.4f}"
        
        sparse_score = individual_scores.get('sparse', '-')
        if sparse_score != '-': sparse_score = f"{sparse_score:.4f}"
        
        graph_score = individual_scores.get('graph', '-')
        if graph_score != '-': graph_score = f"{graph_score:.4f}"
        
        report.append(f"| {i+1} | {cwe_id} | {name} | {dense_score} | {sparse_score} | {graph_score} | {combined_score:.4f} |")
    
    # Generate Venn diagram of overlapping results
    unique_dense = get_unique_cwes("dense", test_results)
    unique_sparse = get_unique_cwes("sparse", test_results)
    unique_graph = get_unique_cwes("graph", test_results)
    all_retrievers = get_cwes_found_by_all(test_results)
    
    report.extend([
        f"\n## Result Overlap Analysis\n",
        f"- **Found by Dense only:** {', '.join(unique_dense) or 'None'}",
        f"- **Found by Sparse only:** {', '.join(unique_sparse) or 'None'}",
        f"- **Found by Graph only:** {', '.join(unique_graph) or 'None'}",
        f"- **Found by all retrievers:** {', '.join(all_retrievers) or 'None'}"
    ])
    
    return "\n".join(report)

def save_results(test_results: Dict[str, Any], output_dir: str, format: str = "all"):
    """Save test results to file."""
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate timestamp for filenames
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Clean query for filename
    query_slug = test_results["query"][:30].replace(" ", "_").replace("/", "_").replace("\\", "_")
    base_filename = f"{timestamp}_{query_slug}"
    
    # Save JSON results
    if format in ["json", "all"]:
        json_path = os.path.join(output_dir, f"{base_filename}.json")
        with open(json_path, 'w') as f:
            json.dump(test_results, f, indent=2)
        logger.info(f"Results saved to {json_path}")
    
    # Save Markdown report
    if format in ["markdown", "md", "all"]:
        md_path = os.path.join(output_dir, f"{base_filename}.md")
        report = generate_comparison_report(test_results)
        with open(md_path, 'w') as f:
            f.write(report)
        logger.info(f"Comparison report saved to {md_path}")
    
    return base_filename

def process_keyphrases(keyphrases_str: str) -> Dict[str, str]:
    """Process keyphrases string into dictionary."""
    if not keyphrases_str:
        return {}
        
    keyphrases = {}
    pairs = keyphrases_str.split(',')
    
    for pair in pairs:
        if ":" in pair:
            key, value = pair.split(":", 1)
            keyphrases[key.strip()] = value.strip()
    
    return keyphrases

def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description="Test and compare retrievers for CWE classification")
    parser.add_argument("query", help="Query text to search with")
    parser.add_argument("--config", default="assign_cwe/src/config.yaml", help="Path to configuration file")
    parser.add_argument("--keyphrases", help="Keyphrases in format 'rootcause:overflow,weakness:bounds' (comma separated)")
    parser.add_argument("--output-dir", default="./output/retriever_tests", help="Directory to save results")
    parser.add_argument("--format", choices=["json", "markdown", "all"], default="all", help="Output format")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()
    
    # Set up logging level based on verbose flag
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(level=log_level)
    
    # Log startup
    logger.info(f"Starting retriever test with query: {args.query}")
    
    try:
        # Initialize retriever
        retriever, config_manager = setup_retriever(args.config)
        
        # Process keyphrases if provided
        keyphrases = process_keyphrases(args.keyphrases) if args.keyphrases else None
        if keyphrases:
            logger.info(f"Using keyphrases: {keyphrases}")
        
        # Run tests both with and without keyphrases
        if keyphrases:
            # Test with keyphrases
            logger.info("Testing retrievers with keyphrases...")
            keyphrase_results = test_retrievers_with_keyphrases(retriever, args.query, keyphrases)
            
            # Save keyphrase results
            save_results(
                keyphrase_results, 
                args.output_dir, 
                args.format
            )
        
        # Test standard retriever functions
        results = test_retrievers(retriever, args.query)
        
        # Save results
        base_filename = save_results(
            results, 
            args.output_dir, 
            args.format
        )
        
        # Print summary to console
        print("\n" + "="*80)
        print(f"RETRIEVER TEST RESULTS SUMMARY")
        print("="*80)
        print(f"Query: {args.query}")
        print(f"Keyphrases: {args.keyphrases or 'None'}")
        print("\nResults:")
        print(f"  Dense retriever: {len(results['dense'])} results")
        print(f"  Sparse retriever: {len(results['sparse'])} results")
        print(f"  Graph retriever: {len(results['graph'])} results")
        print(f"  Combined: {len(results['combined'])} results")
        print("\nTop results by retriever:")
        
        # Show top result from each retriever
        if results['dense']:
            top_dense = results['dense'][0]
            print(f"  Dense: {top_dense['cwe_id']} - {top_dense['name']} (Score: {top_dense['score']:.4f})")
        else:
            print("  Dense: No results")
            
        if results['sparse']:
            top_sparse = results['sparse'][0]
            print(f"  Sparse: {top_sparse['cwe_id']} - {top_sparse['name']} (Score: {top_sparse['score']:.4f})")
        else:
            print("  Sparse: No results")
            
        if results['graph']:
            top_graph = results['graph'][0]
            print(f"  Graph: {top_graph['cwe_id']} - {top_graph['name']} (Score: {top_graph['score']:.4f})")
        else:
            print("  Graph: No results")
            
        if results['combined']:
            top_combined = results['combined'][0]
            print(f"  Combined: {top_combined['cwe_id']} - {top_combined['name']} (Score: {top_combined['score']:.4f})")
        else:
            print("  Combined: No results")
            
        # Show output locations
        print("\nDetailed results saved to:")
        full_path = os.path.abspath(os.path.join(args.output_dir, f"{base_filename}.md"))
        print(f"  {full_path}")
        
        logger.info("Retriever test completed successfully")
        
    except Exception as e:
        logger.error(f"Error during retriever test: {e}", exc_info=True)
        print(f"Error: {e}")
        return 1
        
    return 0

def test_retrievers_with_keyphrases(retriever, query: str, keyphrases: Dict[str, str]) -> Dict[str, Any]:
    """Test retrievers with keyphrases."""
    results = {
        "query": query,
        "keyphrases": keyphrases,
        "timestamp": datetime.now().isoformat(),
        "dense": [],
        "sparse": [],
        "graph": [],
        "combined": []
    }
    
    # Test dense retriever with keyphrases
    try:
        logger.info("Testing dense retriever with keyphrases...")
        # For dense retriever, we can add keyphrases to the query
        enhanced_query = query
        for key, value in keyphrases.items():
            enhanced_query += f" {key}: {value}"
            
        dense_results = retriever.search(
            enhanced_query, k=5, use_graph=False, use_rag=True, use_sparse=False
        )
        results["dense"] = [
            {
                "cwe_id": r.get("metadata", {}).get("doc_id", "unknown"),
                "name": r.get("metadata", {}).get("name", "unknown"),
                "score": r.get("similarity", 0.0)
            }
            for r in dense_results
        ]
        logger.info(f"Dense retriever with keyphrases returned {len(results['dense'])} results")
    except Exception as e:
        logger.error(f"Dense retriever with keyphrases test failed: {e}")
        
    # Test sparse retriever with keyphrases
    try:
        logger.info("Testing sparse retriever with keyphrases...")
        sparse_results = retriever.search(
            query, keyphrases=keyphrases, k=5, use_graph=False, use_rag=False, use_sparse=True
        )
        results["sparse"] = [
            {
                "cwe_id": r.get("metadata", {}).get("doc_id", "unknown"),
                "name": r.get("metadata", {}).get("name", "unknown"),
                "score": r.get("similarity", 0.0)
            }
            for r in sparse_results
        ]
        logger.info(f"Sparse retriever with keyphrases returned {len(results['sparse'])} results")
    except Exception as e:
        logger.error(f"Sparse retriever with keyphrases test failed: {e}")
        
    # Test graph retriever with keyphrases (may not use keyphrases directly)
    try:
        logger.info("Testing graph retriever with keyphrases...")
        graph_results = retriever.search(
            query, keyphrases=keyphrases, k=5, use_graph=True, use_rag=False, use_sparse=False
        )
        results["graph"] = [
            {
                "cwe_id": r.get("metadata", {}).get("doc_id", "unknown"),
                "name": r.get("metadata", {}).get("name", "unknown"),
                "score": r.get("similarity", 0.0)
            }
            for r in graph_results
        ]
        logger.info(f"Graph retriever with keyphrases returned {len(results['graph'])} results")
    except Exception as e:
        logger.error(f"Graph retriever with keyphrases test failed: {e}")
        
    # Get combined results with keyphrases
    try:
        logger.info("Testing combined retriever with keyphrases...")
        combined_results = retriever.search(
            query, keyphrases=keyphrases, k=5, use_graph=True, use_rag=True, use_sparse=True
        )
        results["combined"] = [
            {
                "cwe_id": r.get("metadata", {}).get("doc_id", "unknown"),
                "name": r.get("metadata", {}).get("name", "unknown"),
                "score": r.get("similarity", 0.0),
                "retriever_info": r.get("metadata", {}).get("score_info", {})
            }
            for r in combined_results
        ]
        logger.info(f"Combined retriever with keyphrases returned {len(results['combined'])} results")
    except Exception as e:
        logger.error(f"Combined retriever with keyphrases test failed: {e}")
        
    return results

if __name__ == "__main__":
    sys.exit(main())