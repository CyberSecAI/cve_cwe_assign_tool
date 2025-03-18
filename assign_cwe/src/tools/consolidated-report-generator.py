#!/usr/bin/env python3
"""
Consolidated CWE Report Generator

This script generates comprehensive markdown and JSON reports for CVE/CWE data,
combining information from multiple sources:
1. cwe_results_extraction.json (top level)
2. Per-CVE similar_cves.json files 
3. Per-CVE consolidatedResults.json files

The script creates both per-CVE reports and an overall summary report.
"""

import os
import re
import json
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Set


def load_json_file(file_path: str) -> Dict:
    """Load and parse a JSON file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error loading {file_path}: {e}")
        return {}


def find_files(base_dir: str, pattern: str) -> List[str]:
    """Find all files matching the pattern in the base directory (recursive)."""
    matches = []
    for root, _, files in os.walk(base_dir):
        for filename in files:
            if re.search(pattern, filename):
                matches.append(os.path.join(root, filename))
    return matches


def get_cve_id_from_path(path: str) -> Optional[str]:
    """Extract CVE ID from a file path."""
    cve_match = re.search(r'(CVE-\d{4}-\d+)', path)
    return cve_match.group(1) if cve_match else None


def consolidate_cve_data(
    extraction_data: Dict,
    similar_cves_files: List[str],
    consolidated_results_files: List[str]
) -> Dict[str, Dict]:
    """
    Combine data from multiple sources into a comprehensive data structure.
    
    Args:
        extraction_data: Data from the main extraction JSON
        similar_cves_files: Paths to similar_cves.json files
        consolidated_results_files: Paths to consolidatedResults.json files
        
    Returns:
        Dictionary mapping CVE IDs to consolidated data
    """
    consolidated_data = {}
    
    # First, process the extraction data (base data)
    for cve_id, cve_data in extraction_data.items():
        if cve_id not in consolidated_data:
            consolidated_data[cve_id] = {
                "cve_id": cve_id,
                "extraction_data": cve_data,
                "similar_cves_data": None,
                "consolidated_results": None
            }
    
    # Process similar_cves.json files
    for file_path in similar_cves_files:
        cve_id = get_cve_id_from_path(file_path)
        if not cve_id:
            print(f"Warning: Could not determine CVE ID from {file_path}")
            continue
            
        similar_cves_data = load_json_file(file_path)
        if not similar_cves_data:
            continue
            
        if cve_id not in consolidated_data:
            consolidated_data[cve_id] = {
                "cve_id": cve_id,
                "extraction_data": None,
                "similar_cves_data": None,
                "consolidated_results": None
            }
            
        consolidated_data[cve_id]["similar_cves_data"] = similar_cves_data
    
    # Process _consolidated_results.json files
    for file_path in consolidated_results_files:
        cve_id = get_cve_id_from_path(file_path)
        if not cve_id:
            print(f"Warning: Could not determine CVE ID from {file_path}")
            continue
            
        consolidated_results = load_json_file(file_path)
        if not consolidated_results:
            continue
            
        if cve_id not in consolidated_data:
            consolidated_data[cve_id] = {
                "cve_id": cve_id,
                "extraction_data": None,
                "similar_cves_data": None,
                "consolidated_results": None
            }
            
        consolidated_data[cve_id]["consolidated_results"] = consolidated_results
    
    return consolidated_data


def generate_cve_markdown_report(cve_data: Dict) -> str:
    """
    Generate a comprehensive markdown report for a single CVE.
    
    Args:
        cve_data: Consolidated data for a single CVE
        
    Returns:
        Markdown report as a string
    """
    cve_id = cve_data["cve_id"]
    report = [f"# {cve_id} CWE Analysis Report\n"]
    report.append(f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Add table of contents
    report.append("## Table of Contents\n")
    report.append("1. [Summary](#summary)")
    report.append("2. [Extraction Data](#extraction-data)")
    report.append("3. [Similar CVEs Analysis](#similar-cves-analysis)")
    report.append("4. [Consolidated Results](#consolidated-results)")
    report.append("5. [Source Files](#source-files)\n")
    
    # Summary section
    report.append("## Summary\n")
    
    # Get primary CWEs from extraction data
    primary_cwes = []
    consensus_cwe = ""
    confidence = "N/A"
    
    if cve_data["extraction_data"]:
        primary_cwes = cve_data["extraction_data"].get("primary", [])
    
    # Get consensus CWE from similar_cves_data if available
    if cve_data["similar_cves_data"]:
        consensus_cwe = cve_data["similar_cves_data"].get("consensus_cwe", "")
    
    # Generate summary table
    report.append("| Attribute | Value |")
    report.append("|-----------|-------|")
    report.append(f"| CVE ID | {cve_id} |")
    
    if primary_cwes:
        report.append(f"| Primary CWEs | {', '.join(primary_cwes)} |")
    else:
        report.append("| Primary CWEs | None identified |")
        
    if consensus_cwe:
        report.append(f"| Consensus CWE | {consensus_cwe} |")
    else:
        report.append("| Consensus CWE | None identified |")
    
    report.append("\n")
    
    # Extraction Data section
    report.append("## Extraction Data\n")
    
    if cve_data["extraction_data"]:
        extraction = cve_data["extraction_data"]
        
        # Display CWE classifications
        for category in ["primary", "secondary", "tertiary", "contributing"]:
            cwes = extraction.get(category, [])
            if cwes:
                report.append(f"### {category.capitalize()} CWEs\n")
                
                # Create table with metadata
                report.append("| CWE ID | Name | Confidence | Notes |")
                report.append("|--------|------|------------|-------|")
                
                for cwe_id in cwes:
                    metadata = extraction.get("metadata", {}).get(cwe_id, {})
                    name = metadata.get("name", "")
                    confidence = metadata.get("confidence", "")
                    notes = metadata.get("notes", "")
                    
                    # Format confidence as a string with 2 decimal places if it's a number
                    if isinstance(confidence, (float, int)):
                        confidence = f"{float(confidence):.2f}"
                    
                    report.append(f"| {cwe_id} | {name} | {confidence} | {notes} |")
                
                report.append("\n")
    else:
        report.append("No extraction data available for this CVE.\n")
    
    # Similar CVEs Analysis section
    report.append("## Similar CVEs Analysis\n")
    
    if cve_data["similar_cves_data"]:
        similar = cve_data["similar_cves_data"]
        consensus = similar.get("consensus_cwe", "")
        total_samples = similar.get("total_samples", 0)
        
        report.append(f"Total similar samples analyzed: {total_samples}\n")
        
        if consensus:
            report.append(f"Consensus CWE: **{consensus}**\n")
        else:
            report.append("No consensus CWE identified.\n")
        
        # Top CWEs
        top_cwes = similar.get("top_cwes", [])
        if top_cwes:
            report.append("### Top CWEs\n")
            report.append("| CWE ID | Frequency |")
            report.append("|--------|-----------|")
            
            for cwe_id, frequency in top_cwes:
                report.append(f"| {cwe_id} | {frequency} |")
            
            report.append("\n")
        
        # Confidence levels
        confidence_levels = similar.get("confidence_levels", {})
        if confidence_levels:
            report.append("### Confidence Levels\n")
            
            for level, cwes in confidence_levels.items():
                if cwes:
                    report.append(f"#### {level.capitalize()} Confidence\n")
                    report.append("- " + ", ".join(cwes) + "\n")
    else:
        report.append("No similar CVEs analysis available for this CVE.\n")
    
    # Consolidated Results section
    report.append("## Consolidated Results\n")
    
    if cve_data["consolidated_results"]:
        consolidated = cve_data["consolidated_results"]
        
        # Extract query information
        if "query" in consolidated:
            report.append(f"**Query**: {consolidated.get('query', '')}\n")
        
        # Extract root cause keyphrases if available
        if "keyphrases" in consolidated and "rootcause" in consolidated["keyphrases"]:
            report.append(f"**Root Cause**: {consolidated['keyphrases']['rootcause']}\n")
        
        # Extract retriever weights
        if "retriever_weights" in consolidated:
            report.append("\n### Retriever Weights\n")
            report.append("| Retriever | Weight |")
            report.append("|-----------|--------|")
            
            for retriever, weight in consolidated["retriever_weights"].items():
                report.append(f"| {retriever} | {weight} |")
            
            report.append("\n")
        
        # Extract detailed results with normalized scores
        if "results" in consolidated:
            report.append("### CWE Results\n")
            report.append("| CWE ID | Name | Abstraction | Score | Dense Score | Sparse Score | Graph Score |")
            report.append("|--------|------|-------------|-------|-------------|--------------|-------------|")
            
            for result in consolidated["results"]:
                cwe_id = result.get("cwe_id", "")
                name = result.get("name", "")
                abstraction = result.get("abstraction", "")
                score = result.get("score", 0)
                
                # Extract normalized scores if available
                dense_score = "-"
                sparse_score = "-"
                graph_score = "-"
                
                if "score_info" in result and "normalized_scores" in result["score_info"]:
                    normalized_scores = result["score_info"]["normalized_scores"]
                    dense_score = f"{normalized_scores.get('dense', 0):.4f}" if "dense" in normalized_scores else "-"
                    sparse_score = f"{normalized_scores.get('sparse', 0):.4f}" if "sparse" in normalized_scores else "-"
                    graph_score = f"{normalized_scores.get('graph', 0):.4f}" if "graph" in normalized_scores else "-"
                
                report.append(f"| {cwe_id} | {name} | {abstraction} | {score:.4f} | {dense_score} | {sparse_score} | {graph_score} |")
            
            report.append("\n")
            
            # Add section with detailed score information for top results
            report.append("### Detailed Score Information for Top Results\n")
            
            for i, result in enumerate(consolidated["results"][:3]):  # Show details for top 3
                cwe_id = result.get("cwe_id", "")
                name = result.get("name", "")
                
                report.append(f"#### {i+1}. {cwe_id}: {name}\n")
                
                if "score_info" in result:
                    score_info = result["score_info"]
                    
                    # Show retrievers used
                    retrievers = score_info.get("retrievers", [])
                    report.append(f"**Retrievers used**: {', '.join(retrievers)}\n")
                    
                    # Show raw scores
                    if "raw_scores" in score_info:
                        report.append("\n**Raw Scores**:\n")
                        for retriever, raw_score in score_info["raw_scores"].items():
                            report.append(f"- {retriever}: {raw_score}\n")
                    
                    # Show normalized scores
                    if "normalized_scores" in score_info:
                        report.append("\n**Normalized Scores**:\n")
                        for retriever, norm_score in score_info["normalized_scores"].items():
                            report.append(f"- {retriever}: {norm_score:.4f}\n")
                    
                    # Show weighted scores
                    if "weighted_scores" in score_info:
                        report.append("\n**Weighted Scores**:\n")
                        for retriever, weighted_score in score_info["weighted_scores"].items():
                            report.append(f"- {retriever}: {weighted_score:.4f}\n")
                    
                    # Show adjustment factors
                    if "adjustment_factors" in score_info:
                        adj_factors = score_info["adjustment_factors"]
                        report.append("\n**Score Adjustments**:\n")
                        report.append(f"- Initial combined score: {adj_factors.get('initial_combined_score', 0):.4f}\n")
                        
                        if "abstraction" in adj_factors:
                            abstraction_info = adj_factors["abstraction"]
                            report.append(f"- Abstraction type: {abstraction_info.get('type', '')}, factor: {abstraction_info.get('factor', 1):.2f}\n")
                            report.append(f"  Score after abstraction: {abstraction_info.get('score_after', 0):.4f}\n")
                        
                        if "mapping" in adj_factors:
                            mapping_info = adj_factors["mapping"]
                            report.append(f"- Mapping usage: {mapping_info.get('usage', '')}, boost: {mapping_info.get('boost', 1):.2f}\n")
                            report.append(f"  Final score: {mapping_info.get('score_after', 0):.4f}\n")
                
                report.append("\n")
        
        # Check if we have a map_type
        if "map_type" in consolidated:
            report.append(f"**Mapping Type**: {consolidated.get('map_type', '')}\n")
        
        # Check for specific recommended/rejected CWEs format
        if "cwe_results" in consolidated:
            results = consolidated["cwe_results"]
            
            if "recommended_cwes" in results:
                report.append("### Recommended CWEs\n")
                
                for cwe_info in results["recommended_cwes"]:
                    cwe_id = cwe_info.get("cwe_id", "")
                    name = cwe_info.get("name", "")
                    score = cwe_info.get("score", "")
                    
                    report.append(f"- **{cwe_id}** ({name}): Score {score:.2f}\n")
            
            if "rejected_cwes" in results:
                report.append("### Rejected CWEs\n")
                
                for cwe_info in results["rejected_cwes"]:
                    cwe_id = cwe_info.get("cwe_id", "")
                    name = cwe_info.get("name", "")
                    reason = cwe_info.get("rejection_reason", "")
                    
                    report.append(f"- **{cwe_id}** ({name}): {reason}\n")
    else:
        report.append("No consolidated results available for this CVE.\n")
    
    # Source Files section
    report.append("## Source Files\n")
    
    if cve_data["extraction_data"] and "sources" in cve_data["extraction_data"]:
        sources = cve_data["extraction_data"]["sources"]
        
        report.append("| File | Type | Primary | Secondary | Tertiary | Contributing |")
        report.append("|------|------|---------|-----------|----------|-------------|")
        
        for source in sources:
            file_path = os.path.basename(source["file"])
            file_type = source.get("file_type", "")
            primary = ", ".join(source.get("primary", [])) or "-"
            secondary = ", ".join(source.get("secondary", [])) or "-"
            tertiary = ", ".join(source.get("tertiary", [])) or "-"
            contributing = ", ".join(source.get("contributing", [])) or "-"
            
            report.append(f"| {file_path} | {file_type} | {primary} | {secondary} | {tertiary} | {contributing} |")
        
        report.append("\n")
        
        # Detailed source metadata
        report.append("### Detailed Source Metadata\n")
        
        for source in sources:
            file_path = os.path.basename(source["file"])
            file_type = source.get("file_type", "")
            
            report.append(f"#### {file_path} ({file_type})\n")
            
            metadata = source.get("metadata", {})
            if metadata:
                report.append("| CWE ID | Name | Confidence | Notes |")
                report.append("|--------|------|------------|-------|")
                
                for cwe_id, meta in metadata.items():
                    name = meta.get("name", "")
                    confidence = meta.get("confidence", "")
                    notes = meta.get("notes", "")
                    
                    # Format confidence
                    if isinstance(confidence, (float, int)):
                        confidence = f"{float(confidence):.2f}"
                    
                    report.append(f"| {cwe_id} | {name} | {confidence} | {notes} |")
                
                report.append("\n")
            else:
                report.append("No metadata available for this source.\n")
    else:
        report.append("No source files information available for this CVE.\n")
    
    return "\n".join(report)


def generate_summary_markdown_report(consolidated_data: Dict[str, Dict]) -> str:
    """
    Generate a summary markdown report for all CVEs.
    
    Args:
        consolidated_data: Dictionary mapping CVE IDs to consolidated data
        
    Returns:
        Markdown report as a string
    """
    report = ["# CVE/CWE Analysis Summary Report\n"]
    report.append(f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Add a summary table with key information
    report.append("## CVE Summary\n")
    report.append("| CVE ID | Primary CWEs | Consensus CWE | Top Similar CWEs | Source Files |")
    report.append("|--------|-------------|---------------|------------------|--------------|")
    
    for cve_id, cve_data in sorted(consolidated_data.items()):
        # Get primary CWEs
        primary_cwes = []
        if cve_data["extraction_data"]:
            primary_cwes = cve_data["extraction_data"].get("primary", [])
        
        # Get consensus CWE and top similar CWEs
        consensus_cwe = ""
        top_similar_cwes = []
        
        if cve_data["similar_cves_data"]:
            consensus_cwe = cve_data["similar_cves_data"].get("consensus_cwe", "")
            top_cwes = cve_data["similar_cves_data"].get("top_cwes", [])
            top_similar_cwes = [cwe_id for cwe_id, _ in top_cwes[:3]] if top_cwes else []
        
        # Get source files count
        source_files_count = 0
        if cve_data["extraction_data"] and "sources" in cve_data["extraction_data"]:
            source_files_count = len(cve_data["extraction_data"]["sources"])
        
        # Add row to table
        report.append(f"| {cve_id} | {', '.join(primary_cwes) or '-'} | {consensus_cwe or '-'} | {', '.join(top_similar_cwes) or '-'} | {source_files_count} |")
    
    report.append("\n## CWE Statistics\n")
    
    # Collect statistics on CWEs
    all_primary_cwes = {}
    all_secondary_cwes = {}
    consensus_cwes = {}
    
    for cve_data in consolidated_data.values():
        # Count primary CWEs
        if cve_data["extraction_data"]:
            for cwe in cve_data["extraction_data"].get("primary", []):
                all_primary_cwes[cwe] = all_primary_cwes.get(cwe, 0) + 1
            
            # Count secondary CWEs
            for cwe in cve_data["extraction_data"].get("secondary", []):
                all_secondary_cwes[cwe] = all_secondary_cwes.get(cwe, 0) + 1
        
        # Count consensus CWEs
        if cve_data["similar_cves_data"]:
            consensus = cve_data["similar_cves_data"].get("consensus_cwe", "")
            if consensus:
                consensus_cwes[consensus] = consensus_cwes.get(consensus, 0) + 1
    
    # Most common primary CWEs
    report.append("### Most Common Primary CWEs\n")
    if all_primary_cwes:
        report.append("| CWE ID | Frequency |")
        report.append("|--------|-----------|")
        
        for cwe, count in sorted(all_primary_cwes.items(), key=lambda x: x[1], reverse=True)[:10]:
            report.append(f"| {cwe} | {count} |")
    else:
        report.append("No primary CWEs identified.\n")
    
    # Most common consensus CWEs
    report.append("\n### Most Common Consensus CWEs\n")
    if consensus_cwes:
        report.append("| CWE ID | Frequency |")
        report.append("|--------|-----------|")
        
        for cwe, count in sorted(consensus_cwes.items(), key=lambda x: x[1], reverse=True)[:10]:
            report.append(f"| {cwe} | {count} |")
    else:
        report.append("No consensus CWEs identified.\n")
    
    # Add section for all CWEs from consolidated results for each CVE
    # First, group by CVE
    report.append("\n## Consolidated Results by CVE\n")
    
    for cve_id, cve_data in sorted(consolidated_data.items()):
        report.append(f"### {cve_id}\n")
        
        if (cve_data["consolidated_results"] and "results" in cve_data["consolidated_results"] and 
            cve_data["consolidated_results"]["results"]):
            
            # Display query if available
            if "query" in cve_data["consolidated_results"]:
                report.append(f"**Query**: {cve_data['consolidated_results'].get('query', '')}\n")
            
            # Display root cause if available
            if "keyphrases" in cve_data["consolidated_results"] and "rootcause" in cve_data["consolidated_results"]["keyphrases"]:
                report.append(f"**Root Cause**: {cve_data['consolidated_results']['keyphrases']['rootcause']}\n")
            
            # Display retriever weights if available
            if "retriever_weights" in cve_data["consolidated_results"]:
                weights = cve_data["consolidated_results"]["retriever_weights"]
                dense_weight = weights.get("dense", 0)
                sparse_weight = weights.get("sparse", 0)
                graph_weight = weights.get("graph", 0)
                report.append(f"**Retriever Weights**: Dense: {dense_weight}, Sparse: {sparse_weight}, Graph: {graph_weight}\n")
            
            # Create table for all CWEs
            report.append("| CWE ID | Name | Abstraction | Score | Dense Score | Sparse Score | Graph Score |")
            report.append("|--------|------|-------------|-------|-------------|--------------|-------------|")
            
            for result in cve_data["consolidated_results"]["results"][:10]:  # Limit to top 10 for readability
                cwe_id = result.get("cwe_id", "")
                name = result.get("name", "")
                abstraction = result.get("abstraction", "")
                score = result.get("score", 0)
                
                # Extract normalized scores
                dense_score = "-"
                sparse_score = "-"
                graph_score = "-"
                
                if "score_info" in result and "normalized_scores" in result["score_info"]:
                    normalized_scores = result["score_info"]["normalized_scores"]
                    dense_score = f"{normalized_scores.get('dense', 0):.4f}" if "dense" in normalized_scores else "-"
                    sparse_score = f"{normalized_scores.get('sparse', 0):.4f}" if "sparse" in normalized_scores else "-"
                    graph_score = f"{normalized_scores.get('graph', 0):.4f}" if "graph" in normalized_scores else "-"
                
                report.append(f"| {cwe_id} | {name} | {abstraction} | {score:.4f} | {dense_score} | {sparse_score} | {graph_score} |")
            
            # If there are more than 10 results, indicate this
            if len(cve_data["consolidated_results"]["results"]) > 10:
                report.append(f"\n*Showing top 10 of {len(cve_data['consolidated_results']['results'])} results*\n")
        else:
            report.append("No consolidated results available for this CVE.\n")
        
        report.append("\n")
    
    return "\n".join(report)


def create_report_files(
    consolidated_data: Dict[str, Dict],
    output_dir: str,
    formats: List[str]
) -> None:
    """
    Create report files in the specified formats.
    
    Args:
        consolidated_data: Dictionary mapping CVE IDs to consolidated data
        output_dir: Directory to save reports
        formats: List of formats to generate ('json', 'md', or both)
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Create a directory for individual CVE reports
    cve_reports_dir = os.path.join(output_dir, "cve_reports")
    os.makedirs(cve_reports_dir, exist_ok=True)
    
    # Generate individual CVE reports
    for cve_id, cve_data in consolidated_data.items():
        # Create a directory for this CVE
        cve_dir = os.path.join(cve_reports_dir, cve_id)
        os.makedirs(cve_dir, exist_ok=True)
        
        # Generate markdown report if requested
        if 'md' in formats:
            md_report = generate_cve_markdown_report(cve_data)
            md_path = os.path.join(cve_dir, f"{cve_id}_report.md")
            
            with open(md_path, 'w') as f:
                f.write(md_report)
            
            print(f"Markdown report for {cve_id} saved to {md_path}")
        
        # Generate JSON report if requested
        if 'json' in formats:
            json_path = os.path.join(cve_dir, f"{cve_id}_report.json")
            
            with open(json_path, 'w') as f:
                json.dump(cve_data, f, indent=2)
            
            print(f"JSON report for {cve_id} saved to {json_path}")
    
    # Generate summary report
    if 'md' in formats:
        summary_md = generate_summary_markdown_report(consolidated_data)
        summary_md_path = os.path.join(output_dir, "summary_report.md")
        
        with open(summary_md_path, 'w') as f:
            f.write(summary_md)
        
        print(f"Summary markdown report saved to {summary_md_path}")
    
    # Generate consolidated JSON
    if 'json' in formats:
        # Create a more concise version for the summary JSON
        summary_data = {}
        
        for cve_id, cve_data in consolidated_data.items():
            # Extract all CWEs with normalized scores if available
            retrievers_results = []
            if (cve_data["consolidated_results"] and "results" in cve_data["consolidated_results"] and 
                cve_data["consolidated_results"]["results"]):
                
                for result in cve_data["consolidated_results"]["results"]:
                    cwe_entry = {
                        "cwe_id": result.get("cwe_id", ""),
                        "name": result.get("name", ""),
                        "abstraction": result.get("abstraction", ""),
                        "score": result.get("score", 0)
                    }
                    
                    # Add normalized scores if available
                    if "score_info" in result and "normalized_scores" in result["score_info"]:
                        normalized_scores = result["score_info"]["normalized_scores"]
                        cwe_entry["normalized_scores"] = {
                            "dense": normalized_scores.get("dense", 0) if "dense" in normalized_scores else None,
                            "sparse": normalized_scores.get("sparse", 0) if "sparse" in normalized_scores else None,
                            "graph": normalized_scores.get("graph", 0) if "graph" in normalized_scores else None
                        }
                    
                    # Add to retrievers_results list
                    retrievers_results.append(cwe_entry)
            
            # Extract confidence information per file type
            agents_results = {}
            if cve_data["extraction_data"] and "sources" in cve_data["extraction_data"]:
                for source in cve_data["extraction_data"]["sources"]:
                    file_type = source.get("file_type", "unknown")
                    
                    # Process metadata for each CWE in this source
                    for cwe_id, metadata in source.get("metadata", {}).items():
                        if cwe_id not in agents_results:
                            agents_results[cwe_id] = {}
                        
                        # Store confidence, notes, and name
                        agents_results[cwe_id][file_type] = {
                            "confidence": metadata.get("confidence", None),
                            "notes": metadata.get("notes", ""),
                            "name": metadata.get("name", ""),
                            "classification": get_cwe_classification(source, cwe_id)
                        }
            
            summary_data[cve_id] = {
                "primary_cwes": cve_data["extraction_data"].get("primary", []) if cve_data["extraction_data"] else [],
                "secondary_cwes": cve_data["extraction_data"].get("secondary", []) if cve_data["extraction_data"] else [],
                "consensus_cwe": cve_data["similar_cves_data"].get("consensus_cwe", "") if cve_data["similar_cves_data"] else "",
                "top_similar_cwes": cve_data["similar_cves_data"].get("top_cwes", []) if cve_data["similar_cves_data"] else [],
                "source_files": len(cve_data["extraction_data"].get("sources", [])) if cve_data["extraction_data"] else 0,
                "retrievers": retrievers_results,
                "agents": agents_results
            }
        
        summary_json_path = os.path.join(output_dir, "summary_report.json")
        
        with open(summary_json_path, 'w') as f:
            json.dump(summary_data, f, indent=2)
        
        print(f"Summary JSON report saved to {summary_json_path}")


def get_cwe_classification(source: Dict, cwe_id: str) -> str:
    """
    Determine if a CWE is classified as primary, secondary, tertiary, or contributing in a source.
    
    Args:
        source: Source information dictionary
        cwe_id: CWE ID to check
        
    Returns:
        Classification as a string ("primary", "secondary", "tertiary", "contributing", or "unknown")
    """
    if cwe_id in source.get("primary", []):
        return "primary"
    elif cwe_id in source.get("secondary", []):
        return "secondary"
    elif cwe_id in source.get("tertiary", []):
        return "tertiary"
    elif cwe_id in source.get("contributing", []):
        return "contributing"
    else:
        return "unknown"

def main():
    """Main function to run the script."""
    parser = argparse.ArgumentParser(description='Generate consolidated CWE reports')
    parser.add_argument('--input-dir', required=True, help='Base directory containing CVE data')
    parser.add_argument('--output-dir', help='Directory to save reports (default: ./reports)')
    parser.add_argument('--formats', choices=['json', 'md', 'all'], default='all', 
                        help='Output formats (json, md, or all)')
    
    args = parser.parse_args()
    
    input_dir = args.input_dir
    output_dir = args.output_dir or os.path.join(os.getcwd(), "reports")
    
    # Determine formats to generate
    formats = []
    if args.formats == 'all':
        formats = ['json', 'md']
    else:
        formats = [args.formats]
    
    print(f"Scanning {input_dir} for CVE data...")
    
    # Load the main extraction JSON file
    extraction_json_path = os.path.join(input_dir, "cwe_results_extraction.json")
    extraction_data = load_json_file(extraction_json_path)
    
    if not extraction_data:
        print(f"Warning: Could not load main extraction data from {extraction_json_path}")
    
    # Find similar_cves.json files
    similar_cves_pattern = r'(?:CVE-\d{4}-\d+_)?similar_cves\.json$'
    similar_cves_files = find_files(input_dir, similar_cves_pattern)
    
    print(f"Found {len(similar_cves_files)} similar_cves.json files")
    
    # Find _consolidated_results.json files 
    consolidated_results_pattern = r'(?:CVE-\d{4}-\d+)?_consolidated_results\.json$'
    consolidated_results_files = find_files(input_dir, consolidated_results_pattern)
    
    print(f"Found {len(consolidated_results_files)} _consolidated_results.json files")
    
    # Consolidate data
    consolidated_data = consolidate_cve_data(
        extraction_data, 
        similar_cves_files, 
        consolidated_results_files
    )
    
    print(f"Consolidated data for {len(consolidated_data)} CVEs")
    
    # Create reports
    create_report_files(consolidated_data, output_dir, formats)
    
    print(f"Report generation complete. Reports saved to {output_dir}")


if __name__ == "__main__":
    main()