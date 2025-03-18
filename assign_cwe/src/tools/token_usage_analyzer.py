#!/usr/bin/env python3
"""
Token Usage Analyzer

A standalone tool for analyzing token usage logs from the CVE processing pipeline.
This script generates detailed reports on token usage across different stages of processing.

Usage:
    python token_usage_analyzer.py <path_to_token_usage.csv> [output_dir]
    
Example:
    python ./assign_cwe/src/tools/token_usage_analyzer.py ../cwe_assign_reports/token_usage.csv

If output_dir is not provided, reports will be saved in the same directory as the CSV file.
"""

import os
import sys
import csv
import json
import time
import argparse
from typing import Dict, Any, List


def analyze_token_usage(csv_path: str, output_dir: str = None) -> Dict[str, Any]:
    """
    Analyze token usage data from a CSV file and generate summary statistics.
    
    Args:
        csv_path: Path to the token usage CSV file
        output_dir: Optional directory to save reports (defaults to CSV directory)
        
    Returns:
        Dictionary with summary statistics
    """
    if not os.path.exists(csv_path):
        print(f"Error: Token usage log not found at {csv_path}")
        sys.exit(1)
    
    # If output_dir not specified, use the directory containing the CSV
    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(csv_path))
        
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    print(f"Reading token usage data from {csv_path}")
    
    # Read the CSV data
    token_data = []
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Convert string numbers to integers
            for key in ['input_length', 'input_words', 'output_length', 'output_words']:
                row[key] = int(row[key])
            token_data.append(row)
    
    print(f"Read {len(token_data)} entries from CSV")
    
    # Calculate summary statistics
    summary = {
        "total_entries": len(token_data),
        "by_stage": {},
        "overall": {
            "total_input_length": 0,
            "total_input_words": 0,
            "total_output_length": 0, 
            "total_output_words": 0,
            "avg_input_length": 0,
            "avg_input_words": 0,
            "avg_output_length": 0,
            "avg_output_words": 0
        },
        "per_cve": {}
    }
    
    # Get unique stages and CVEs
    stages = sorted(set(entry["stage"] for entry in token_data))
    cve_ids = sorted(set(entry["cve_id"] for entry in token_data))
    
    print(f"Found {len(stages)} stages and {len(cve_ids)} CVEs")
    
    # Initialize stage summaries
    for stage in stages:
        summary["by_stage"][stage] = {
            "count": 0,
            "total_input_length": 0,
            "total_input_words": 0,
            "total_output_length": 0,
            "total_output_words": 0,
            "avg_input_length": 0,
            "avg_input_words": 0,
            "avg_output_length": 0,
            "avg_output_words": 0,
            "min_input_length": float('inf'),
            "max_input_length": 0,
            "min_output_length": float('inf'),
            "max_output_length": 0
        }
    
    # Initialize per-CVE summaries
    for cve_id in cve_ids:
        summary["per_cve"][cve_id] = {
            "total_input_length": 0,
            "total_input_words": 0,
            "total_output_length": 0,
            "total_output_words": 0,
            "stages": {}
        }
        
        # Initialize stage data for each CVE
        for stage in stages:
            summary["per_cve"][cve_id]["stages"][stage] = {
                "input_length": 0,
                "input_words": 0,
                "output_length": 0,
                "output_words": 0,
                "timestamp": ""
            }
    
    # Calculate statistics
    for entry in token_data:
        cve_id = entry["cve_id"]
        stage = entry["stage"]
        
        # Update stage summary
        stage_summary = summary["by_stage"][stage]
        stage_summary["count"] += 1
        stage_summary["total_input_length"] += entry["input_length"]
        stage_summary["total_input_words"] += entry["input_words"]
        stage_summary["total_output_length"] += entry["output_length"]
        stage_summary["total_output_words"] += entry["output_words"]
        stage_summary["min_input_length"] = min(stage_summary["min_input_length"], entry["input_length"])
        stage_summary["max_input_length"] = max(stage_summary["max_input_length"], entry["input_length"])
        stage_summary["min_output_length"] = min(stage_summary["min_output_length"], entry["output_length"])
        stage_summary["max_output_length"] = max(stage_summary["max_output_length"], entry["output_length"])
        
        # Update CVE summary
        cve_summary = summary["per_cve"][cve_id]
        cve_summary["total_input_length"] += entry["input_length"]
        cve_summary["total_input_words"] += entry["input_words"]
        cve_summary["total_output_length"] += entry["output_length"]
        cve_summary["total_output_words"] += entry["output_words"]
        
        # Update stage data for the CVE
        cve_summary["stages"][stage] = {
            "input_length": entry["input_length"],
            "input_words": entry["input_words"],
            "output_length": entry["output_length"],
            "output_words": entry["output_words"],
            "timestamp": entry["timestamp"]
        }
        
        # Update overall totals
        summary["overall"]["total_input_length"] += entry["input_length"]
        summary["overall"]["total_input_words"] += entry["input_words"]
        summary["overall"]["total_output_length"] += entry["output_length"]
        summary["overall"]["total_output_words"] += entry["output_words"]
    
    # Calculate averages for each stage
    for stage, stats in summary["by_stage"].items():
        if stats["count"] > 0:
            stats["avg_input_length"] = stats["total_input_length"] / stats["count"]
            stats["avg_input_words"] = stats["total_input_words"] / stats["count"]
            stats["avg_output_length"] = stats["total_output_length"] / stats["count"]
            stats["avg_output_words"] = stats["total_output_words"] / stats["count"]
    
    # Calculate overall averages
    if summary["total_entries"] > 0:
        summary["overall"]["avg_input_length"] = summary["overall"]["total_input_length"] / summary["total_entries"]
        summary["overall"]["avg_input_words"] = summary["overall"]["total_input_words"] / summary["total_entries"]
        summary["overall"]["avg_output_length"] = summary["overall"]["total_output_length"] / summary["total_entries"]
        summary["overall"]["avg_output_words"] = summary["overall"]["total_output_words"] / summary["total_entries"]
    

    # Estimate token costs 
    # Gemini https://ai.google.dev/gemini-api/docs/pricing
    # Input price $0.10
    # Output price $0.40
    
    # Using a simple words-to-tokens ratio of 0.75 (1 token ≈ 0.75 words)
    word_to_token_ratio = 0.75
    input_cost_per_1k = 0.10/1000  
    output_cost_per_1k = 0.40/1000
    
    # Calculate token estimates and costs
    summary["token_estimates"] = {
        "total_input_tokens": int(summary["overall"]["total_input_words"] / word_to_token_ratio),
        "total_output_tokens": int(summary["overall"]["total_output_words"] / word_to_token_ratio),
        "estimated_input_cost": (summary["overall"]["total_input_words"] / word_to_token_ratio / 1000) * input_cost_per_1k,
        "estimated_output_cost": (summary["overall"]["total_output_words"] / word_to_token_ratio / 1000) * output_cost_per_1k,
        "estimated_total_cost": ((summary["overall"]["total_input_words"] / word_to_token_ratio / 1000) * input_cost_per_1k) + 
                            ((summary["overall"]["total_output_words"] / word_to_token_ratio / 1000) * output_cost_per_1k)
    }
    
    # Add per-stage token estimates
    for stage, stats in summary["by_stage"].items():
        stats["estimated_input_tokens"] = int(stats["total_input_words"] / word_to_token_ratio)
        stats["estimated_output_tokens"] = int(stats["total_output_words"] / word_to_token_ratio)
        stats["estimated_input_cost"] = (stats["total_input_words"] / word_to_token_ratio / 1000) * input_cost_per_1k
        stats["estimated_output_cost"] = (stats["total_output_words"] / word_to_token_ratio / 1000) * output_cost_per_1k
        stats["estimated_total_cost"] = stats["estimated_input_cost"] + stats["estimated_output_cost"]
    
    # Add per-CVE token estimates
    for cve_id, stats in summary["per_cve"].items():
        stats["estimated_input_tokens"] = int(stats["total_input_words"] / word_to_token_ratio)
        stats["estimated_output_tokens"] = int(stats["total_output_words"] / word_to_token_ratio)
        stats["estimated_input_cost"] = (stats["total_input_words"] / word_to_token_ratio / 1000) * input_cost_per_1k
        stats["estimated_output_cost"] = (stats["total_output_words"] / word_to_token_ratio / 1000) * output_cost_per_1k
        stats["estimated_total_cost"] = stats["estimated_input_cost"] + stats["estimated_output_cost"]
    
    # Generate and save reports
    save_reports(summary, output_dir)
    
    return summary


def save_reports(summary: Dict[str, Any], output_dir: str):
    """
    Generate and save various reports based on the summary data.
    
    Args:
        summary: Dictionary with summary statistics
        output_dir: Directory to save reports
    """
    # 1. Save the full JSON summary
    json_report_path = os.path.join(output_dir, "token_usage_summary.json")
    with open(json_report_path, 'w') as f:
        json.dump(summary, f, indent=2)
    
    # 2. Generate markdown summary report
    md_report = generate_markdown_report(summary)
    md_report_path = os.path.join(output_dir, "token_usage_summary.md")
    with open(md_report_path, 'w') as f:
        f.write(md_report)
    
    # 3. Generate CSV summary of per-CVE costs
    csv_report_path = os.path.join(output_dir, "token_usage_per_cve.csv")
    with open(csv_report_path, 'w', newline='') as f:
        fieldnames = [
            "cve_id", 
            "total_input_words", 
            "total_output_words", 
            "estimated_input_tokens", 
            "estimated_output_tokens",
            "estimated_total_cost"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for cve_id, stats in summary["per_cve"].items():
            writer.writerow({
                "cve_id": cve_id,
                "total_input_words": stats["total_input_words"],
                "total_output_words": stats["total_output_words"],
                "estimated_input_tokens": stats["estimated_input_tokens"],
                "estimated_output_tokens": stats["estimated_output_tokens"],
                "estimated_total_cost": round(stats["estimated_total_cost"], 4)
            })
    
    # 4. Generate CSV summary of per-stage costs
    csv_stage_path = os.path.join(output_dir, "token_usage_per_stage.csv")
    with open(csv_stage_path, 'w', newline='') as f:
        fieldnames = [
            "stage", 
            "count",
            "avg_input_words", 
            "avg_output_words",
            "total_input_words",
            "total_output_words",
            "estimated_input_tokens", 
            "estimated_output_tokens",
            "estimated_total_cost"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for stage, stats in summary["by_stage"].items():
            writer.writerow({
                "stage": stage,
                "count": stats["count"],
                "avg_input_words": round(stats["avg_input_words"], 2),
                "avg_output_words": round(stats["avg_output_words"], 2),
                "total_input_words": stats["total_input_words"],
                "total_output_words": stats["total_output_words"],
                "estimated_input_tokens": stats["estimated_input_tokens"],
                "estimated_output_tokens": stats["estimated_output_tokens"],
                "estimated_total_cost": round(stats["estimated_total_cost"], 4)
            })
    
    print(f"Reports saved to:")
    print(f"  - {json_report_path}")
    print(f"  - {md_report_path}")
    print(f"  - {csv_report_path}")
    print(f"  - {csv_stage_path}")


def generate_markdown_report(summary: Dict[str, Any]) -> str:
    """
    Generate a markdown report from the summary data.
    
    Args:
        summary: Dictionary with summary statistics
        
    Returns:
        Markdown formatted report
    """
    md_report = f"""# Token Usage Summary Report

## Overall Statistics

- **Total CVEs Processed**: {len(summary["per_cve"])}
- **Total Entries**: {summary["total_entries"]}
- **Total Input Characters**: {summary["overall"]["total_input_length"]:,}
- **Total Input Words**: {summary["overall"]["total_input_words"]:,}
- **Total Output Characters**: {summary["overall"]["total_output_length"]:,}
- **Total Output Words**: {summary["overall"]["total_output_words"]:,}

## Token Estimates and Costs

- **Estimated Input Tokens**: {summary["token_estimates"]["total_input_tokens"]:,}
- **Estimated Output Tokens**: {summary["token_estimates"]["total_output_tokens"]:,}
- **Estimated Input Cost**: ${summary["token_estimates"]["estimated_input_cost"]:.2f}
- **Estimated Output Cost**: ${summary["token_estimates"]["estimated_output_cost"]:.2f}
- **Estimated Total Cost**: ${summary["token_estimates"]["estimated_total_cost"]:.2f}

## Cost Per CVE

| Metric | Average | Min | Max | Total |
|--------|---------|-----|-----|-------|
"""
    # Calculate per-CVE statistics
    costs = [stats["estimated_total_cost"] for stats in summary["per_cve"].values()]
    avg_cost = sum(costs) / len(costs) if costs else 0
    min_cost = min(costs) if costs else 0
    max_cost = max(costs) if costs else 0
    total_cost = sum(costs)
    
    md_report += f"| **Cost** | ${avg_cost:.4f} | ${min_cost:.4f} | ${max_cost:.4f} | ${total_cost:.2f} |\n\n"

    # Add stats for each stage
    md_report += "## By Stage\n\n"
    
    # Create a table for stage statistics
    md_report += "| Stage | Count | Avg Input Words | Avg Output Words | Total Tokens | Cost |\n"
    md_report += "|-------|-------|----------------|-----------------|-------------|------|\n"
    
    for stage, stats in summary["by_stage"].items():
        total_tokens = stats["estimated_input_tokens"] + stats["estimated_output_tokens"]
        md_report += f"| {stage.capitalize()} | {stats['count']} | {stats['avg_input_words']:.2f} | {stats['avg_output_words']:.2f} | {total_tokens:,} | ${stats['estimated_total_cost']:.2f} |\n"
    
    md_report += "\n"
    
    # Add detailed stage information
    for stage, stats in summary["by_stage"].items():
        md_report += f"""### {stage.capitalize()}

- **Count**: {stats["count"]}
- **Avg Input Length**: {stats["avg_input_length"]:.2f} characters
- **Avg Input Words**: {stats["avg_input_words"]:.2f} words
- **Avg Output Length**: {stats["avg_output_length"]:.2f} characters
- **Avg Output Words**: {stats["avg_output_words"]:.2f} words
- **Min/Max Input**: {stats["min_input_length"]:,} / {stats["max_input_length"]:,} characters
- **Min/Max Output**: {stats["min_output_length"]:,} / {stats["max_output_length"]:,} characters
- **Estimated Cost**: ${stats["estimated_total_cost"]:.2f}

"""

    # Add Top 10 most expensive CVEs
    md_report += "## Top 10 Most Expensive CVEs\n\n"
    md_report += "| CVE ID | Input Words | Output Words | Total Tokens | Cost |\n"
    md_report += "|--------|-------------|-------------|-------------|------|\n"
    
    # Sort CVEs by cost and get top 10
    sorted_cves = sorted(
        [(cve_id, stats) for cve_id, stats in summary["per_cve"].items()],
        key=lambda x: x[1]["estimated_total_cost"],
        reverse=True
    )
    
    # Sort CVEs by cost and get top 10
    sorted_cves = sorted(
        [(cve_id, stats) for cve_id, stats in summary["per_cve"].items()],
        key=lambda x: x[1]["estimated_total_cost"],
        reverse=True
    )
    
    # Add top 10 to table
    for cve_id, stats in sorted_cves[:10]:
        total_tokens = stats["estimated_input_tokens"] + stats["estimated_output_tokens"]
        md_report += f"| {cve_id} | {stats['total_input_words']:,} | {stats['total_output_words']:,} | {total_tokens:,} | ${stats['estimated_total_cost']:.4f} |\n"
    
    # Add a timestamp
    md_report += f"\n\n*Report generated on {time.strftime('%Y-%m-%d %H:%M:%S')}*"
    
    return md_report


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description="Analyze token usage data from CVE processing.")
    parser.add_argument("csv_path", help="Path to the token_usage.csv file")
    parser.add_argument("--output-dir", "-o", help="Directory to save reports (defaults to CSV directory)")
    
    args = parser.parse_args()
    
    # Validate CSV path
    if not os.path.exists(args.csv_path):
        print(f"Error: File not found: {args.csv_path}")
        sys.exit(1)
    
    # Run analysis
    try:
        summary = analyze_token_usage(args.csv_path, args.output_dir)
        print(f"Analysis complete. Estimated total cost: ${summary['token_estimates']['estimated_total_cost']:.2f}")
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()