#!/usr/bin/env python3

# "Total CVEs in results" - Shows the total number of CVEs in your results file
# "CVEs in both results and benchmark" - Shows how many of your results CVEs are also in the benchmark
# "CVEs with at least one CWE match" - Shows how many CVEs have matching CWEs
# "Total benchmark CWEs for results CVEs" - Only counts benchmark CWEs for CVEs in your results
# "Total matched CWEs" - Shows how many individual CWEs matched across all CVEs
#!/usr/bin/env python3

import json
import csv
import argparse
import sys
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Any


def generate_csv_report(comparison_results: List[Dict[str, Any]], json_results: Dict[str, Any], output_path: str) -> None:
    """Generate a CSV report with CWE sources per CVE."""
    csv_columns = [
        'CVE', 
        'Benchmark_CWEs',
        'Agent_Resolution', 
        'Agent_Criticism', 
        'Agent_Analysis', 
        'Primary_CWEs', 
        'Secondary_CWEs', 
        'Consensus_CWE', 
        'Top_Similar_CWEs', 
        'Retriever_Dense', 
        'Retriever_Sparse', 
        'Retriever_Graph',
        'Matched_CWEs'
    ]
    
    # Create a dictionary to map comparison results by CVE ID for easier lookup
    results_by_cve = {result['cve_id']: result for result in comparison_results}
    
    try:
        with open(output_path, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer.writeheader()
            
            # Process each CVE in the results
            for cve_id in sorted(json_results.keys()):
                if cve_id not in results_by_cve:
                    continue
                    
                result = results_by_cve[cve_id]
                
                # Format CWE lists for CSV
                row = {
                    'CVE': cve_id,
                    'Benchmark_CWEs': ';'.join(sorted(result.get('benchmark_cwes', set()))),
                    'Agent_Resolution': ';'.join(sorted(result['result_cwes'].get('agents_resolution', set()))),
                    'Agent_Criticism': ';'.join(sorted(result['result_cwes'].get('agents_criticism', set()))),
                    'Agent_Analysis': ';'.join(sorted(result['result_cwes'].get('agents_analysis', set()))),
                    'Primary_CWEs': ';'.join(sorted(result['result_cwes'].get('primary_cwes', set()))),
                    'Secondary_CWEs': ';'.join(sorted(result['result_cwes'].get('secondary_cwes', set()))),
                    'Consensus_CWE': ';'.join([cwe for cwe in sorted(result['result_cwes'].get('consensus_cwe', set())) if cwe]),
                    'Top_Similar_CWEs': ';'.join(sorted(result['result_cwes'].get('top_similar_cwes', set()))),
                    'Retriever_Dense': ';'.join(sorted(result['result_cwes'].get('retriever_dense', set()))),
                    'Retriever_Sparse': ';'.join(sorted(result['result_cwes'].get('retriever_sparse', set()))),
                    'Retriever_Graph': ';'.join(sorted(result['result_cwes'].get('retriever_graph', set()))),
                    'Matched_CWEs': ';'.join(sorted(result.get('matched_cwes', set())))
                }
                
                writer.writerow(row)
                
        print(f"\nCSV report generated: {output_path}")
        
    except Exception as e:
        print(f"Error generating CSV report: {e}")


def load_json_results(file_path: str) -> Dict[str, Any]:
    """Load and parse the JSON results file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading JSON file {file_path}: {e}")
        sys.exit(1)


def load_csv_benchmark(file_path: str) -> Dict[str, Set[str]]:
    """Load and parse the CSV benchmark file."""
    benchmark_data = defaultdict(set)
    try:
        with open(file_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve_id = row['CVE']
                new_cwe = row['New CWE']
                if new_cwe.startswith("CWE-"):
                    benchmark_data[cve_id].add(new_cwe)
    except Exception as e:
        print(f"Error loading CSV file {file_path}: {e}")
        sys.exit(1)
    return benchmark_data


def collect_cwes_from_results(cve_data: Dict[str, Any]) -> Dict[str, Set[str]]:
    """Collect all CWEs mentioned in the results for a specific CVE."""
    # Handle top_similar_cwes with a recursive approach to handle any nested structure
    top_similar_cwes = set()
    raw_top_similar = cve_data.get('top_similar_cwes', [])
    
    def extract_cwes(item):
        if isinstance(item, str) and item.startswith('CWE-'):
            top_similar_cwes.add(item)
        elif isinstance(item, list):
            for sub_item in item:
                extract_cwes(sub_item)
        elif isinstance(item, dict) and 'cwe_id' in item:
            if isinstance(item['cwe_id'], str) and item['cwe_id'].startswith('CWE-'):
                top_similar_cwes.add(item['cwe_id'])
    
    if isinstance(raw_top_similar, list):
        for item in raw_top_similar:
            extract_cwes(item)
    
    # Initialize source dictionaries for retriever types
    retriever_dense = set()
    retriever_sparse = set()
    retriever_graph = set()
    
    # Extract CWEs from retrievers by type
    for retriever in cve_data.get('retrievers', []):
        cwe_id = retriever.get('cwe_id')
        if not cwe_id:
            continue
            
        # Add to general retrievers set
        retriever_set = set()
        
        # Check which types of normalized scores exist
        normalized_scores = retriever.get('normalized_scores', {})
        if normalized_scores.get('dense') is not None:
            retriever_dense.add(cwe_id)
        if normalized_scores.get('sparse') is not None:
            retriever_sparse.add(cwe_id)
        if normalized_scores.get('graph') is not None:
            retriever_graph.add(cwe_id)
    
    collected_cwes = {
        'primary_cwes': set(cve_data.get('primary_cwes', [])),
        'secondary_cwes': set(cve_data.get('secondary_cwes', [])),
        'consensus_cwe': {cve_data.get('consensus_cwe')} if cve_data.get('consensus_cwe') else set(),
        'top_similar_cwes': top_similar_cwes,
        'retrievers': set(),
        'agents_resolution': set(),
        'agents_analysis': set(),
        'agents_criticism': set(),
        'retriever_dense': retriever_dense,
        'retriever_sparse': retriever_sparse,
        'retriever_graph': retriever_graph
    }
    
    # Extract CWEs from retrievers
    for retriever in cve_data.get('retrievers', []):
        cwe_id = retriever.get('cwe_id')
        if cwe_id:
            collected_cwes['retrievers'].add(cwe_id)
    
    # Extract CWEs from agents
    for agent_cwe, agent_data in cve_data.get('agents', {}).items():
        if agent_data.get('resolution', {}).get('name'):
            collected_cwes['agents_resolution'].add(agent_cwe)
        if agent_data.get('analysis', {}).get('name'):
            collected_cwes['agents_analysis'].add(agent_cwe)
        if agent_data.get('criticism', {}).get('name'):
            collected_cwes['agents_criticism'].add(agent_cwe)
    
    # Create a set of all unique CWEs
    all_cwes = set()
    for cwe_set in collected_cwes.values():
        all_cwes.update(cwe_set)
    
    collected_cwes['all_cwes'] = all_cwes
    return collected_cwes


def compare_results(json_results: Dict[str, Any], benchmark_data: Dict[str, Set[str]]) -> List[Dict[str, Any]]:
    """Compare JSON results with benchmark data and generate comparison report."""
    comparison_results = []
    
    # Process each CVE in the JSON results
    for cve_id, cve_data in json_results.items():
        # Include only CVEs that are in both the results and benchmark
        if cve_id in benchmark_data:
            benchmark_cwes = benchmark_data[cve_id]
            collected_cwes = collect_cwes_from_results(cve_data)
            
            # Determine matches and mismatches
            matched_cwes = benchmark_cwes.intersection(collected_cwes['all_cwes'])
            benchmark_only = benchmark_cwes - collected_cwes['all_cwes']
            results_only = collected_cwes['all_cwes'] - benchmark_cwes
            
            # Create a mapping of where each CWE appears in the results
            cwe_sources = {}
            for cwe in collected_cwes['all_cwes']:
                sources = []
                for source, cwe_set in collected_cwes.items():
                    if source != 'all_cwes' and cwe in cwe_set:
                        sources.append(source)
                cwe_sources[cwe] = sources
            
            comparison_results.append({
                'cve_id': cve_id,
                'benchmark_cwes': benchmark_cwes,
                'result_cwes': collected_cwes,
                'matched_cwes': matched_cwes,
                'benchmark_only': benchmark_only,
                'results_only': results_only,
                'cwe_sources': cwe_sources
            })
        # Skip CVEs that are in results but not in benchmark
        else:
            collected_cwes = collect_cwes_from_results(cve_data)
            comparison_results.append({
                'cve_id': cve_id,
                'benchmark_cwes': set(),
                'result_cwes': collected_cwes,
                'matched_cwes': set(),
                'benchmark_only': set(),
                'results_only': collected_cwes['all_cwes'],
                'cwe_sources': {cwe: [source for source, cwe_set in collected_cwes.items() 
                                   if source != 'all_cwes' and cwe in cwe_set] 
                            for cwe in collected_cwes['all_cwes']},
                'missing_in_benchmark': True
            })
    
    return comparison_results


def format_cwe_with_source(cwe: str, sources: List[str], is_match: bool) -> str:
    """Format a CWE string with its sources and highlight if it's a match."""
    source_str = ", ".join(sources)
    if is_match:
        return f"**{cwe}** ({source_str})"
    else:
        return f"{cwe} ({source_str})"


def print_comparison_report(comparison_results: List[Dict[str, Any]]) -> None:
    """Print a formatted comparison report."""
    print("\n# CWE Benchmark Comparison Report\n")
    
    # Sort results by CVE ID
    sorted_results = sorted(comparison_results, key=lambda x: x['cve_id'])
    
    for result in sorted_results:
        cve_id = result['cve_id']
        print(f"\n## {cve_id}\n")
        
        # Check if CVE is missing in benchmark
        if result.get('missing_in_benchmark', False):
            print("**Not found in benchmark**\n")
            print("### Results CWEs:")
            for cwe in sorted(result['results_only']):
                sources = result['cwe_sources'][cwe]
                print(f"- {cwe} ({', '.join(sources)})")
            continue
        
        # Print matched CWEs
        if result['matched_cwes']:
            print("### Matched CWEs:")
            for cwe in sorted(result['matched_cwes']):
                sources = result['cwe_sources'][cwe]
                print(f"- **{cwe}** ({', '.join(sources)})")
        
        # Print benchmark-only CWEs
        if result['benchmark_only']:
            print("\n### In Benchmark Only:")
            for cwe in sorted(result['benchmark_only']):
                print(f"- {cwe}")
        
        # Print results-only CWEs
        if result['results_only']:
            print("\n### In Results Only:")
            for cwe in sorted(result['results_only']):
                sources = result['cwe_sources'][cwe]
                print(f"- {cwe} ({', '.join(sources)})")
        
        # Print detailed breakdown of CWEs in results
        print("\n### Detailed CWE Sources:")
        
        # Resolution agents
        if result['result_cwes']['agents_resolution']:
            print("\n#### Agents Resolution:")
            for cwe in sorted(result['result_cwes']['agents_resolution']):
                is_match = cwe in result['matched_cwes']
                if is_match:
                    print(f"- **{cwe}**")
                else:
                    print(f"- {cwe}")
        
        # Analysis agents
        if result['result_cwes']['agents_analysis']:
            print("\n#### Agents Analysis:")
            for cwe in sorted(result['result_cwes']['agents_analysis']):
                is_match = cwe in result['matched_cwes']
                if is_match:
                    print(f"- **{cwe}**")
                else:
                    print(f"- {cwe}")
        
        # Criticism agents
        if result['result_cwes']['agents_criticism']:
            print("\n#### Agents Criticism:")
            for cwe in sorted(result['result_cwes']['agents_criticism']):
                is_match = cwe in result['matched_cwes']
                if is_match:
                    print(f"- **{cwe}**")
                else:
                    print(f"- {cwe}")
        
        # Primary CWEs
        if result['result_cwes']['primary_cwes']:
            print("\n#### Primary CWEs:")
            for cwe in sorted(result['result_cwes']['primary_cwes']):
                is_match = cwe in result['matched_cwes']
                if is_match:
                    print(f"- **{cwe}**")
                else:
                    print(f"- {cwe}")
        
        # Secondary CWEs
        if result['result_cwes']['secondary_cwes']:
            print("\n#### Secondary CWEs:")
            for cwe in sorted(result['result_cwes']['secondary_cwes']):
                is_match = cwe in result['matched_cwes']
                if is_match:
                    print(f"- **{cwe}**")
                else:
                    print(f"- {cwe}")
        
        # Consensus CWE
        if result['result_cwes']['consensus_cwe']:
            print("\n#### Consensus CWE:")
            for cwe in sorted(result['result_cwes']['consensus_cwe']):
                if cwe:  # Skip empty strings
                    is_match = cwe in result['matched_cwes']
                    if is_match:
                        print(f"- **{cwe}**")
                    else:
                        print(f"- {cwe}")
        
        # Top Similar CWEs
        if result['result_cwes']['top_similar_cwes']:
            print("\n#### Top Similar CWEs:")
            for cwe in sorted(result['result_cwes']['top_similar_cwes']):
                is_match = cwe in result['matched_cwes']
                if is_match:
                    print(f"- **{cwe}**")
                else:
                    print(f"- {cwe}")
        
        # Retrievers
        if result['result_cwes']['retrievers']:
            print("\n#### Retrievers:")
            for cwe in sorted(result['result_cwes']['retrievers']):
                is_match = cwe in result['matched_cwes']
                if is_match:
                    print(f"- **{cwe}**")
                else:
                    print(f"- {cwe}")



def main():
    parser = argparse.ArgumentParser(description='Compare CWE assignments with benchmark data')
    parser.add_argument('--results', required=True, help='Path to the JSON results file')
    parser.add_argument('--benchmark', required=True, help='Path to the CSV benchmark file')
    parser.add_argument('--output', help='Optional output file for the comparison report')
    parser.add_argument('--csv', help='Output CSV file with CWE sources per CVE')
    
    args = parser.parse_args()
    
    # Load the data
    json_results = load_json_results(args.results)
    benchmark_data = load_csv_benchmark(args.benchmark)
    
    # Compare the results
    comparison_results = compare_results(json_results, benchmark_data)
    
    # Output the comparison report
    if args.output:
        with open(args.output, 'w') as f:
            sys.stdout = f
            print_comparison_report(comparison_results)
            sys.stdout = sys.__stdout__
    else:
        print_comparison_report(comparison_results)
    
    # Generate CSV output if requested
    if args.csv:
        generate_csv_report(comparison_results, json_results, args.csv)
    
    # Print summary statistics
    total_cves = len(json_results)
    cves_in_benchmark = sum(1 for result in comparison_results if result.get('cve_id') in benchmark_data)
    cves_with_matches = sum(1 for result in comparison_results if result.get('matched_cwes'))
    
    # Calculate benchmark CWEs only for CVEs that are in the results
    total_benchmark_cwes = sum(len(benchmark_data[cve_id]) for cve_id in json_results if cve_id in benchmark_data)
    total_matched_cwes = sum(len(result['matched_cwes']) for result in comparison_results)
    
    print("\n\n# Summary Statistics")
    print(f"- Total CVEs in results: {total_cves}")
    print(f"- CVEs in both results and benchmark: {cves_in_benchmark} ({(cves_in_benchmark/total_cves)*100:.2f}% of results)")
    print(f"- CVEs with at least one CWE match: {cves_with_matches} ({(cves_with_matches/cves_in_benchmark)*100:.2f}% of CVEs in benchmark)")
    print(f"- Total benchmark CWEs for results CVEs: {total_benchmark_cwes}")
    print(f"- Total matched CWEs: {total_matched_cwes} ({(total_matched_cwes/total_benchmark_cwes)*100:.2f}% of benchmark CWEs)")
    
    # Calculate source-specific match statistics
    sources = [
        'agents_resolution', 
        'agents_analysis', 
        'agents_criticism',
        'primary_cwes', 
        'secondary_cwes', 
        'consensus_cwe', 
        'top_similar_cwes', 
        'retrievers'
    ]
    
    print("\n## Matches by Source")
    
    source_matches = defaultdict(int)
    source_totals = defaultdict(int)
    source_cves = defaultdict(set)
    
    for result in comparison_results:
        cve_id = result.get('cve_id')
        # Skip CVEs not in benchmark
        if cve_id not in benchmark_data:
            continue
            
        for source in sources:
            # Count total CWEs per source
            source_cwes = result['result_cwes'].get(source, set())
            source_totals[source] += len(source_cwes)
            
            # Count matched CWEs per source
            matched_from_source = source_cwes.intersection(result['matched_cwes'])
            source_matches[source] += len(matched_from_source)
            
            # Track CVEs with matches from this source
            if matched_from_source:
                source_cves[source].add(cve_id)
    
    # Sort sources by number of matches (highest first)
    sorted_sources = sorted(sources, key=lambda s: source_matches[s], reverse=True)
    
    for source in sorted_sources:
        total = source_totals[source]
        matches = source_matches[source]
        cves_count = len(source_cves[source])
        
        if total > 0:
            match_percent = (matches / total) * 100
        else:
            match_percent = 0
            
        if cves_in_benchmark > 0:
            cve_percent = (cves_count / cves_in_benchmark) * 100
        else:
            cve_percent = 0
            
        print(f"### {source.replace('_', ' ').title()}")
        print(f"- Matches: {matches} of {total} ({match_percent:.2f}%)")
        print(f"- CVEs with matches: {cves_count} ({cve_percent:.2f}% of CVEs in benchmark)")




if __name__ == '__main__':
    main()