#!/bin/sh

# Create CWE assignment reports
#python ./assign_cwe/src/main.py --csv ./data_in/cves.csv --output-dir ../cwe_assign_reports
python ./assign_cwe/src/main.py --csv data_in/top25-mitre-mapping-analysis-2023-public_with_cve_descriptions_2000.csv --output-dir ../cwe_assign_reports


# Determine token usage from previous step
python ./assign_cwe/src/tools/token_usage_analyzer.py ../cwe_assign_reports/token_usage.csv

# Extract results from agents
python ./assign_cwe/src/tools/cwe_results_analysis.py --input ../cwe_assign_reports/

# Consolidate all results. Creates a local reports dir
python ./assign_cwe/src/tools/consolidated-report-generator.py --input-dir ../cwe_assign_reports --formats all

#Count CVE dirs
ls -l  ../cwe_assign_reports | grep '^d' | wc -l

# Compare to benchmark results
python ./assign_cwe/src/tools/benchmark.py --results reports/summary_report.json --benchmark ../cwe_top25_all/data_out/merged_mitre_mapping_analysis.csv --output ./reports/benchmark_report.md

