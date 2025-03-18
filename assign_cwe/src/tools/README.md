# CWE Analysis Toolkit

A comprehensive toolkit for extracting, analyzing, and generating reports on Common Weakness Enumeration (CWE) classifications from security assessment files.

## Overview

The CWE Analysis Toolkit consists of three main tools that work together to provide a complete CWE analysis pipeline:

1. **CWE Extraction Tool** - Extracts raw CWE data from analysis, criticism, and resolution files
2. **CWE Consolidated Report Generator** - Processes the extracted data and similar CVEs information to create comprehensive reports
3. **Token Usage Analyzer** - Analyzes token usage and costs across the processing pipeline

These tools help security analysts track how CWE classifications evolve throughout the analysis process, consolidate information from multiple sources into unified reports, and understand the computational resources required by the pipeline.

## Workflow

![CWE Analysis Workflow](workflow.png)

1. First, run the **CWE Extraction Tool** to extract CWE classifications from raw analysis files
2. Then, run the **CWE Consolidated Report Generator** to combine this data with similar CVEs information and generate comprehensive reports
3. Optionally, run the **Token Usage Analyzer** to assess token usage and costs throughout the pipeline


## Tools

### 1. CWE Extraction Tool

Extracts CWE data from raw security assessment files.

```bash
python cwe_extraction.py --input ./cwe_assign_reports
```

#### Key Features
- Processes analysis, criticism, and resolution markdown files
- Identifies primary, secondary, tertiary, and contributing CWEs
- Extracts confidence scores, names, and notes
- Generates `cwe_results_extraction.json` (required for the Report Generator)

[View CWE Extraction Tool README](./cwe_results_analysis.md)

### 2. CWE Consolidated Report Generator

Generates comprehensive reports by consolidating extracted CWE data with similar CVEs information.

```bash
python consolidated-report-generator.py --input-dir ./data --output-dir ./reports
```

#### Key Features
- Combines data from multiple sources:
  - Extraction results (`cwe_results_extraction.json`)
  - Similar CVEs data (`*_similar_cves.json`)
  - Consolidated results (`*_consolidated_results.json`)
- Extracts normalized scores (dense, sparse, graph)
- Tracks confidence per file type (analysis, criticism, resolution)
- Generates per-CVE reports and a global summary report

[View Consolidated Report Generator README](./consolidated-report-generator.md)


### 3. Token Usage Analyzer

Analyzes token usage logs to provide statistics and cost estimates for the pipeline.

```bash
python token_usage_analyzer.py ./cwe_assign_reports/token_usage.csv
```

#### Key Features
- Calculates detailed metrics for token usage across all processing stages
- Estimates token costs based on current LLM pricing
- Generates JSON, Markdown, and CSV reports
- Provides per-CVE and per-stage usage breakdown
- Identifies the most expensive CVEs to process

[View Token Usage Analyzer README](./token_usage_analyzer.md)


## Example Usage

### Complete Pipeline

```bash
# Step 1: Extract CWE data from raw files
python cwe_extraction.py --input ./cwe_assign_reports --output-dir ./data

# Step 2: Generate consolidated reports
python consolidated-report-generator.py --input-dir ./data --output-dir ./reports --formats all

# Step 3: Analyze token usage (if token_usage.csv is available)
python token_usage_analyzer.py ./cwe_assign_reports/token_usage.csv --output-dir ./reports
```

### Working with a Single CVE

```bash
# Step 1: Extract CWE data for a specific CVE
python cwe_extraction.py --input CVE-2022-1148 --output-dir ./data

# Step 2: Generate consolidated report for that CVE
python consolidated-report-generator.py --input-dir ./data --output-dir ./reports
```

## Output

After running the complete toolkit, you'll have:

```
reports/
├── summary_report.md              # Global CWE summary across all CVEs
├── summary_report.json            # Structured CWE summary data
├── token_usage_summary.md         # Token usage statistics report
├── token_usage_summary.json       # Complete token usage data
├── token_usage_per_cve.csv        # CSV of token usage by CVE
├── token_usage_per_stage.csv      # CSV of token usage by stage
└── cve_reports/                   # Per-CVE detailed reports
    ├── CVE-2021-21381/
    │   ├── CVE-2021-21381_report.md
    │   └── CVE-2021-21381_report.json
    ├── CVE-2021-40539/
    │   ├── CVE-2021-40539_report.md
    │   └── CVE-2021-40539_report.json
    └── ...
```
