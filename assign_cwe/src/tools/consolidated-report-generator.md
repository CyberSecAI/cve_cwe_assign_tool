# CWE Consolidated Report Generator

A comprehensive tool that generates detailed markdown and JSON reports for CVE/CWE data by consolidating information from multiple sources.

## Overview

The CWE Consolidated Report Generator extracts and combines data from various analysis files, including:

1. **Extraction Data** (`cwe_results_extraction.json`) - Core CWE mappings from analysis, criticism, and resolution files
2. **Similar CVEs** (`CVE-XXXX-XXXXX_similar_cves.json`) - Information about similar CVEs and consensus CWEs
3. **Consolidated Results** (`CVE-XXXX-XXXXX_consolidated_results.json`) - Detailed retriever-based CWE analysis with scoring

The tool creates both per-CVE reports and a global summary report, available in Markdown and JSON formats.

## Features

- **Comprehensive Data Consolidation**: Merges data from multiple sources into a unified report structure
- **Normalized Score Extraction**: Extracts dense, sparse, and graph-based normalized scores for each CWE
- **Confidence Tracking**: Captures confidence scores per CWE across different file types (analysis, criticism, resolution)
- **Detailed Classification**: Shows how each CWE was classified (primary, secondary, tertiary, contributing)
- **Statistical Analysis**: Provides summary statistics on the most common CWEs across all CVEs
- **Multiple Output Formats**: Generates both human-readable markdown reports and machine-readable JSON files



## Usage

```bash
python consolidated-report-generator.py --input-dir /path/to/cve/data --output-dir /path/to/reports --formats all
```

Example

```bash
python ./assign_cwe/src/tools/consolidated-report-generator.py --input-dir ../cwe_assign_reports --formats all
```
### Arguments

- `--input-dir` (required): Directory containing the CVE data files
- `--output-dir` (optional): Directory to save reports (default: ./reports)
- `--formats` (optional): Output formats - `json`, `md`, or `all` (default: all)

## Report Structure

### Individual CVE Reports

Each CVE gets a dedicated directory with detailed reports containing:

1. **Summary** - High-level overview of the CVE and its primary CWEs
2. **Extraction Data** - CWEs extracted from analysis, criticism, and resolution files
3. **Similar CVEs Analysis** - Information about similar vulnerabilities and consensus CWEs
4. **Consolidated Results** - Detailed retriever-based CWE analysis with scores
5. **Source Files** - Information about the source files analyzed
6. **CWE Confidence by Source Type** - Confidence scores for each CWE across different file types

### Summary Report

The summary report provides a global overview of all CVEs:

1. **CVE Summary Table** - Quick reference for all CVEs and their key attributes
2. **CWE Statistics** - Most common primary and consensus CWEs
3. **CWE Confidence by Source Type** - Tables showing confidence scores across different analyses
4. **Consolidated Results by CVE** - Normalized scores from retrievers for each CVE

## Output Directory Structure

```
reports/
├── summary_report.md
├── summary_report.json
└── cve_reports/
    ├── CVE-2021-21381/
    │   ├── CVE-2021-21381_report.md
    │   └── CVE-2021-21381_report.json
    ├── CVE-2021-40539/
    │   ├── CVE-2021-40539_report.md
    │   └── CVE-2021-40539_report.json
    └── ...
```

## JSON Structure

The summary JSON file contains:
- Primary, secondary, tertiary, and contributing CWEs for each CVE
- Consensus CWE and similar CVE information
- Full retriever results with normalized scores
- Detailed confidence information per CWE per file type

Example:
```json
{
  "CVE-2021-21381": {
    "primary_cwes": ["CWE-184", "CWE-22"],
    "secondary_cwes": ["CWE-22"],
    "consensus_cwe": "",
    "top_similar_cwes": [],
    "source_files": 2,
    "retrievers": [
      {
        "cwe_id": "CWE-258",
        "name": "Empty Password in Configuration File",
        "abstraction": "Variant",
        "score": 0.8258525308708515,
        "normalized_scores": {
          "dense": 0.7756104082235742,
          "sparse": 0.5262846631104398,
          "graph": 0.5746733943916607
        }
      },
      ... additional CWEs ...
    ],
    "agents": {
      "CWE-184": {
        "resolution": {
          "confidence": 0.8,
          "notes": "Acceptable-Use, Primary weakness.",
          "name": "Incomplete List of Disallowed Inputs",
          "classification": "primary"
        },
        "analysis": {
          "confidence": 0.75,
          "notes": "Acceptable-Use",
          "name": "Incomplete List of Disallowed Inputs",
          "classification": "primary"
        }
      },
      ... additional confidence data ...
    }
  },
  ... additional CVEs ...
}
```

## Use Cases

- **Vulnerability Research**: Compare and analyze CWE mappings across similar vulnerabilities
- **Data Analysis**: Perform statistical analysis on CWE confidence and classification patterns
- **Report Generation**: Generate comprehensive reports for vulnerability management
- **CWE Validation**: Compare human-assigned CWEs with those suggested by retrieval systems


