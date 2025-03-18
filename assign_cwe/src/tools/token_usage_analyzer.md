# Token Usage Analyzer

A standalone tool for analyzing token usage logs from the CVE processing pipeline, generating detailed reports on usage and cost metrics across different stages of processing.

## Overview

The Token Usage Analyzer processes CSV logs of token usage to provide comprehensive statistics and cost estimates. It helps security researchers and developers understand the computational resource requirements and associated costs of running the CWE analysis pipeline.

## Features

- **Comprehensive Statistics**: Calculates detailed metrics for token usage across all processing stages
- **Cost Estimation**: Estimates token costs based on current LLM pricing
- **Multiple Report Formats**: Generates JSON, Markdown, and CSV reports
- **Per-CVE Analysis**: Breaks down usage statistics by individual CVEs
- **Per-Stage Analysis**: Provides insights into token usage at each pipeline stage
- **Top Cost Analysis**: Identifies the most expensive CVEs to process


## Usage

```bash
python token_usage_analyzer.py <path_to_token_usage.csv> [--output-dir OUTPUT_DIR]
```

Examples

```bash
python ./assign_cwe/src/tools/token_usage_analyzer.py ../cwe_assign_reports/token_usage.csv
```


### Arguments

| Argument | Description |
|----------|-------------|
| `csv_path` | Path to the token_usage.csv file (required) |
| `--output-dir`, `-o` | Directory to save reports (defaults to CSV directory) |

### Examples

Basic usage:
```bash
python token_usage_analyzer.py ../cwe_assign_reports/token_usage.csv
```

Specify output directory:
```bash
python token_usage_analyzer.py ../cwe_assign_reports/token_usage.csv --output-dir ./reports
```

## Input Format

The script expects a CSV file with the following columns:
- `cve_id`: CVE identifier
- `stage`: Processing stage (e.g., "retriever", "analyzer", "critic", "resolver")
- `input_length`: Number of characters in the input
- `input_words`: Number of words in the input
- `output_length`: Number of characters in the output
- `output_words`: Number of words in the output
- `timestamp`: When the processing occurred

## Output Files

The tool generates the following report files:

- `token_usage_summary.json` - Complete data in JSON format
- `token_usage_summary.md` - Human-readable Markdown report with tables and statistics
- `token_usage_per_cve.csv` - CSV summary of token usage and costs per CVE
- `token_usage_per_stage.csv` - CSV summary of token usage and costs per processing stage

## Output Structure

### JSON Output Structure

```json
{
  "total_entries": 123,
  "by_stage": {
    "retriever": {
      "count": 45,
      "total_input_length": 123456,
      "total_input_words": 20000,
      "avg_input_length": 2743.5,
      "avg_input_words": 444.4,
      ...
    },
    ...
  },
  "overall": {
    "total_input_length": 500000,
    "total_input_words": 80000,
    ...
  },
  "per_cve": {
    "CVE-2021-12345": {
      "total_input_length": 12000,
      "total_input_words": 2000,
      ...
    },
    ...
  },
  "token_estimates": {
    "total_input_tokens": 106667,
    "total_output_tokens": 53333,
    "estimated_input_cost": 10.67,
    "estimated_output_cost": 21.33,
    "estimated_total_cost": 32.00
  }
}
```

### Markdown Report

The markdown report includes:
- Overall statistics for the entire pipeline
- Token estimates and costs
- Average/min/max cost per CVE
- Detailed breakdown by processing stage
- List of the top 10 most expensive CVEs to process

## Cost Estimation

The tool uses the following assumptions for cost estimation:
- Words to tokens ratio: 0.75 (1 token ≈ 0.75 words)
- Input cost: $0.10 per 1K tokens
- Output cost: $0.40 per 1K tokens

These values are based on Gemini model pricing as of March 2025 but can be adjusted in the code if needed.

## Integration with CWE Analysis Toolkit

This tool is designed to complement the CWE Analysis Toolkit, providing insights into the computational resources required by the CWE extraction and reporting pipeline.
