# CWE Extraction Tool

A Python tool that extracts CWE information and classifications from security analysis files, including confidence scores and metadata.

## Overview

The CWE Extraction Tool analyzes security assessment files (analysis, criticism, and resolution markdown files) to extract Common Weakness Enumeration (CWE) classifications. It identifies primary, secondary, tertiary, and contributing CWEs, along with their confidence scores, names, and notes.

## Features

- **Multi-file support**: Processes analysis, criticism, and resolution markdown files
- **Classification detection**: Automatically identifies primary, secondary, tertiary, and contributing CWEs
- **Metadata extraction**: Pulls confidence scores, CWE names, and analysis notes
- **Comprehensive output**: Generates JSON, markdown, and text reports
- **Source tracking**: Maintains provenance of each CWE classification
- **Recursive directory processing**: Can process entire directory structures


## Usage

```bash
python cwe_extraction.py --input INPUT [--output-dir OUTPUT_DIR] [--format {text,json,md,all}] [--no-save] [--no-recursive]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `--input` | Input file, directory, or CVE ID (e.g., CVE-2022-1148) |
| `--output-dir` | Output directory (defaults to input directory) |
| `--format` | Output format: text, json, md, or all (default: all) |
| `--no-save` | Do not save results to files (display on console only) |
| `--no-recursive` | Do not process directories recursively |

### Examples

Process a single file:
```bash
python cwe_extraction.py --input CVE-2022-1148_analysis.md
```

Process a specific CVE directory:
```bash
python cwe_extraction.py --input CVE-2022-1148
```

Process a directory containing multiple CVE directories:
```bash
python cwe_extraction.py --input ./cwe_assign_reports
```

Generate only JSON output:
```bash
python cwe_extraction.py --input CVE-2022-1148 --format json
```

Output to a specific directory:
```bash
python cwe_extraction.py --input CVE-2022-1148 --output-dir ./results
```

## Output Files

The tool generates one or more of the following files depending on the format option:

- `cwe_results_extraction.json` - Structured data in JSON format
- `cwe_results_extraction.md` - Formatted markdown report with tables
- `cwe_results_extraction.txt` - Plain text summary

## Output Structure

### JSON Output Structure

```json
{
  "CVE-YYYY-XXXXX": {
    "primary": ["CWE-XXX", "CWE-YYY"],
    "secondary": ["CWE-ZZZ"],
    "tertiary": [],
    "contributing": [],
    "metadata": {
      "CWE-XXX": {
        "confidence": 0.95,
        "notes": "Primary weakness",
        "name": "CWE Name"
      },
      "CWE-YYY": {
        "confidence": 0.8,
        "notes": "Also applicable",
        "name": "Another CWE Name"
      }
    },
    "sources": [
      {
        "file": "path/to/CVE-YYYY-XXXXX_analysis.md",
        "file_type": "analysis",
        "primary": ["CWE-XXX"],
        "secondary": ["CWE-ZZZ"],
        "tertiary": [],
        "contributing": [],
        "metadata": {...}
      },
      {
        "file": "path/to/CVE-YYYY-XXXXX_resolution.md",
        "file_type": "resolution",
        "primary": ["CWE-XXX", "CWE-YYY"],
        "secondary": [],
        "tertiary": [],
        "contributing": [],
        "metadata": {...}
      }
    ]
  }
}
```

### Markdown Report Structure

The markdown report includes:
- Summary of primary, secondary, tertiary, and contributing CWEs
- Metadata for each CWE including confidence and notes
- Source file information
- Detailed metadata per source file

## Supported File Types

The tool can process the following file types:

- `*_analysis.md` - Analysis files
- `*_criticism.md` - Criticism files
- `*_resolution.md` - Resolution files


## Integration with Other Tools

This tool is often used as the first step in a CWE analysis pipeline, producing input for other tools like the CWE Consolidated Report Generator.

