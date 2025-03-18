#!/usr/bin/env python3
"""
CWE Extraction Script

This script extracts CWE information from security analysis files
including _analysis.md, _criticism.md, and _resolution.md files.
It captures classification (primary/secondary/tertiary/contributing)
and additional metadata like confidence scores and notes.
"""



import re
import os
import json
from typing import Dict, List, Tuple, Set, Optional


def extract_cves_from_file(file_path: str) -> Dict[str, Dict[str, List[str]]]:
    """
    Extract CVEs from supported files (_analysis.md, _criticism.md, _resolution.md)
    
    Args:
        file_path: Path to the file to extract from
        
    Returns:
        Dict mapping CVE IDs to primary/secondary/tertiary/contributing CWEs
    """
    # Determine file type from name
    file_name = os.path.basename(file_path)
    file_type = None
    
    if file_name.endswith("_analysis.md"):
        file_type = "analysis"
    elif file_name.endswith("_criticism.md"):
        file_type = "criticism"
    elif file_name.endswith("_resolution.md"):
        file_type = "resolution"

    
    if file_type is None:
        return {}
    
    # Process JSON files differently
    if file_type == "retriever":
        return extract_from_retriever_json(file_path)
    
    # For markdown files, read content and process
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Extract CVE ID from filename
    cve_id_match = re.search(r'(CVE-\d{4}-\d+)', file_name)
    file_cve_id = cve_id_match.group(1) if cve_id_match else None
    
    return extract_from_markdown(content, file_type, file_cve_id, file_path)


def extract_from_retriever_json(file_path: str) -> Dict[str, Dict[str, List[str]]]:
    """
    Extract CVEs from retriever report JSON files.
    
    Args:
        file_path: Path to the JSON file
        
    Returns:
        Dict with CVE and CWE information
    """
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Extract CVE ID from filename
        file_name = os.path.basename(file_path)
        cve_id_match = re.search(r'(CVE-\d{4}-\d+)', file_name)
        cve_id = cve_id_match.group(1) if cve_id_match else "Unknown-CVE"
        
        # Results structure with source information
        results = {
            cve_id: {
                "primary": [],
                "secondary": [],
                "tertiary": [],
                "contributing": [],
                "metadata": {},
                "source_file": file_path,
                "file_type": "retriever"
            }
        }
        
        # Look for results_table or results in the JSON
        cwe_candidates = []
        if 'results_table' in data:
            cwe_candidates = data['results_table']
        elif 'results' in data:
            cwe_candidates = data['results']
        
        # Process found candidates (assuming top 3 are considered primary)
        for i, candidate in enumerate(cwe_candidates[:3]):
            cwe_id = None
            # Handle different formats
            if 'cwe_id' in candidate:
                cwe_id = candidate['cwe_id']
            elif 'metadata' in candidate and 'doc_id' in candidate['metadata']:
                cwe_id = candidate['metadata']['doc_id']
            
            if cwe_id:
                if not cwe_id.startswith("CWE-"):
                    cwe_id = f"CWE-{cwe_id}"
                results[cve_id]["primary"].append(cwe_id)
        
        return results
    
    except Exception as e:
        print(f"Error processing retriever JSON {file_path}: {e}")
        return {}

def extract_from_markdown(content: str, file_type: str, file_cve_id: Optional[str], file_path: str) -> Dict[str, Dict[str, List[str]]]:
    """
    Extract CVEs from markdown files.
    
    Args:
        content: File content
        file_type: Type of file (analysis, criticism, resolution)
        file_cve_id: CVE ID extracted from filename, if any
        file_path: Original file path for reference
        
    Returns:
        Dict with extracted information
    """
    # Extract each CVE block using regex - find "Final Resolution for CVE-XXXX-XXXXX" sections
    results = {}
    
    # Pattern for CVE blocks varies by file type
    if file_type == "resolution":
        cve_pattern = r'# Final Resolution for (CVE-\d{4}-\d+).*?(?=# Final Resolution for|\Z)'
    elif file_type == "criticism":
        cve_pattern = r'# Criticism for (CVE-\d{4}-\d+).*?(?=# Criticism for|\Z)'
    else:
        # For analysis and other types, use a more general pattern
        cve_pattern = r'# (?:Analysis|Criticism|Final Analysis) (?:of|for) (CVE-\d{4}-\d+).*?(?=# (?:Analysis|Criticism|Final Analysis)|\Z)'
    
    cve_blocks = list(re.finditer(cve_pattern, content, re.DOTALL))
    
    # If no blocks found with the specific patterns, look for a single CVE document
    if not cve_blocks and file_cve_id:
        # Treat the whole document as one block for the file_cve_id
        # First check if there's a table anywhere in the document
        table_lines = []
        for line in content.split('\n'):
            if line.strip().startswith('|') and line.strip().endswith('|'):
                table_lines.append(line)
        
        if table_lines:
            # Extract CWEs from the table
            cwe_ids = extract_cwe_ids(content)  # Extract from the whole content
            classifications = classify_cwes(content, cwe_ids)  # Analyze the whole content
            
            # Add source information
            classifications["source_file"] = file_path
            classifications["file_type"] = file_type
            
            results[file_cve_id] = classifications
            return results
            
        # If no table, try to find a summary section
        summary_pattern = r'# Summary.*?(?=## |\Z)'
        summary_match = re.search(summary_pattern, content, re.DOTALL)
        
        if summary_match:
            summary_section = summary_match.group(0)
            cwe_ids = extract_cwe_ids(summary_section)
            classifications = classify_cwes(summary_section, cwe_ids)
            
            # Add source information
            classifications["source_file"] = file_path
            classifications["file_type"] = file_type
            
            results[file_cve_id] = classifications
        elif "# Summary" in content:
            # If there's a Summary heading but no section was found, try a more lenient approach
            # This handles cases where the Summary section isn't followed by another heading
            summary_section = content[content.find("# Summary"):]
            cwe_ids = extract_cwe_ids(summary_section)
            classifications = classify_cwes(summary_section, cwe_ids)
            
            # Add source information
            classifications["source_file"] = file_path
            classifications["file_type"] = file_type
            
            results[file_cve_id] = classifications
        else:
            # If no summary section, try to extract from the entire content
            cwe_ids = extract_cwe_ids(content)
            if cwe_ids:  # Only process if we found CWE IDs
                classifications = classify_cwes(content, cwe_ids)
                
                # Add source information
                classifications["source_file"] = file_path
                classifications["file_type"] = file_type
                
                results[file_cve_id] = classifications
        
        return results
    
    # Process each block found
    for block in cve_blocks:
        full_block = block.group(0)
        cve_id = block.group(1)
        
        # Look for a table in the block
        table_lines = []
        for line in full_block.split('\n'):
            if line.strip().startswith('|') and line.strip().endswith('|'):
                table_lines.append(line)
                
        if table_lines:
            # Extract CWEs directly from the block if it contains a table
            cwe_ids = extract_cwe_ids(full_block)
            classifications = classify_cwes(full_block, cwe_ids)
            
            # Add source information
            classifications["source_file"] = file_path
            classifications["file_type"] = file_type
            
            results[cve_id] = classifications
            continue
            
        # If no table, extract just the Summary section from each CVE block
        summary_pattern = r'# Summary.*?(?=## |\Z)'
        summary_match = re.search(summary_pattern, full_block, re.DOTALL)
        
        if not summary_match:
            # If no summary section found with the pattern, try to get everything after "# Summary"
            if "# Summary" in full_block:
                summary_start = full_block.find("# Summary")
                summary_section = full_block[summary_start:]
            else:
                # If no Summary section, use the entire block
                summary_section = full_block
        else:
            summary_section = summary_match.group(0)
        
        # Extract all CWE IDs from the summary section
        cwe_ids = extract_cwe_ids(summary_section)
        
        # Determine the primary/secondary/tertiary classification based on text analysis
        classifications = classify_cwes(summary_section, cwe_ids)
        
        # Add source information
        classifications["source_file"] = file_path
        classifications["file_type"] = file_type
        
        results[cve_id] = classifications
    
    return results

def extract_cwe_ids(text: str) -> Set[str]:
    """
    Extract all CWE IDs from the text.
    
    Args:
        text: The text to extract from
        
    Returns:
        Set of CWE IDs
    """
    # Match CWE-XXX patterns
    cwe_pattern = r'CWE-(\d+)'
    cwe_matches = re.findall(cwe_pattern, text)
    return {f"CWE-{cwe}" for cwe in cwe_matches}

def classify_cwes(text: str, cwe_ids: Set[str]) -> Dict[str, List[str]]:
    """
    Classify CWEs as primary, secondary, tertiary, or contributing based on text analysis.
    Also extract confidence values and mapping notes.
    
    Args:
        text: The text to analyze
        cwe_ids: Set of CWE IDs to classify
        
    Returns:
        Dictionary with primary, secondary, tertiary, and contributing CWEs and their metadata
    """
    # Initialize result structure
    classifications = {
        "primary": [],
        "secondary": [],
        "tertiary": [],
        "contributing": [],
        "metadata": {}  # Store confidence and notes for each CWE
    }
    
    # Split into lines for easier analysis
    lines = text.split("\n")
    
    # Check if there's a markdown table
    table_lines = []
    for line in lines:
        if line.strip().startswith('|') and line.strip().endswith('|'):
            table_lines.append(line)
    
    # Track if each CWE has been classified
    classified_cwes = set()
    
    # If table lines found, extract classifications from them
    if table_lines:
        # Find the headers to determine column positions
        header_line = None
        for line in table_lines:
            if ('CWE ID' in line or 
                'CWE-Vulnerability Mapping Notes' in line or 
                'CWE Name' in line or 
                'CWE Abstraction Level' in line or
                'CWE Vulnerability Mapping Label' in line):
                header_line = line
                break
        
        # If we found the header, parse the column positions
        column_indices = {}
        if header_line:
            headers = [h.strip() for h in header_line.split('|')[1:-1]]
            for i, header in enumerate(headers):
                if 'CWE ID' in header:
                    column_indices['cwe_id'] = i
                elif 'CWE Name' in header:
                    column_indices['name'] = i
                elif 'Confidence' in header:
                    column_indices['confidence'] = i
                elif 'CWE-Vulnerability Mapping Notes' in header or 'Mapping Notes' in header:
                    column_indices['notes'] = i
                elif 'CWE Abstraction Level' in header:
                    column_indices['abstraction'] = i
                elif 'CWE Vulnerability Mapping Label' in header:
                    column_indices['mapping_label'] = i
        
        # Process each row in the table
        for line in table_lines:
            # Skip header and separator lines
            if line.strip().startswith('|') and ('---' in line or 'CWE Name' in line or 'CWE ID' in line):
                continue
                
            # Extract CWE-ID from line directly
            line_cwe_matches = re.findall(r'CWE-(\d+)', line)
            
            if not line_cwe_matches:
                continue
                
            # Extract cell values from the row
            cells = [cell.strip() for cell in line.split('|')[1:-1]]
            if len(cells) < 2:  # Need at least CWE ID and one more field
                continue
                
            for cwe_num in line_cwe_matches:
                cwe_id = f"CWE-{cwe_num}"
                
                # Check for classification indicators
                cwe_class = "primary"  # Default to primary
                
                # Check if we have a mapping label column or notes column for classification
                if 'mapping_label' in column_indices and len(cells) > column_indices['mapping_label']:
                    label = cells[column_indices['mapping_label']].lower()
                    if 'primary' in label:
                        cwe_class = "primary"
                    elif 'secondary' in label:
                        cwe_class = "secondary"
                    elif 'tertiary' in label:
                        cwe_class = "tertiary"
                    elif 'contributing' in label:
                        cwe_class = "contributing"
                elif 'notes' in column_indices and len(cells) > column_indices['notes']:
                    notes = cells[column_indices['notes']].lower()
                    if 'primary' in notes:
                        cwe_class = "primary"
                    elif 'secondary' in notes:
                        cwe_class = "secondary"
                    elif 'tertiary' in notes:
                        cwe_class = "tertiary"
                    elif 'contributing' in notes:
                        cwe_class = "contributing"
                else:
                    # Fall back to checking the whole line
                    line_lower = line.lower()
                    if "primary" in line_lower or "primary cwe" in line_lower:
                        cwe_class = "primary"
                    elif "secondary" in line_lower or "secondary candidate" in line_lower:
                        cwe_class = "secondary"
                    elif "tertiary" in line_lower:
                        cwe_class = "tertiary"
                    elif "contributing" in line_lower:
                        cwe_class = "contributing"
                
                # Add to classification list if not already there
                if cwe_id not in classifications[cwe_class]:
                    classifications[cwe_class].append(cwe_id)
                
                # Extract metadata if column positions are known
                if column_indices and len(cells) > 0:
                    metadata = {}
                    
                    # Extract confidence
                    if 'confidence' in column_indices and len(cells) > column_indices['confidence']:
                        confidence_str = cells[column_indices['confidence']]
                        # Try to convert confidence to float
                        try:
                            # Extract numeric part from string like "0.85" or "85%"
                            confidence_match = re.search(r'(\d+\.?\d*)', confidence_str)
                            if confidence_match:
                                confidence_value = float(confidence_match.group(1))
                                # If it's a percentage (over 1), convert to decimal
                                if confidence_value > 1:
                                    confidence_value /= 100
                                metadata['confidence'] = confidence_value
                        except:
                            metadata['confidence'] = confidence_str
                    
                    # Extract notes
                    if 'notes' in column_indices and len(cells) > column_indices['notes']:
                        notes = cells[column_indices['notes']]
                        if notes and notes != "-":
                            metadata['notes'] = notes
                    
                    # Extract name
                    if 'name' in column_indices and len(cells) > column_indices['name']:
                        name = cells[column_indices['name']]
                        if name and name != "-":
                            metadata['name'] = name
                    
                    # Extract abstraction level
                    if 'abstraction' in column_indices and len(cells) > column_indices['abstraction']:
                        abstraction = cells[column_indices['abstraction']]
                        if abstraction and abstraction != "-":
                            metadata['abstraction'] = abstraction
                    
                    # Extract mapping label
                    if 'mapping_label' in column_indices and len(cells) > column_indices['mapping_label']:
                        mapping_label = cells[column_indices['mapping_label']]
                        if mapping_label and mapping_label != "-":
                            metadata['mapping_label'] = mapping_label
                    
                    # Store metadata for this CWE
                    if metadata:
                        classifications["metadata"][cwe_id] = metadata
                
                classified_cwes.add(cwe_id)
    
    # If no table was found or no CWEs were classified from the table,
    # try to classify based on textual analysis
    if not classified_cwes:
        for cwe_id in cwe_ids:
            # For each CWE, determine its classification from the text
            if "primary" in text.lower() + cwe_id.lower() or "primary cwe" in text.lower() + cwe_id.lower():
                classifications["primary"].append(cwe_id)
            elif "secondary" in text.lower() + cwe_id.lower() or "secondary candidate" in text.lower() + cwe_id.lower():
                classifications["secondary"].append(cwe_id)
            elif "tertiary" in text.lower() + cwe_id.lower():
                classifications["tertiary"].append(cwe_id)
            elif "contributing" in text.lower() + cwe_id.lower():
                classifications["contributing"].append(cwe_id)
            else:
                # Default to primary if no classification is found
                classifications["primary"].append(cwe_id)
            
            classified_cwes.add(cwe_id)
    
    # Handle any CWEs mentioned but not classified
    unclassified_cwes = cwe_ids - classified_cwes
    if unclassified_cwes:
        for cwe_id in unclassified_cwes:
            if cwe_id not in classifications["primary"]:
                classifications["primary"].append(cwe_id)
    
    # If no classifications at all, all CWEs are primary by default
    if sum(len(cwes) for class_type, cwes in classifications.items() if class_type != "metadata") == 0:
        classifications["primary"] = list(cwe_ids)
    
    return classifications


def determine_classification(line: str, cwe_id: str) -> str:
    """
    Determine CWE classification from a table line.
    
    Args:
        line: The table line containing the CWE
        cwe_id: The CWE ID to classify
        
    Returns:
        Classification (primary, secondary, tertiary, or contributing)
    """
    line_lower = line.lower()
    
    # Check for explicit classification terms
    if "primary" in line_lower:
        return "primary"
    
    if "secondary" in line_lower:
        return "secondary"
        
    if "tertiary" in line_lower:
        return "tertiary"
        
    if "contributing" in line_lower:
        return "contributing"
    
    # Look for classification in mappings
    if "primary cwe" in line_lower:
        return "primary"
        
    if "secondary cwe" in line_lower or "secondary candidate" in line_lower:
        return "secondary"
    
    # Default to primary
    return "primary"


def process_directory(directory_path: str) -> Dict[str, Dict[str, List[str]]]:
    """
    Process all supported files in a directory and its subdirectories.
    
    Args:
        directory_path: Path to the directory containing files
        
    Returns:
        Combined results for all files
    """
    combined_results = {}
    
    # Look for CVE directories (subdirectories matching CVE-YYYY-NNNNN pattern)
    cve_dirs = []
    cve_pattern = re.compile(r'CVE-\d{4}-\d+')
    
    # Check for direct CVE directories
    for item in os.listdir(directory_path):
        item_path = os.path.join(directory_path, item)
        if os.path.isdir(item_path) and cve_pattern.match(item):
            cve_dirs.append(item_path)
    
    # If no CVE directories found directly, assume this directory contains CVE files
    if not cve_dirs:
        cve_dirs = [directory_path]
    
    # Process each directory
    for cve_dir in cve_dirs:
        # Process files in this directory
        for filename in os.listdir(cve_dir):
            # Check for supported file types
            if (filename.endswith("_analysis.md") or 
                filename.endswith("_criticism.md") or 
                filename.endswith("_resolution.md") ):
                
                file_path = os.path.join(cve_dir, filename)
                file_results = extract_cves_from_file(file_path)
                
                # Merge with combined results
                for cve_id, classifications in file_results.items():
                    if cve_id not in combined_results:
                        combined_results[cve_id] = {
                            "primary": [],
                            "secondary": [],
                            "tertiary": [],
                            "contributing": [],
                            "metadata": {},  # Add metadata dictionary
                            "sources": []
                        }
                    
                    # Extract metadata before removing it from classifications
                    metadata = classifications.pop("metadata", {})
                    
                    # Add source info
                    source_info = {
                        "file": classifications.get("source_file", file_path),
                        "file_type": classifications.get("file_type", "unknown"),
                        "primary": classifications.get("primary", []),
                        "secondary": classifications.get("secondary", []),
                        "tertiary": classifications.get("tertiary", []),
                        "contributing": classifications.get("contributing", []),
                        "metadata": metadata  # Add metadata to source
                    }
                    combined_results[cve_id]["sources"].append(source_info)
                    
                    # Merge CWE classifications
                    for class_type in ["primary", "secondary", "tertiary", "contributing"]:
                        for cwe_id in classifications.get(class_type, []):
                            if cwe_id not in combined_results[cve_id][class_type]:
                                combined_results[cve_id][class_type].append(cwe_id)
                                
                            # Merge metadata for this CWE
                            if cwe_id in metadata:
                                if cwe_id not in combined_results[cve_id]["metadata"]:
                                    combined_results[cve_id]["metadata"][cwe_id] = metadata[cwe_id]
    
    return combined_results


def process_directory_recursive(directory_path: str) -> Dict[str, Dict[str, List[str]]]:
    """
    Process all supported files in a directory and its subdirectories recursively.
    
    Args:
        directory_path: Path to the directory containing files
        
    Returns:
        Combined results for all files
    """
    combined_results = {}
    cve_pattern = re.compile(r'CVE-\d{4}-\d+')
    
    # Walk through all subdirectories
    for root, dirs, files in os.walk(directory_path):
        # Check if current directory is a CVE directory or contains supported files
        process_current_dir = False
        dir_name = os.path.basename(root)
        
        # Process if directory name matches CVE pattern
        if cve_pattern.match(dir_name):
            process_current_dir = True
        else:
            # Process if directory contains supported files
            for file in files:
                if (file.endswith("_analysis.md") or 
                    file.endswith("_criticism.md") or 
                    file.endswith("_resolution.md")):
                    process_current_dir = True
                    break
        
        if process_current_dir:
            # Process files in this directory
            for filename in files:
                # Check for supported file types
                if (filename.endswith("_analysis.md") or 
                    filename.endswith("_criticism.md") or 
                    filename.endswith("_resolution.md") ):
                    
                    file_path = os.path.join(root, filename)
                    file_results = extract_cves_from_file(file_path)
                    
                    # Merge with combined results
                    for cve_id, classifications in file_results.items():
                        if cve_id not in combined_results:
                            combined_results[cve_id] = {
                                "primary": [],
                                "secondary": [],
                                "tertiary": [],
                                "contributing": [],
                                "metadata": {},  # Add metadata dictionary
                                "sources": []
                            }
                        
                        # Extract metadata before removing it from classifications
                        metadata = classifications.pop("metadata", {})
                        
                        # Add source info
                        source_info = {
                            "file": classifications.get("source_file", file_path),
                            "file_type": classifications.get("file_type", "unknown"),
                            "primary": classifications.get("primary", []),
                            "secondary": classifications.get("secondary", []),
                            "tertiary": classifications.get("tertiary", []),
                            "contributing": classifications.get("contributing", []),
                            "metadata": metadata  # Add metadata to source
                        }
                        combined_results[cve_id]["sources"].append(source_info)
                        
                        # Merge CWE classifications
                        for class_type in ["primary", "secondary", "tertiary", "contributing"]:
                            for cwe_id in classifications.get(class_type, []):
                                if cwe_id not in combined_results[cve_id][class_type]:
                                    combined_results[cve_id][class_type].append(cwe_id)
                                    
                                # Merge metadata for this CWE
                                if cwe_id in metadata:
                                    if cwe_id not in combined_results[cve_id]["metadata"]:
                                        combined_results[cve_id]["metadata"][cwe_id] = metadata[cwe_id]
    
    return combined_results


def save_markdown_report(results, output_file):
    """
    Save results to a markdown file.
    
    Args:
        results: Extracted CVE/CWE results
        output_file: Output file path
    """
    with open(output_file, 'w') as f:
        f.write("# CVE/CWE Extraction Results\n\n")
        f.write("This report shows CWEs extracted from Summary sections in analysis, criticism, and resolution files.\n\n")
        
        for cve_id, data in results.items():
            f.write(f"## {cve_id}\n\n")
            
            # Write consolidated CWEs as detailed lists with metadata
            for class_type in ["primary", "secondary", "tertiary", "contributing"]:
                if data[class_type]:
                    f.write(f"### {class_type.capitalize()} CWEs\n\n")
                    
                    # Create a table for CWEs with metadata
                    f.write("| CWE ID | Name | Confidence | Notes |\n")
                    f.write("|--------|------|------------|-------|\n")
                    
                    for cwe in data[class_type]:
                        # Get metadata if available
                        cwe_metadata = data.get("metadata", {}).get(cwe, {})
                        
                        name = cwe_metadata.get("name", "-")
                        confidence = cwe_metadata.get("confidence", "-")
                        notes = cwe_metadata.get("notes", "-")
                        
                        # Format confidence as string with 2 decimal places if it's a float
                        if isinstance(confidence, float):
                            confidence = f"{confidence:.2f}"
                        
                        f.write(f"| {cwe} | {name} | {confidence} | {notes} |\n")
                    
                    f.write("\n")
            
            # Write sources as tables
            f.write("### Source Files\n\n")
            f.write("| File | Type | Primary | Secondary | Tertiary | Contributing |\n")
            f.write("|------|------|---------|-----------|----------|-------------|\n")
            
            for source in data["sources"]:
                source_file = os.path.basename(source["file"])
                primary = ", ".join(source["primary"]) if source["primary"] else "-"
                secondary = ", ".join(source["secondary"]) if source["secondary"] else "-"
                tertiary = ", ".join(source["tertiary"]) if source["tertiary"] else "-"
                contributing = ", ".join(source["contributing"]) if source["contributing"] else "-"
                
                f.write(f"| {source_file} | {source['file_type']} | {primary} | {secondary} | {tertiary} | {contributing} |\n")
            
            # Add detailed source metadata section
            f.write("\n### Detailed Source Metadata\n\n")
            
            for source in data["sources"]:
                source_file = os.path.basename(source["file"])
                f.write(f"#### {source_file} ({source['file_type']})\n\n")
                
                # Show metadata for each CWE in this source
                source_metadata = source.get("metadata", {})
                if source_metadata:
                    f.write("| CWE ID | Name | Confidence | Notes |\n")
                    f.write("|--------|------|------------|-------|\n")
                    
                    for cwe_id, meta in source_metadata.items():
                        name = meta.get("name", "-")
                        confidence = meta.get("confidence", "-")
                        notes = meta.get("notes", "-")
                        
                        # Format confidence as string with 2 decimal places if it's a float
                        if isinstance(confidence, float):
                            confidence = f"{confidence:.2f}"
                        
                        f.write(f"| {cwe_id} | {name} | {confidence} | {notes} |\n")
                    
                    f.write("\n")
                else:
                    f.write("No metadata available for this source.\n\n")
            
            f.write("\n---\n\n")


def main():
    """Main function to run from command line."""
    import argparse
    import datetime
    
    parser = argparse.ArgumentParser(description='Extract CVEs from security analysis files')
    parser.add_argument('--input', required=True, help='Input file, directory, or CVE ID (e.g., CVE-2022-1148)')
    parser.add_argument('--output-dir', help='Output directory (defaults to input directory)')
    parser.add_argument('--format', choices=['text', 'json', 'md', 'all'], default='all', 
                        help='Output format (text, json, md, or all)')
    parser.add_argument('--no-save', action='store_true', help='Do not save results to files')
    parser.add_argument('--no-recursive', action='store_true', help='Do not process directories recursively')
    
    args = parser.parse_args()
    
    # Check if input is a CVE ID rather than a path
    cve_pattern = re.compile(r'^CVE-\d{4}-\d+$')
    is_cve_id = cve_pattern.match(args.input)
    
    if is_cve_id:
        # If the input is a CVE ID, look for that CVE directory in the current location
        input_path = os.path.join(".", args.input)
        if not os.path.exists(input_path):
            print(f"Error: CVE directory {args.input} not found in current directory.")
            return
    else:
        input_path = args.input
    
    # Determine output directory
    if args.output_dir:
        output_dir = args.output_dir
    else:
        if os.path.isdir(input_path):
            output_dir = input_path
        else:
            output_dir = os.path.dirname(input_path) or '.'
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate timestamp for filenames
    #timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Process input
    if os.path.isdir(input_path):
        # Use recursive by default for directories, unless --no-recursive is specified
        if args.no_recursive or is_cve_id:
            results = process_directory(input_path)
        else:
            results = process_directory_recursive(input_path)
            
        if is_cve_id:
            base_filename = f"{args.input}_extraction"
        else:
            base_filename = f"cwe_results_extraction"
    else:
        file_results = extract_cves_from_file(input_path)
        
        # Restructure single file results to match directory format
        results = {}
        for cve_id, classifications in file_results.items():
            source_file = classifications.pop("source_file", input_path)
            file_type = classifications.pop("file_type", "unknown")
            metadata = classifications.pop("metadata", {})
            
            results[cve_id] = {
                "primary": classifications.get("primary", []),
                "secondary": classifications.get("secondary", []),
                "tertiary": classifications.get("tertiary", []),
                "contributing": classifications.get("contributing", []),
                "metadata": metadata,
                "sources": [{
                    "file": source_file,
                    "file_type": file_type,
                    "primary": classifications.get("primary", []),
                    "secondary": classifications.get("secondary", []),
                    "tertiary": classifications.get("tertiary", []),
                    "contributing": classifications.get("contributing", []),
                    "metadata": metadata
                }]
            }
        
        # Use input filename as base
        base_filename = f"{os.path.splitext(os.path.basename(input_path))[0]}_extraction"
    
    if not results:
        print("\nNo CVE/CWE data found in the specified location(s).")
        return
    
    # Always display results to console
    print(f"\nFound {len(results)} CVEs:")
    for cve_id, data in results.items():
        print(f"\n{cve_id}:")
        
        # Print consolidated CWEs with metadata
        for class_type in ["primary", "secondary", "tertiary", "contributing"]:
            if data[class_type]:
                cwes_with_metadata = []
                for cwe_id in data[class_type]:
                    metadata = data.get("metadata", {}).get(cwe_id, {})
                    confidence = metadata.get("confidence", "-")
                    if isinstance(confidence, float):
                        confidence = f"{confidence:.2f}"
                    cwes_with_metadata.append(f"{cwe_id} (Conf: {confidence})")
                
                print(f"  {class_type.capitalize()} CWEs: {', '.join(cwes_with_metadata)}")
        
        # Print sources
        print("  Sources:")
        for source in data["sources"]:
            source_file = os.path.basename(source["file"])
            print(f"    - {source_file} ({source['file_type']})")
            
            for class_type in ["primary", "secondary", "tertiary", "contributing"]:
                if source[class_type]:
                    print(f"      {class_type.capitalize()}: {', '.join(source[class_type])}")
    
    # Save results to files unless --no-save is specified
    if not args.no_save:
        # Determine which formats to save
        save_formats = []
        if args.format == 'all':
            save_formats = ['json', 'md', 'text']
        else:
            save_formats = [args.format]
        
        # Save in each specified format
        for fmt in save_formats:
            if fmt == 'json':
                json_output = os.path.join(output_dir, f"{base_filename}.json")
                with open(json_output, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"\nJSON results saved to {json_output}")
            
            elif fmt == 'md':
                md_output = os.path.join(output_dir, f"{base_filename}.md")
                save_markdown_report(results, md_output)
                print(f"\nMarkdown report saved to {md_output}")
            
            elif fmt == 'text':
                text_output = os.path.join(output_dir, f"{base_filename}.txt")
                with open(text_output, 'w') as f:
                    for cve_id, data in results.items():
                        f.write(f"\n{cve_id}:\n")
                        
                        # Write consolidated CWEs with metadata
                        for class_type in ["primary", "secondary", "tertiary", "contributing"]:
                            if data[class_type]:
                                cwes_with_metadata = []
                                for cwe_id in data[class_type]:
                                    metadata = data.get("metadata", {}).get(cwe_id, {})
                                    confidence = metadata.get("confidence", "-")
                                    if isinstance(confidence, float):
                                        confidence = f"{confidence:.2f}"
                                    cwes_with_metadata.append(f"{cwe_id} (Conf: {confidence})")
                                
                                f.write(f"  {class_type.capitalize()} CWEs: {', '.join(cwes_with_metadata)}\n")
                        
                        # Write sources
                        f.write("  Sources:\n")
                        for source in data["sources"]:
                            source_file = os.path.basename(source["file"])
                            f.write(f"    - {source_file} ({source['file_type']})\n")
                            
                            for class_type in ["primary", "secondary", "tertiary", "contributing"]:
                                if source[class_type]:
                                    f.write(f"      {class_type.capitalize()}: {', '.join(source[class_type])}\n")
                            
                            # Write metadata
                            source_metadata = source.get("metadata", {})
                            if source_metadata:
                                f.write("      Metadata:\n")
                                for cwe_id, meta in source_metadata.items():
                                    confidence = meta.get("confidence", "-")
                                    if isinstance(confidence, float):
                                        confidence = f"{confidence:.2f}"
                                    f.write(f"        {cwe_id}: Confidence={confidence}\n")
                
                print(f"\nText results saved to {text_output}")


if __name__ == "__main__":
    main()