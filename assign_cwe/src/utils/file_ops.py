# src/utils/file_ops.py

"""
Utility functions for file operations in the CWE Knowledge Base system.
"""

import os
import json
import csv
from pathlib import Path
from typing import Dict, List, Any
from utils.logger import get_logger

logger = get_logger(__name__)

def ensure_directory(directory_path: str) -> str:
    """
    Ensure a directory exists, create it if it doesn't.
    
    Args:
        directory_path: Path to directory
        
    Returns:
        The directory path (for chaining)
    """
    os.makedirs(directory_path, exist_ok=True)
    return directory_path

def save_markdown(filepath: str, title: str, content: str) -> str:
    """
    Save content as markdown with a title.
    
    Args:
        filepath: Path where to save the file
        title: Title to prepend to the content
        content: Markdown content
        
    Returns:
        The filepath (for chaining)
    """
    try:
        with open(filepath, 'w') as f:
            f.write(f"# {title}\n\n{content}")
        return filepath
    except Exception as e:
        logger.error(f"Error saving markdown to {filepath}: {e}")
        raise

def save_json(filepath: str, data: Dict[str, Any]) -> str:
    """
    Save data as JSON with proper handling of non-serializable objects.
    
    Args:
        filepath: Path where to save the file
        data: Data to save as JSON
        
    Returns:
        The filepath (for chaining)
    """
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        return filepath
    except Exception as e:
        logger.error(f"Error saving JSON to {filepath}: {e}")
        raise

def save_csv(filepath: str, headers: List[str], rows: List[List[Any]]) -> str:
    """
    Save data as CSV.
    
    Args:
        filepath: Path where to save the file
        headers: CSV header row
        rows: CSV data rows
        
    Returns:
        The filepath (for chaining)
    """
    try:
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        return filepath
    except Exception as e:
        logger.error(f"Error saving CSV to {filepath}: {e}")
        raise

def append_csv_row(filepath: str, row: List[Any]) -> str:
    """
    Append a row to a CSV file.
    
    Args:
        filepath: Path to the CSV file
        row: Row data to append
        
    Returns:
        The filepath (for chaining)
    """
    try:
        with open(filepath, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(row)
        return filepath
    except Exception as e:
        logger.error(f"Error appending to CSV {filepath}: {e}")
        raise

def read_csv(filepath: str, required_fields: List[str] = None) -> List[Dict[str, Any]]:
    """
    Read a CSV file and return its contents as a list of dictionaries.
    
    Args:
        filepath: Path to the CSV file
        required_fields: List of required field names
        
    Returns:
        List of dictionaries, one per row
    """
    try:
        with open(filepath, 'r') as f:
            reader = csv.DictReader(f)
            
            if required_fields:
                csv_field_names = reader.fieldnames if reader.fieldnames else []
                field_mapping = {}
                
                for required in required_fields:
                    found = False
                    for field in csv_field_names:
                        if field.lower() == required.lower():
                            field_mapping[required] = field
                            found = True
                            break
                    if not found:
                        raise ValueError(f"CSV file missing required field: {required}")
                
                # Create a list of dictionaries with normalized field names
                rows = []
                for row in reader:
                    normalized_row = {}
                    for required, actual in field_mapping.items():
                        normalized_row[required] = row[actual]
                    rows.append(normalized_row)
                return rows
            
            return list(reader)
    except Exception as e:
        logger.error(f"Error reading CSV {filepath}: {e}")
        raise