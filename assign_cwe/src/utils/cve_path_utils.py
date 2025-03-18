# /src/cve_path_utils.py

"""Utility functions for handling CVE file paths."""

import os
import json
from typing import Optional

def get_subdir_name(number: str) -> str:
    """
    Get the subdirectory name based on CVE number.
    
    Args:
        number: The CVE number (e.g., '3123' from CVE-2024-3123)
        
    Returns:
        str: Subdirectory name (e.g., '3xxx')
    """
    num = int(number)
    if num < 10000:  # 0xxx to 9xxx
        return f"{num // 1000:01d}xxx"
    else:
        return f"{num // 1000:02d}xxx"

def get_cve_path(base_dir: str, cve_id: str) -> str:
    """
    Get the full path to a CVE JSON file.
    
    Args:
        base_dir: Base directory containing CVE information
        cve_id: CVE identifier (e.g., 'CVE-2024-3123')
        
    Returns:
        str: Full path to the CVE JSON file
    """
    try:
        # Split CVE ID into components
        _, year, number = cve_id.split('-')
        
        # Build path components
        subdir = get_subdir_name(number)
        
        # Construct full path
        return os.path.join(base_dir, year, subdir, f"{cve_id}.json")
    except Exception as e:
        raise ValueError(f"Invalid CVE ID format: {cve_id}") from e

def get_reference_path(base_dir: str, cve_id: str) -> str:
    """
    Get the full path to a CVE reference markdown file.
    Handles path structure like: ../cve_info_refs/2022/25xxx/CVE-2022-25830/refined/refined.md
    
    Args:
        base_dir: Base directory containing CVE reference information
        cve_id: CVE identifier (e.g., 'CVE-2022-25830')
        
    Returns:
        str: Full path to the refined.md file
    """
    try:
        # Split CVE ID into components
        _, year, number = cve_id.split('-')
        
        # Build path components
        subdir = get_subdir_name(number)
        
        # Construct full path with refined subdirectory
        return os.path.join(base_dir, year, subdir, cve_id, "refined", "refined.md")
    except Exception as e:
        raise ValueError(f"Invalid CVE ID format: {cve_id}") from e

def read_cve_file(file_path: str) -> Optional[dict]:
    """
    Read and parse a CVE JSON file.
    
    Args:
        file_path: Path to the CVE JSON file
        
    Returns:
        Optional[dict]: Parsed JSON content or None if file doesn't exist
    """
    try:
        if not os.path.exists(file_path):
            return None
            
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        raise IOError(f"Error reading CVE file {file_path}: {str(e)}") from e

def read_reference_file(file_path: str) -> Optional[str]:
    """
    Read a reference markdown file.
    
    Args:
        file_path: Path to the refined.md file
        
    Returns:
        Optional[str]: File content or None if file doesn't exist
    """
    try:
        if not os.path.exists(file_path):
            return None
            
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        raise IOError(f"Error reading reference file {file_path}: {str(e)}") from e