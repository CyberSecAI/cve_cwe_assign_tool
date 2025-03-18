# src/models/__init__.py

"""
CWE Models package for handling Common Weakness Enumeration data structures.

This package provides the data models and utilities for working with CWE entries,
including their relationships, examples, and searchable representations.
"""

from .cwe import (
    CWEEntry,
    AlternateTerm,
    RelatedWeakness,
    load_cwe_database
)
from .vulnerability_info import (
    VulnerabilityInfo,
    SimilarityInsight,
    ProcessingResult
)

__all__ = [
    'CWEEntry',
    'AlternateTerm',
    'RelatedWeakness',
    'load_cwe_database',
    'VulnerabilityInfo',
    'SimilarityInsight',
    'ProcessingResult'
]