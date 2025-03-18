"""
Agents package for LLM-based analysis and decision making.

This package provides agent implementations for analyzing vulnerabilities,
critiquing analyses, and making final determinations about CWE classifications.
"""

from .base import BaseAgent
from .enhanced_llm import EnhancedLLMAgent

__all__ = [
    'BaseAgent',
    'EnhancedLLMAgent',
]