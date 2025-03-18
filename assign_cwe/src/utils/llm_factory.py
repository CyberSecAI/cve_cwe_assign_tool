# src/utils/llm_factory.py

"""
LLM Factory module providing a unified interface for different LLM providers using Langchain.
"""

import os
from typing import Dict, Any, Optional, Union, List
from utils.logger import get_logger

logger = get_logger(__name__)

class LLMFactory:
    """Factory class for creating LLM instances using Langchain."""
    
    @staticmethod
    def create_llm(provider: str, config: Dict[str, Any]):
        """
        Create a Langchain LLM instance based on provider and configuration.
        
        Args:
            provider: LLM provider name (anthropic, gemini, openai)
            config: Configuration dictionary for the LLM
            
        Returns:
            Langchain LLM instance
        """
        provider = provider.lower()
        
        if provider == "anthropic":
            return LLMFactory._create_anthropic_llm(config)
        elif provider == "gemini":
            return LLMFactory._create_gemini_llm(config)
        elif provider == "openai":
            return LLMFactory._create_openai_llm(config)
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")
    
    @staticmethod
    def _create_anthropic_llm(config: Dict[str, Any]):
        """Create Anthropic LLM instance."""
        try:
            from langchain_anthropic import ChatAnthropic
            
            model = config.get("model", "claude-3-haiku-20240307")
            temperature = config.get("temperature", 0.7)
            max_tokens = config.get("max_tokens", 2048)
            api_key = config.get("api_key", os.getenv("ANTHROPIC_API_KEY"))
            
            if not api_key:
                raise ValueError("No API key provided for Anthropic")
            
            llm = ChatAnthropic(
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                anthropic_api_key=api_key
            )
            
            logger.info(f"Created Anthropic LLM with model: {model}")
            return llm
            
        except ImportError:
            logger.error("Could not import langchain_anthropic. Please install with: pip install langchain-anthropic")
            raise
    
    @staticmethod
    def _create_gemini_llm(config: Dict[str, Any]):
        """Create Google Gemini LLM instance."""
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
            
            model = config.get("model", "gemini-pro")
            temperature = config.get("temperature", 0.7)
            max_tokens = config.get("max_tokens", 2048)
            api_key = config.get("api_key", os.getenv("GOOGLE_API_KEY"))
            
            if not api_key:
                raise ValueError("No API key provided for Gemini")
            
            llm = ChatGoogleGenerativeAI(
                model=model,
                temperature=temperature,
                max_output_tokens=max_tokens,
                google_api_key=api_key
            )
            
            logger.info(f"Created Gemini LLM with model: {model}")
            return llm
            
        except ImportError:
            logger.error("Could not import langchain_google_genai. Please install with: pip install langchain-google-genai")
            raise
    
    @staticmethod
    def _create_openai_llm(config: Dict[str, Any]):
        """Create OpenAI LLM instance."""
        try:
            from langchain_openai import ChatOpenAI
            
            model = config.get("model", "gpt-4")
            temperature = config.get("temperature", 0.7)
            max_tokens = config.get("max_tokens", 2048)
            api_key = config.get("api_key", os.getenv("OPENAI_API_KEY"))
            
            if not api_key:
                raise ValueError("No API key provided for OpenAI")
            
            llm = ChatOpenAI(
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                openai_api_key=api_key
            )
            
            logger.info(f"Created OpenAI LLM with model: {model}")
            return llm
            
        except ImportError:
            logger.error("Could not import langchain_openai. Please install with: pip install langchain-openai")
            raise

# Usage example:
# config = {"model": "gemini-pro", "temperature": 0.7, "max_tokens": 2048}
# llm = LLMFactory.create_llm("gemini", config)