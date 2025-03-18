"""Base agent definitions for the CWE analysis system."""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

class BaseAgent(ABC):
    """Abstract base class for all agents in the system."""
    
    def __init__(self, role: str):
        """
        Initialize a base agent.
        
        Args:
            role: The role of this agent (e.g., "analyzer", "critic", "resolver")
        """
        self.role = role
        
    @abstractmethod
    def generate_response(self, input_text: str) -> str:
        """
        Generate a response based on input text.
        
        Args:
            input_text: The input text to process
            
        Returns:
            str: The generated response
        """
        pass
        
    @abstractmethod
    def get_metadata(self) -> Dict[str, Any]:
        """
        Get metadata about the agent.
        
        Returns:
            Dict containing agent metadata
        """
        pass
        
    def validate_input(self, input_text: str, max_length: int = 10000) -> Optional[str]:
        """
        Validate input text before processing.
        
        Args:
            input_text: The input text to validate
            max_length: Maximum allowed length from configuration
            
        Returns:
            Optional[str]: Error message if validation fails, None if successful
        """
        if not input_text or not input_text.strip():
            return "Input text cannot be empty"
        if len(input_text) > max_length:
            return f"Input text exceeds maximum length of {max_length} characters"
        return None
        
    def format_response(self, response: str) -> str:
        """
        Format the response before returning.
        
        Args:
            response: The raw response to format
            
        Returns:
            str: The formatted response
        """
        return response.strip()

class ContextAwareAgent(BaseAgent):
    """Base class for agents that maintain context between interactions."""
    
    def __init__(self, role: str, context_limit: int = 5):
        """
        Initialize a context-aware agent.
        
        Args:
            role: The role of this agent
            context_limit: Maximum number of previous interactions to maintain
        """
        super().__init__(role)
        self.context_limit = context_limit
        self.context_history = []
        
    def add_to_context(self, interaction: Dict[str, str]):
        """
        Add an interaction to the context history.
        
        Args:
            interaction: Dictionary containing the interaction details
        """
        self.context_history.append(interaction)
        if len(self.context_history) > self.context_limit:
            self.context_history.pop(0)
            
    def clear_context(self):
        """Clear the context history."""
        self.context_history = []
        
    def get_context(self) -> str:
        """
        Get the current context as a formatted string.
        
        Returns:
            str: Formatted context string
        """
        if not self.context_history:
            return ""
            
        context_parts = []
        for interaction in self.context_history:
            context_parts.append(
                f"Input: {interaction['input']}\n"
                f"Response: {interaction['response']}\n"
                f"---"
            )
        return "\n".join(context_parts)