# Contextual Retrieval for CWE Classification

- [Contextual Retrieval for CWE Classification](#contextual-retrieval-for-cwe-classification)
  - [Overview](#overview)
  - [Key Components](#key-components)
    - [Contextual Enhancement Process](#contextual-enhancement-process)
    - [LRU Caching Mechanism](#lru-caching-mechanism)
    - [Dense Vector Retrieval](#dense-vector-retrieval)
    - [Reranking Capabilities](#reranking-capabilities)
  - [Key Advantages](#key-advantages)
    - [Enhanced Semantics](#enhanced-semantics)
    - [Efficiency Improvements](#efficiency-improvements)
    - [Configurable Behavior](#configurable-behavior)
  - [Example Usage](#example-usage)
  - [Integration with Other Components](#integration-with-other-components)


This document describes the contextual retrieval capabilities of the CWE classification system, which enhances standard retrieval methods with LLM-generated context.

## Overview

The `ContextualHybridRetriever` component improves retrieval accuracy by:

1. Using LLMs to generate enhanced contextual descriptions for CWE entries
2. Caching these enriched representations for efficiency
3. Leveraging both original and enhanced descriptions during retrieval
4. Providing reranking capabilities for search results

## Key Components

### Contextual Enhancement Process

The system enriches CWE entries through a contextual enhancement process:

```python
def generate_context(self, entry: CWEEntry) -> Tuple[str, Any]:
    """Generate context for a CWE entry with in-memory caching."""
    cache_key = f"CWE-{entry.ID}"
    
    # Check in-memory cache first
    if cached_result := self.context_cache.get(cache_key):
        logger.debug(f"Context cache hit for {cache_key}")
        return cached_result

    # Generate new context if not in cache
    prompt = f"""
    Please analyze this CWE entry and provide a concise context that captures its key characteristics:

    ID: CWE-{entry.ID}
    Name: {entry.Name}
    Type: {entry.Abstraction}
    Description: {entry.Description}
    """

    response = self.anthropic_client.messages.create(
        model="claude-3-haiku-20240307",
        max_tokens=1024,
        temperature=0,
        messages=[{
            "role": "user",
            "content": prompt
        }]
    )
    
    result = (response.content[0].text, response.usage)
    self.context_cache.put(cache_key, result)
    
    return result
```

### LRU Caching Mechanism

To optimize performance, the contextual retriever implements an LRU (Least Recently Used) cache:

- Keeps most frequently accessed contexts in memory
- Evicts least recently used items when capacity is reached
- Provides fast access for common CWEs
- Tracks cache performance metrics (hits/misses)

### Dense Vector Retrieval

The contextual retriever leverages a Qdrant-based dense vector store:

- Stores both original and contextually enhanced CWE descriptions
- Uses embeddings to perform semantic search
- Optimizes for similarity matching with query variations

### Reranking Capabilities

For improved ranking of search results, the retriever can:

- Apply cross-encoder reranking to initial results
- Use Cohere's reranking API for improved relevance scoring
- Preserve original scores for transparency

## Key Advantages

### Enhanced Semantics

By generating LLM-enhanced contexts, the system:

- Captures key characteristics that might be buried in technical descriptions
- Normalizes terminology across different CWEs
- Emphasizes important aspects relevant to detection and classification
- Improves matching with natural language vulnerability descriptions

### Efficiency Improvements

The contextual system improves efficiency through:

- Caching mechanisms to avoid redundant API calls
- Batch processing for context generation
- Parallel threading for enhanced performance
- Token usage tracking for monitoring

### Configurable Behavior

The contextual retriever offers configurable options:

- Adjustable cache size for memory management
- Prompt customization for different context styles
- Reranking toggle for precision vs. speed tradeoffs
- Parallel processing control for performance tuning

## Example Usage

```python
# Initialize the contextual hybrid retriever
contextual_retriever = ContextualHybridRetriever(
    name="contextual_hybrid",
    anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
    cohere_api_key=os.getenv("COHERE_API_KEY"),
    parallel_threads=2,
    qdrant_location="./data/qdrant",
    embedding_client=embedding_client,
    cache_size=5000
)

# Load CWE data and enhance with context
contextual_retriever.load_data(cwe_entries)

# Search with contextual enhancement
results = contextual_retriever.search(
    "SQL injection vulnerability in login form",
    k=5,
    rerank=True
)

# Access token usage statistics
token_usage = contextual_retriever.token_counts
print(f"Input tokens: {token_usage['input']}")
print(f"Output tokens: {token_usage['output']}")

# Get cache metrics
cache_size = len(contextual_retriever.context_cache)
cache_capacity = contextual_retriever.context_cache.capacity
print(f"Cache utilization: {cache_size}/{cache_capacity}")
```

## Integration with Other Components

The contextual retriever integrates with other system components:

1. **Enhanced LLM Agents**: Provides context-rich results for LLM analysis
2. **Hybrid Retrieval**: Can be combined with sparse and graph-based retrieval methods
3. **Relationship Analysis**: Complements graph-based relationship insights

By combining contextual retrieval with relationship analysis, the system provides a comprehensive understanding of CWEs that includes both semantic richness and structural relationships.