# CWE Knowledge Base with Combined RAG and Property Graph Architecture

## Overview
This system implements a hybrid architecture that combines Retrieval-Augmented Generation (RAG) with a Property Graph for analyzing the Common Weakness Enumeration (CWE) knowledge base. By integrating both approaches, the system provides comprehensive vulnerability analysis that leverages both semantic understanding and structural relationships within the CWE hierarchy.

---

## Input to the LLM

The system processes the following inputs to generate a comprehensive analysis:

1. **CVE Description**:
   - The primary input is the vulnerability description from the CVE (Common Vulnerabilities and Exposures) entry. This provides the context for the analysis, including details about the vulnerability's nature, impact, and potential exploitation vectors.

2. **Key Phrases**:
   - Key phrases extracted from the CVE description or provided as additional input. These phrases highlight critical aspects of the vulnerability, such as the root cause, weakness type, and technical details.

3. **Reference Text**:
   - Additional reference content that provides further context or technical details about the vulnerability. This could include code snippets, attack patterns, or mitigation strategies.

4. **Simimar CVE Description CWE Consensus**:
   - Some CVEs with very similar CVE Descriptions have the same CWEs. The consensus CWE for a CVE is given if it exists.

The LLM uses these inputs to generate an initial analysis, which is then refined through a multi-agent system.

---

## Agent System

The system employs a multi-agent architecture to iteratively refine the analysis of vulnerabilities. The agents are:

1. **Analyzer Agent**:
   - The Analyzer agent generates an initial analysis of the vulnerability based on the input description, key phrases, and reference text. It identifies potential CWE matches and provides a technical explanation of why these CWEs apply.

2. **Critic Agent**:
   - The Critic agent reviews the initial analysis and provides feedback. It examines the proposed CWE classifications, checks for mismatches or oversights, and ensures that the analysis considers all relevant aspects of the vulnerability.

3. **Resolver Agent**:
   - The Resolver agent makes the final determination on the most appropriate CWE classification. It considers both the initial analysis and the feedback from the Critic agent, ensuring that the final decision is well-justified and takes into account the relationships between CWEs.

---

## RAG System

The Retrieval-Augmented Generation (RAG) system enhances the retrieval of relevant CWE entries by combining dense vector search with sparse retrieval techniques. The RAG system includes:

1. **Dense Retriever**:
   - Uses vector embeddings to find semantically similar CWE entries. The embeddings are generated using a model like `text-embedding-ada-002` and stored in a vector database (Qdrant).

2. **Sparse Retriever**:
   - Uses traditional keyword-based retrieval (BM25) to find exact matches or partial matches based on keywords in the CVE description.

3. **Hybrid Retriever**:
   - Combines the results from both dense and sparse retrievers, reranking them to prioritize the most relevant CWEs. The hybrid retriever also considers the relationships between CWEs, as captured in the property graph.


### Strengths and Weaknesses of each Retriever
1. **Dense Retriever**:
   - Uses semantic similarity (e.g., cosine similarity between embeddings).
   - Strengths: Captures semantic meaning and context.
   - Weaknesses: May miss exact keyword matches or structural relationships.

2. **Sparse Retriever**:
   - Uses keyword-based matching (e.g., BM25).
   - Strengths: Excels at exact keyword matches and keyphrase relevance.
   - Weaknesses: May miss semantic or structural relevance.

3. **Property Graph Retriever**:
   - Uses structural relationships (e.g., parent-child, peer, chain relationships).
   - Strengths: Captures hierarchical and relational context.
   - Weaknesses: May miss semantic or keyword relevance.

### Benefits of the RAG System:
- **Semantic Understanding**: The dense retriever captures the semantic meaning of the vulnerability description, allowing for more accurate matching of CWEs based on conceptual similarity.
- **Exact Matching**: The sparse retriever ensures that exact keyword matches are not overlooked, providing a balance between semantic and exact matching.
- **Contextual Enhancement**: The RAG system uses LLM-generated context to enrich the retrieved CWE entries, improving the relevance of the results.

---

## Embeddings from CWE ID Entries

The embeddings used in the RAG system are generated from each CWE ID entry rather than from chunks of text. This approach has several benefits:

1. **Holistic Representation**:
   - Each CWE entry is embedded as a whole, capturing the full context of the weakness, including its description, relationships, and examples. This ensures that the embedding represents the entire CWE, not just a fragment.

2. **Consistency**:
   - By embedding entire CWE entries, the system avoids inconsistencies that can arise from chunking, where different parts of the same CWE might be represented differently.

3. **Efficient Retrieval**:
   - Embedding entire entries allows for more efficient retrieval, as the system can directly compare the query embedding with the CWE embeddings without needing to aggregate results from multiple chunks.

---

## Output Report

The system generates a detailed output report that includes the following sections:

1. **Vulnerability Description**:
   - A summary of the vulnerability description provided as input.

2. **Summary**:
   - A table of the most relevant CWEs identified, along with their relevance scores.

3. **Detailed Analysis**:
   - The initial analysis generated by the Analyzer agent, including the technical explanation of why the identified CWEs apply.

4. **Critical Review**:
   - Feedback from the Critic agent, highlighting potential mismatches or oversights in the initial analysis.

5. **Final Resolution**:
   - The final CWE classification determined by the Resolver agent, along with a justification for the decision.

6. **CWE Relationships**:
   - A visual representation (Mermaid diagram) of the relationships between the identified CWEs, showing how they are connected in the CWE hierarchy.

### How to Use the Report:
- **Identify Relevant CWEs**: Use the summary table to quickly identify the most relevant CWEs for the vulnerability.
- **Understand the Analysis**: Review the detailed analysis to understand why specific CWEs were identified and how they relate to the vulnerability.
- **Validate the Results**: Use the critical review to validate the analysis and ensure that all relevant aspects of the vulnerability have been considered.
- **Explore Relationships**: Use the CWE relationships section to explore how the identified CWEs are connected and to identify potential patterns or chains of weaknesses.

---

## Architecture Overview

### Combined Retrieval Approach
The system uses two complementary retrieval methods:

1. **RAG-based Retrieval**:
   - Semantic similarity through dense vector search
   - Contextual enhancement using LLMs
   - Reranking for relevance optimization

2. **Property Graph-based Retrieval**:
   - Structural relationship navigation
   - Pattern-based matching
   - Hierarchical traversal

### Why Both Approaches are Needed
The CWE knowledge base has two distinct aspects that benefit from different retrieval methods:

1. **Semantic Content** (handled by RAG):
   - Detailed vulnerability descriptions
   - Technical impact statements
   - Code examples and scenarios

2. **Structural Relationships** (handled by Property Graph):
   - Hierarchical classifications (Base/Class/Category)
   - Peer relationships between weaknesses
   - Causal chains and dependencies

---

## Property Graph Implementation

### Graph Structure
The property graph is built from CWE JSON fields to capture the rich relationship structure:

1. **Nodes**:
   - **Types**: BASE, CLASS, CATEGORY, VIEW, COMPOUND, VARIANT
   - **Properties**:
     - ID: CWE identifier
     - Name: Weakness name
     - Abstraction: Level in hierarchy
     - Status: Current status
     - Description: Main content

2. **Relationships**:
   - **CHILD_OF**: Hierarchical parent-child relationships
   - **PEER_OF**: Similar-level related weaknesses
   - **CAN_PRECEDE**: Temporal/causal relationships
   - **REQUIRES**: Dependency relationships
   - **ALTERNATIVE_TO**: Alternative classification options
   - **CONTAINS**: Membership relationships
   - **MEMBER_OF**: Group affiliations
   - **RELATED_TO**: General associations

### Graph Building Process
1. **Node Creation**:
   ```python
   # Example of how nodes are created from CWE entries
   nodes = {
       "BASE": ["CHILD_OF", "PEER_OF", "CAN_PRECEDE"],
       "CLASS": ["CHILD_OF", "PEER_OF", "CONTAINS"],
       "CATEGORY": ["CHILD_OF", "CONTAINS"]
   }
   ```

2. **Relationship Extraction**:
   - Parsed from RelatedWeaknesses field
   - Derived from Abstraction levels
   - Inferred from common patterns

3. **Property Assignment**:
   - Metadata from CWE entries
   - Computed properties (e.g., connection counts)
   - Contextual information

---

## Benefits of Combined Approach
````
EnhancedHybridRetriever
├── Neo4j Property Graph (schema + relationships)
└── ContextualHybridRetriever
    └── QdrantDenseRetriever (vector search)


retrievers/
├── __init__.py           # Exports core components
├── base.py              # Base retriever interface
├── hybrid.py            # ContextualHybridRetriever with in-memory caching
├── neo4j_property_graph.py  # Neo4j-based property graph
├── enhanced_hybrid.py   # Main orchestrator
└── qdrant_retriever.py  # Vector search

````
1. **EnhancedHybridRetriever**
   - Main entry point
   - Orchestrates Neo4j and RAG
   - Combines graph and vector search results

2. **CWEPropertyGraph**
   - Neo4j-based graph store
   - CWE-specific schema and relationships
   - Graph traversal and querying

3. **ContextualHybridRetriever**
   - RAG implementation
   - In-memory context caching
   - Reranking capabilities

4. **QdrantDenseRetriever**
   - Vector storage and search
   - Embedding caching
   - Batch processing