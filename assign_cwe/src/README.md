# CWE Assignment System

- [CWE Assignment System](#cwe-assignment-system)
  - [System Overview](#system-overview)
  - [Core Components](#core-components)
    - [Agents](#agents)
    - [Retrieval Systems](#retrieval-systems)
    - [CWE Relationship Analysis](#cwe-relationship-analysis)
  - [Key Features](#key-features)
  - [Configuration](#configuration)
      - [Directory Structure](#directory-structure)
  - [Getting Started](#getting-started)
  - [Usage](#usage)


The CWE Assignment System is an advanced framework for automatically identifying and assigning Common Weakness Enumeration (CWE) classifications to vulnerabilities using a multi-agent approach combined with hybrid retrieval methods.

## System Overview

This system uses a combination of:

1. **Multiple LLM Agents** - Analyzer, Critic, and Resolver roles working together to evaluate vulnerabilities
2. **Hybrid Retrieval Techniques** - Dense vector search, sparse retrieval, and property graph relationships
3. **CWE Relationship Analysis** - Graph-based analysis of CWE hierarchies and relationships
4. **Multiple LLM Providers** - Support for Anthropic, OpenAI, Gemini models

## Core Components

### Agents

The system employs a multi-agent architecture with specialized roles:

- **Analyzer Agent** - Performs initial vulnerability analysis and CWE classification
- **Critic Agent** - Reviews and critiques the analyzer's assessment
- **Resolver Agent** - Makes the final determination based on both analyses

Each agent is enhanced with retrieval capabilities and can access the CWE knowledge graph.

### Retrieval Systems

The framework uses three complementary retrieval approaches:

- **Dense Vector Search** - Semantic similarity using embeddings
- **Sparse Retrieval** - Keyword-based search using BM25 algorithm
- **Property Graph** - Neo4j-backed graph database for traversing CWE relationships

Results from these retrievers are combined with intelligent weighting to produce optimal results.

### CWE Relationship Analysis

The system incorporates comprehensive relationship analysis:

- **Abstraction Levels** - Analyzes the appropriate level of specificity (Pillar, Class, Base, Variant)
- **Chain Analysis** - Examines causal chains between weaknesses
- **Peer Relationships** - Identifies related weaknesses across the CWE hierarchy

## Key Features

- Configurable multi-LLM architecture with support for different providers
- Evidence-based analysis with confidence scoring
- Hybrid retrieval system that combines semantic search with graph-based approaches
- Detailed reporting with relationship insights and abstraction analysis


## Configuration

The system is configured through a YAML file that specifies:

- LLM providers and parameters
- Retrieval system weights
- Agent settings
- Database paths

See `config.yaml` for detailed configuration options.





#### Directory Structure
```
assign_cwe/
├── agents/                # LLM-based agents for analysis, critique, and resolution
├── config/                # Configuration settings and environment variables
├── models/                # Data models for vulnerabilities and CWEs
├── prompts/               # Prompt templates for LLM agents
├── retrievers/            # Retrieval methods for finding relevant CWEs
└── src/                   # Main source code for the system
```

## Getting Started


1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
2. **Set Up Environment Variables**:
   - Create a `.env` file in the `env/` directory with the necessary API keys and Neo4j credentials.
   - Example `.env`:
     ```
     ANTHROPIC_API_KEY=your_anthropic_api_key
     COHERE_API_KEY=your_cohere_api_key
     NEO4J_URL=bolt://localhost:7687
     NEO4J_USERNAME=neo4j
     NEO4J_PASSWORD=your_neo4j_password
     ```
3. **Setup Neo4J Database**
4. **Run the System**:
   ```bash
   python src/main.py --config path/to/config.yaml --file path/to/vulnerability.json
   ```


## Usage

```bash
(env) top25_cwe_assign_compare$ python assign_cwe/src/main.py --csv ./data_in/cves.csv --output-dir ../cwe_assign_reports
```
