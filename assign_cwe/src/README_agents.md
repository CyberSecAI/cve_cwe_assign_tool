# CWE Classification System: Multi-Agent Architecture



- [CWE Classification System: Multi-Agent Architecture](#cwe-classification-system-multi-agent-architecture)
  - [Agent Design Philosophy](#agent-design-philosophy)
      - [LLM-Based Agents](#llm-based-agents)
      - [Agent Workflow](#agent-workflow)
  - [Agent Interaction Flow](#agent-interaction-flow)
  - [Agent Hierarchy](#agent-hierarchy)
    - [1. BaseAgent](#1-baseagent)
    - [2. ContextAwareAgent](#2-contextawareagent)
    - [3. EnhancedLLMAgent](#3-enhancedllmagent)
    - [4. RelationshipEnhancedLLMAgent](#4-relationshipenhancedllmagent)
  - [Agent Roles and Responsibilities](#agent-roles-and-responsibilities)
    - [Analyzer Agent](#analyzer-agent)
    - [Critic Agent](#critic-agent)
    - [Resolver Agent](#resolver-agent)
  - [Example Agent Instantiation](#example-agent-instantiation)
  - [Agent Configuration](#agent-configuration)

This document provides an overview of the multi-agent architecture used in the CWE classification system.

## Agent Design Philosophy

The system employs a collaborative multi-agent approach with specialized roles to improve CWE classification accuracy through:

1. **Division of Responsibility**: Each agent focuses on a specific aspect of the analysis
2. **Checks and Balances**: Agents review and critique each other's work
3. **Iterative Refinement**: Analysis undergoes multiple passes to improve accuracy
4. **Specialized Expertise**: Each agent has role-specific prompting and behavior

#### LLM-Based Agents
The system uses three LLM-based agents to analyze, critique, and resolve CWE classifications:

1. **Analyzer**:
   - **Role**: Identifies potential CWEs based on the vulnerability description.
   - **Input**: Vulnerability description.
   - **Output**: List of potential CWEs with confidence scores.

2. **Critic**:
   - **Role**: Reviews the analyzer's CWE assignments and provides feedback.
   - **Input**: Analyzer's CWE assignments and vulnerability description.
   - **Output**: Critique of the analyzer's assignments, including suggested improvements.

3. **Resolver**:
   - **Role**: Makes the final decision on the most appropriate CWE classification.
   - **Input**: Analyzer's CWE assignments and critic's feedback.
   - **Output**: Final CWE classification with justification.

#### Agent Workflow
1. **Analyzer** processes the vulnerability description and generates initial CWE assignments.
2. **Critic** reviews the analyzer's assignments and provides feedback.
3. **Resolver** considers both the analyzer's assignments and the critic's feedback to make the final decision.


## Agent Interaction Flow

1. **Vulnerability Input**: System receives vulnerability description
2. **Analyzer Phase**: Analyzer agent performs initial assessment
3. **Critic Phase**: Critic agent reviews the analyzer's assessment
4. **Resolution Phase**: Resolver agent makes final determination
5. **Output Generation**: System formats comprehensive output with relationship insights


## Agent Hierarchy

The system implements three core agent roles:

### 1. BaseAgent
- Abstract base class that defines the agent interface
- Provides common functionality like input validation and response formatting
- Extended by `ContextAwareAgent` to maintain interaction history

### 2. ContextAwareAgent
- Extends BaseAgent with context maintenance capabilities
- Keeps track of previous interactions for contextual understanding
- Manages context history with a configurable limit

### 3. EnhancedLLMAgent
- Extends ContextAwareAgent with LLM and retrieval capabilities
- Integrates with multiple LLM providers (Anthropic, OpenAI, Gemini)
- Uses hybrid retrieval for context enhancement
- Specialized for analyzer, critic, and resolver roles

### 4. RelationshipEnhancedLLMAgent
- Extends EnhancedLLMAgent with graph relationship analysis
- Adds CWE relationship visualization and analysis
- Provides abstraction level recommendations and chain analysis
- Enhances responses with relationship insights

## Agent Roles and Responsibilities

### Analyzer Agent
- Performs initial vulnerability analysis
- Extracts key details from vulnerability descriptions
- Identifies potential CWE classifications
- Provides rationale for classifications
- Generates confidence scores

### Critic Agent
- Reviews the analyzer's assessment
- Identifies gaps or errors in the analysis
- Suggests alternative or additional CWEs
- Evaluates the quality of evidence
- Checks for proper abstraction level

### Resolver Agent
- Makes the final determination based on both analyses
- Resolves conflicts between analyzer and critic
- Provides comprehensive justification
- Generates final confidence score
- Creates structured output with relationship context




## Example Agent Instantiation

```python
# Create analyzer agent with relationship enhancement
analyzer = RelationshipEnhancedLLMAgent(
    role="analyzer",
    llm_provider="anthropic",
    llm_config=config.get_llm_config(),
    context_limit=5,
    max_iterations=3,
    embedding_client=embedding_client,
    retriever=hybrid_retriever,
    cwe_database_path="./data/cwe_database.json",
    output_dir="./output/relationship_analysis"
)
```

## Agent Configuration

Each agent can be configured with:

- **LLM Provider**: Choice of Anthropic, OpenAI, Gemini
- **Context Limit**: Maximum number of previous interactions to maintain
- **Max Iterations**: Maximum number of retry loops
- **Retriever Integration**: Connection to hybrid retrieval system
- **Specialized Prompts**: Role-specific instructions

The multi-agent architecture provides a robust framework for accurate CWE classification through specialized roles, collaborative analysis, and iterative refinement.