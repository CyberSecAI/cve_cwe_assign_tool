# CWE Retrieval Scoring Methodology

- [CWE Retrieval Scoring Methodology](#cwe-retrieval-scoring-methodology)
  - [Retrieval Methods](#retrieval-methods)
    - [1. Dense Vector Retriever](#1-dense-vector-retriever)
    - [2. Sparse Retriever](#2-sparse-retriever)
    - [3. Graph Retriever](#3-graph-retriever)
  - [Scoring Factors (Ordered by Impact)](#scoring-factors-ordered-by-impact)
  - [Scoring Methodology](#scoring-methodology)
    - [1. Score Normalization](#1-score-normalization)
    - [2. Individual Retriever Weighting](#2-individual-retriever-weighting)
    - [3. Quality-Adjusted Consensus Boosting](#3-quality-adjusted-consensus-boosting)
    - [4. Retriever Pair-Specific Adjustments](#4-retriever-pair-specific-adjustments)
    - [5. Graph Relationship Boosting](#5-graph-relationship-boosting)
    - [6. Mapping Guidance Preference](#6-mapping-guidance-preference)
    - [7. Parent-Child Chain Strength](#7-parent-child-chain-strength)
    - [8. Final Score Calculation](#8-final-score-calculation)
  - [Example Calculation](#example-calculation)
  - [Benefits of This Approach](#benefits-of-this-approach)


This document explains the sophisticated scoring methodology used for ranking Common Weakness Enumeration (CWE) entries based on multiple retrieval methods. The system combines results from three different retrievers, normalizes and weights their scores, and applies various boosting factors to produce a final ranking of the most relevant CWEs.

## Retrieval Methods

The system uses three complementary retrieval methods:

### 1. Dense Vector Retriever
- Uses vector embeddings to represent semantic meaning
- Scores range naturally from 0-1 (cosine similarity)
- Focuses on semantic matching between query and CWE descriptions
- Implemented using Qdrant vector database

### 2. Sparse Retriever
- Uses BM25 algorithm for keyword-based matching
- Raw scores can be very large (e.g., 500-1000+)
- Focuses on term frequency and exact keyword matches
- Better at capturing specific technical terms

### 3. Graph Retriever
- Uses Neo4j property graph to represent CWE relationships
- Can leverage both text search and graph relationships
- Captures structural knowledge about relationships between CWEs
- May use embeddings for initial matching

## Scoring Factors (Ordered by Impact)

Our scoring methodology incorporates multiple factors, ordered here by their potential impact on the final ranking:

1. **Quality-Adjusted Consensus Boosting** (up to 2.0× boost)
   - Results found by all three retrievers receive up to 2.0× boost
   - Results found by two retrievers receive up to 1.5× boost
   - Boost is scaled by the average confidence score of the retrievers

2. **Mapping Guidance Preference** (0.5× to 1.1× adjustment)
   - ALLOWED: +10% boost (factor 1.1) - explicitly recommended for mapping
   - ALLOWED-WITH-REVIEW: +5% boost (factor 1.05) - appropriate with care
   - DISCOURAGED: -20% penalty (factor 0.8) - not recommended for mapping
   - PROHIBITED: -50% penalty (factor 0.5) - should not be used for mapping

3. **Abstraction Level Adjustment** (0.6× to 1.3× adjustment)
   - Base CWEs: +30% boost (factor 1.3) - prioritizes practical weakness types
   - Variant CWEs: +20% boost (factor 1.2) - rewards specific weakness instances
   - Class CWEs: -20% penalty (factor 0.8) - reduces overly general weaknesses
   - Pillar CWEs: -40% penalty (factor 0.6) - strongly discourages top-level abstractions

4. **Parent-Child Chain Strength** (up to 1.15× boost)
   - Boosts CWEs whose parents/children also score well
   - Child→Parent: up to +15% boost when parents also rank highly
   - Parent→Children: up to +10% boost for parents with multiple high-scoring children

5. **Retriever Pair-Specific Adjustments** (0.9× to 1.2× adjustment)
   - Sparse + Dense: +20% additional boost (independent methodologies)
   - Sparse + Graph: +10% additional boost (somewhat independent)
   - Dense + Graph: -10% reduced boost (more overlapping methodologies)

6. **Relationship Bonus** (up to 1.3× boost)
   - CWEs with explicit relationships receive up to +30% additional boost
   - More relationships lead to higher boost, scaled by relationship count

7. **Individual Retriever Weighting** (Base weights)
   - Sparse: 0.4 (highest weight for direct keyphrase matching)
   - Dense: 0.35 (good weight for semantic understanding)
   - Graph: 0.25 (base weight for structural relationships)

## Scoring Methodology

The scoring process follows these steps:

### 1. Score Normalization

- **Dense Scores**: Already in 0-1 range, used as-is
- **Graph Scores**: Already in 0-1 range, used as-is
- **Sparse Scores**: Normalized by capping at 1000 and dividing by 1000
  ```python
  if retriever == "sparse" and score > 1.0:
      normalized_score = min(score, 1000.0) / 1000.0
  ```

### 2. Individual Retriever Weighting

- Each retriever has an assigned weight (configurable, defaults: dense=0.35, sparse=0.4, graph=0.25)
- Individual scores are multiplied by these weights
- The weighted scores are summed (not averaged)

### 3. Quality-Adjusted Consensus Boosting

When multiple retrievers find the same CWE, we apply a boost that's adjusted by the quality of agreement:

```python
# Calculate average normalized score across retrievers
avg_score = sum(normalized_scores.values()) / len(normalized_scores)
# Scale the quality factor - full boost at avg_score of 0.4+
quality_factor = min(avg_score * 2.5, 1.0)

# Apply the quality-adjusted boost
if retriever_count == 2:
    base_boost = 1.5
    count_boost = 1.0 + (base_boost - 1.0) * quality_factor * pair_boost_modifier
elif retriever_count == 3:
    base_boost = 2.0
    count_boost = 1.0 + (base_boost - 1.0) * quality_factor
```

This means:
- High-confidence agreements (avg score ≥ 0.4) get the full boost
- Low-confidence agreements get proportionally less boost
- Two retrievers agreeing gives a max 1.5x boost
- Three retrievers agreeing gives a max 2.0x boost

### 4. Retriever Pair-Specific Adjustments

Not all retriever agreements are equal. We adjust the boost based on which specific retrievers agree:

```python
pair_boost_modifiers = {
    frozenset(['sparse', 'dense']): 1.2,    # Sparse and dense are more independent: +20% boost
    frozenset(['sparse', 'graph']): 1.1,    # Sparse and graph have some independence: +10% boost
    frozenset(['dense', 'graph']): 0.9,     # Dense and graph have more overlap: -10% boost
}
```

### 5. Graph Relationship Boosting

CWEs identified by the graph retriever with explicit relationships receive additional boosts:

```python
# Boost the graph retriever's weight if it found relationships
if retriever == 'graph' and is_relationship_based:
    relationship_boost = min(1.0 + (relationship_count * 0.1), 1.5)
    weight *= relationship_boost

# Add relationship bonus to final score
if is_relationship_based:
    relationship_bonus = 1.0 + min(relationship_count * 0.05, 0.3)  # Up to 30% bonus
```

### 6. Mapping Guidance Preference

We apply boosts based on MITRE's official mapping guidance:

```python
if mapping_usage == "ALLOWED":
    mapping_boost = 1.1  # 10% boost for explicitly allowed CWEs
elif mapping_usage == "ALLOWED-WITH-REVIEW":
    mapping_boost = 1.05  # 5% boost for CWEs allowed with review
elif mapping_usage == "DISCOURAGED":
    mapping_boost = 0.8  # 20% penalty for discouraged CWEs
elif mapping_usage == "PROHIBITED":
    mapping_boost = 0.5  # 50% penalty for prohibited CWEs
```

### 7. Parent-Child Chain Strength

We boost CWEs that form strong chains with their parents or children:

```python
# For child CWEs with high-scoring parents
max_parent_score = max(parent_scores)
chain_boost = 1.0 + min(0.15, max_parent_score * 0.2)

# For parent CWEs with multiple high-scoring children
avg_child_score = sum(child_scores) / len(child_scores)
child_chain_boost = 1.0 + min(0.1, avg_child_score * 0.15 * min(1.0, len(child_scores) / 3))
```

### 8. Final Score Calculation

The final score combines all these factors:

```python
combined_score = sum_score * count_boost * abstraction_factor * relationship_bonus * mapping_boost * chain_boost
```

## Example Calculation

Let's walk through a simplified example using CWE-917 from the Log4j vulnerability:

1. **Raw Scores**:
   - Dense: 0.505
   - Sparse: 1060.911
   - Graph: 0.477

2. **Normalized Scores**:
   - Dense: 0.505
   - Sparse: 1.0 (capped at 1000/1000)
   - Graph: 0.477

3. **Weighted Scores** (weights: dense=0.35, sparse=0.4, graph=0.25):
   - Dense: 0.505 * 0.35 = 0.177
   - Sparse: 1.0 * 0.4 = 0.4
   - Graph: 0.477 * 0.25 = 0.119
   - Sum: 0.696

4. **Quality-Adjusted Consensus Boost**:
   - Average score: (0.505 + 1.0 + 0.477) / 3 = 0.661
   - Quality factor: min(0.661 * 2.5, 1.0) = 1.0 (full boost)
   - Base boost for 3 retrievers: 2.0
   - Count boost: 1.0 + (2.0 - 1.0) * 1.0 = 2.0

5. **Abstraction Level Adjustment**:
   - CWE-917 is "Base" type: factor = 1.3

6. **Relationship Bonus** (assuming 2 relationships):
   - Relationship bonus: 1.0 + min(2 * 0.05, 0.3) = 1.1

7. **Mapping Guidance** (assuming "ALLOWED"):
   - Mapping boost: 1.1

8. **Chain Strength** (assuming parent score of 0.6):
   - Chain boost: 1.0 + min(0.15, 0.6 * 0.2) = 1.12

9. **Final Score**:
   - 0.696 * 2.0 * 1.3 * 1.1 * 1.1 * 1.12 = 2.462

This approach produces a final ranking that considers multiple factors and provides a sophisticated balance between different signals of CWE relevance.

## Benefits of This Approach

1. **Mapping Guidance Integration**: Incorporates MITRE's official guidance for appropriate CWE usage
2. **Hierarchical Context Awareness**: Considers parent-child relationships within the CWE hierarchy
3. **Prioritizes Direct Weakness Identification**: Gives highest weight to sparse retrieval that directly matches rootcause and weakness keyphrases
4. **Balanced Multi-Signal Integration**: Combines exact keyword matching, semantic similarity, and relationship information
5. **Quality-Aware Consensus**: Values agreement between retrievers but considers confidence levels
6. **Independence-Aware**: Accounts for overlap between retrievers when calculating boosts
7. **Structure-Aware**: Prioritizes CWEs with explicit relationships in the CWE database
8. **Specificity-Focused**: Favors more specific CWEs that provide actionable information

The end result is a ranking system that provides highly relevant CWE recommendations that consider both textual and structural information about vulnerabilities, while also respecting MITRE's official guidance and leveraging the CWE hierarchy.