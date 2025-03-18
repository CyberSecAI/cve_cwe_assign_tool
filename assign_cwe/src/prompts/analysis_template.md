{role_prompt}

Relevant CWE Information:
{context}

## Retrieved CWEs and Scores
| CWE ID | Name | Relevance Score | Mapping Usage |
|--------|------|----------------|---------------|
{retrieved_cwes_table}

### Retriever Score Interpretation
{retriever_interpretation}

### Mapping Guidance
{mapping_guidance}

### Potential Mitigations
{mitigations_guidance}

Current Input:
{input_text}

Based on the above information, provide your analysis. 
Consider the following key aspects:

1. **Content Matching**
   - Match the vulnerability description against CWE descriptions
   - Identify technical indicators that align with specific CWE characteristics
   - Pay special attention to CWEs with high relevance scores

2. **Relationship Analysis**
   - Evaluate hierarchical relationships (ChildOf, ParentOf) to find the optimal level of specificity
   - Examine chain relationships (CanPrecede, CanFollow, RequiredBy, Requires) to identify potential vulnerability chains
   - Consider peer relationships (PeerOf, CanAlsoBe) that may offer alternative classifications
   - Assess abstraction levels (Pillar, Class, Base, Variant) to ensure appropriate granularity

3. **Mapping Guidance Analysis**
   - Consider the official MITRE mapping guidance when selecting CWEs
   - Pay attention to Usage recommendations (ALLOWED, DISCOURAGED, PROHIBITED)
   - Review the provided rationale for mapping decisions
   - Consider suggested alternative mappings where appropriate

4. **Mitigation Analysis**
   - Consider how the potential mitigations align with the vulnerability description
   - Use mitigation information to help understand the nature of the weakness
   - Evaluate whether the mitigations would address the specific vulnerability described

5. **Evidence-Based Decision Making**
   - Use specific evidence from the vulnerability description to justify your classification
   - Consider how relationship context enhances your understanding of the vulnerability
   - Evaluate confidence based on both direct evidence and relationship insights
   - Consider the retriever scores as supporting evidence for your decisions

Your response should be detailed and well-structured, incorporating evidence, relationship analysis, 
mapping guidance, and mitigation insights. Remember to explicitly reference how these factors 
influenced your classification decisions.