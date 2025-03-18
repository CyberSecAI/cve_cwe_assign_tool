
# Application Entry Point
main.py::main()
├── ConfigManager initialization
├── initialize_embedding_client()
├── Initialize retrievers and databases
└── VulnerabilityProcessor initialization
    └── processor.process_file("vulnerabilities.csv") or processor.process_directory()
        ├── Read CSV file
        ├── For each vulnerability entry:
        │   └── processor.process_vulnerability(vulnerability_entry)
        │       │
        │       ├── # Phase 1: Preparation
        │       ├── prepare_vulnerability_info(entry)
        │       │   ├── Create VulnerabilityInfo object
        │       │   ├── Extract keyphrases if available
        │       │   └── Gather reference content if available
        │       │
        │       ├── # Phase 2: Initial Analysis
        │       ├── analyzer.generate_response(vulnerability_info.description)
        │       │   ├── validate_input(input_text, max_input_length)
        │       │   │
        │       │   ├── # Search for relevant CWEs
        │       │   ├── retriever.search(input_text, k=5, use_graph=True, use_rag=True, rerank=False)
        │       │   │   ├── _prepare_keyphrases(keyphrases)
        │       │   │   │
        │       │   │   ├── _execute_searches(query, filtered_keyphrases, k, use_graph, use_rag, use_sparse)
        │       │   │   │   │
        │       │   │   │   ├── # First search method: Graph-based
        │       │   │   │   ├── IF use_graph=True:
        │       │   │   │   │   ├── graph_results = _search_with_graph(query, k)
        │       │   │   │   │   │   └── property_graph.search(query, k*2, include_text=True)
        │       │   │   │   │   └── formatted_graph_results = _format_graph_results(graph_results)
        │       │   │   │   │       # Adds metadata, mapping notes, mitigations from cwe_entries
        │       │   │   │   │
        │       │   │   │   ├── # Second search method: Dense vector (RAG)
        │       │   │   │   ├── IF use_rag=True:
        │       │   │   │   │   ├── dense_results = _search_with_rag(query, filtered_keyphrases, k)
        │       │   │   │   │   │   └── dense_retriever.search(enhanced_query, k*2)
        │       │   │   │   │   └── formatted_rag_results = _format_rag_results(dense_results)
        │       │   │   │   │
        │       │   │   │   ├── # Third search method: Sparse retrieval (BM25)
        │       │   │   │   ├── IF use_sparse=True:
        │       │   │   │   │   ├── sparse_results = _search_with_sparse(query, filtered_keyphrases, k, cve_id)
        │       │   │   │   │   │   ├── IF keyphrases:
        │       │   │   │   │   │   │   └── sparse_retriever.search_with_keyphrases(query,filtered_keyphrases k*2)
        │       │   │   │   │   │   └── ELSE:
        │       │   │   │   │   │       └── sparse_retriever.search(query, k*2)
        │       │   │   │   │   └── formatted_sparse_results = _format_sparse_results(sparse_results)
        │       │   │   │   │
        │       │   │   │   └── Return all_results, result_sources, result_scores, retriever_results
        │       │   │   │
        │       │   │   ├── _log_raw_results() # If cve_id is provided
        │       │   │   └── Return raw search results
        │       │   │
        │       │   ├── # Process search results for LLM
        │       │   ├── context = _build_enhanced_context(cwe_results)
        │       │   ├── retrieved_cwes_table = _build_cwe_table(cwe_results)
        │       │   ├── retriever_interpretation = _get_retriever_interpretation()
        │       │   ├── mapping_guidance = _create_mapping_guidance_section(cwe_results)
        │       │   ├── mitigations_guidance = _create_mitigations_guidance_section(cwe_results)
        │       │   │
        │       │   ├── # Create prompt and get LLM response
        │       │   ├── prompt = analysis_template.format(...)
        │       │   ├── llm_response = _call_llm(prompt)
        │       │   ├── response_text = llm_response["response"]
        │       │   │
        │       │   ├── # Extract CWE IDs from response
        │       │   ├── IF self.role == "analyzer":
        │       │   │   └── extracted_cwe_ids = _extract_cwe_references(response_text)
        │       │   ├── IF self.role == "critic":
        │       │   │   └── Process critic-specific logic
        │       │   │
        │       │   └── Return formatted response with CWE IDs
        │       │
        │       ├── # For RelationshipEnhancedLLMAgent, add relationship analysis
        │       ├── IF using RelationshipEnhancedLLMAgent:
        │       │   └── Additional relationship analysis is performed
        │       │       ├── super().generate_response(input_text) # Call parent method
        │       │       ├── relationship_analyzer.incorporate_into_analysis(cwe_ids, vulnerability_description)
        │       │       └── enhance_response_with_relationships(response_text, relationship_analysis)
        │       │
        │       ├── # Phase 3: Criticism
        │       ├── critic_input = _create_critic_input(vulnerability_info.analysis, vulnerability_info.description)
        │       ├── critic.generate_response(critic_input)
        │       │   └── Similar flow as analyzer, but with critic-specific prompt
        │       │
        │       ├── # Phase 4: Resolution
        │       ├── resolver_input = combine analyzer output and criticism
        │       ├── resolver.generate_response(resolver_input)
        │       │   └── Similar flow as analyzer, but with resolver-specific prompt
        │       │
        │       └── Return processed vulnerability info
        │
        └── Return all processing results