# LLM Provider Guide

- [LLM Provider Guide](#llm-provider-guide)
  - [System Architecture Overview](#system-architecture-overview)
  - [Configurable LLM Providers for Agents](#configurable-llm-providers-for-agents)
  - [Environment Variables](#environment-variables)
  - [Config.yaml Settings](#configyaml-settings)
  - [Fixed Components](#fixed-components)
  - [Command Line Override](#command-line-override)
  - [Dependencies](#dependencies)
  - [Example Usage](#example-usage)
    - [Basic Example with Default Provider](#basic-example-with-default-provider)
    - [Specifying a Provider for Agents](#specifying-a-provider-for-agents)
    - [Processing a CSV with OpenAI for Agents](#processing-a-csv-with-openai-for-agents)
  - [Troubleshooting](#troubleshooting)
    - [API Key Issues](#api-key-issues)
    - [Missing Dependencies](#missing-dependencies)
    - [Model Not Found](#model-not-found)


This guide explains how to configure LLM providers in the CWE Knowledge Base system, which uses a combination of different AI providers for specific components.

## System Architecture Overview

The CWE Knowledge Base uses multiple AI providers, each with a specialized role:

1. **Agent LLMs** (configurable): These power the analyzer, critic, and resolver agents that perform vulnerability analysis
2. **OpenAI Embeddings** (fixed): Used for generating vector embeddings for CWE entries
3. **Anthropic Contextual Retriever** (fixed): Used for generating enhanced context descriptions for CWE entries (cached for efficiency)

## Configurable LLM Providers for Agents

You can configure which LLM provider powers the analysis agents:

1. **Anthropic** (Claude models)
2. **Google Gemini** (Gemini models)
3. **OpenAI** (GPT models)

## Environment Variables

Ensure you have the appropriate API keys set in your environment:

```bash
# For Anthropic (Claude) - Required for contextual retrieval regardless of agent configuration
export ANTHROPIC_API_KEY=your_anthropic_api_key

# For Google Gemini - Required if using Gemini for agents
export GOOGLE_API_KEY=your_gemini_api_key

# For OpenAI - Required for embeddings and if using OpenAI for agents
export OPENAI_API_KEY=your_openai_api_key
```

You can also create a `.env` file in the project root (or at the path specified in `config.settings`):

```
ANTHROPIC_API_KEY=your_anthropic_api_key
GOOGLE_API_KEY=your_gemini_api_key
OPENAI_API_KEY=your_openai_api_key
```

## Config.yaml Settings

Update your `config.yaml` file to specify the LLM provider and model for the agents:

```yaml
# Anthropic configuration for agents
llm_config:
  llm_type: "anthropic"
  api_key: "${ANTHROPIC_API_KEY}"
  model: "claude-3-haiku-20240307"  # Or claude-3-sonnet-20240229, claude-3-opus-20240229, etc.
  temperature: 0.7
  max_tokens: 2048
```

```yaml
# Google Gemini configuration for agents
llm_config:
  llm_type: "gemini"
  api_key: "${GOOGLE_API_KEY}"
  model: "gemini-2.0-flash"  # Or gemini-pro
  temperature: 0.7
  max_tokens: 2048
```

```yaml
# OpenAI configuration for agents
llm_config:
  llm_type: "openai"
  api_key: "${OPENAI_API_KEY}"
  model: "gpt-4"  # Or gpt-3.5-turbo, etc.
  temperature: 0.7
  max_tokens: 2048
```

## Fixed Components

These components use specific providers and are not configurable through the `llm_config`:

1. **Embeddings**: Always uses OpenAI with the `text-embedding-3-small` model
2. **Contextual Retrieval**: Always uses Anthropic Claude for generating enhanced context descriptions of CWE entries (with caching for efficiency)

## Command Line Override

You can override the agent LLM provider from the command line:

```bash
python src/main.py --llm-provider gemini
```

This will use the Gemini provider for agents regardless of what's in the config file.

## Dependencies

Ensure you have installed all necessary dependencies:

```bash
# Required for all configurations
pip install langchain-openai langchain-anthropic

# Required if using Gemini
pip install langchain-google-genai
```

## Example Usage

### Basic Example with Default Provider

```bash
python src/main.py
```

### Specifying a Provider for Agents

```bash
python src/main.py --llm-provider gemini
```

### Processing a CSV with OpenAI for Agents

```bash
python src/main.py --llm-provider openai --csv ./data_in/test_cves.csv --output-dir ./cwe_assign_reports
```

## Troubleshooting

### API Key Issues

If you see errors related to API keys:

1. Check that all required environment variables are set:
   - `OPENAI_API_KEY` (required for all configurations)
   - `ANTHROPIC_API_KEY` (required for all configurations)
   - `GOOGLE_API_KEY` (required only if using Gemini for agents)

2. Verify each API key is valid and not expired

### Missing Dependencies

If you see import errors, install all necessary dependencies:

```bash
pip install langchain-openai langchain-anthropic langchain-google-genai
```

### Model Not Found

If you see errors about models not being found:

1. Check that you're using a valid model name for the selected provider
2. Ensure your API key has access to the specified model