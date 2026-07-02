# Cohere

**Bifrost provider id:** `cohere`

## Quick start

```bash
export COHERE_API_KEY=...
export CYNATIVE_LLM_PROVIDER=cohere
export CYNATIVE_LLM_MODEL=command-r-plus
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: cohere
  model: command-r-plus
  api_key: env.COHERE_API_KEY
```

## Authentication

Get a key from <https://dashboard.cohere.com/api-keys>.

## Links

- Cohere API reference: <https://docs.cohere.com/reference/about>
- Bifrost Cohere provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/cohere>
