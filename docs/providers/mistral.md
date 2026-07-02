# Mistral

**Bifrost provider id:** `mistral`

## Quick start

```bash
export MISTRAL_API_KEY=...
export CYNATIVE_LLM_PROVIDER=mistral
export CYNATIVE_LLM_MODEL=mistral-large-latest
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: mistral
  model: mistral-large-latest
  api_key: env.MISTRAL_API_KEY
```

## Authentication

Get a key from <https://console.mistral.ai/api-keys>.

## Links

- Mistral API docs: <https://docs.mistral.ai/api/>
- Bifrost Mistral provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/mistral>
