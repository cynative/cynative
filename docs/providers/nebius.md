# Nebius AI Studio

**Bifrost provider id:** `nebius`

## Quick start

```bash
export NEBIUS_API_KEY=...
export CYNATIVE_LLM_PROVIDER=nebius
export CYNATIVE_LLM_MODEL=meta-llama/Llama-3.3-70B-Instruct
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: nebius
  model: meta-llama/Llama-3.3-70B-Instruct
  api_key: env.NEBIUS_API_KEY
```

## Authentication

Get a key from the Nebius AI Studio console.

## Links

- Nebius AI Studio docs: <https://studio.nebius.ai/>
- Bifrost Nebius provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/nebius>
