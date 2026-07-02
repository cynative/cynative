# Cerebras

**Bifrost provider id:** `cerebras`

## Quick start

```bash
export CEREBRAS_API_KEY=...
export CYNATIVE_LLM_PROVIDER=cerebras
export CYNATIVE_LLM_MODEL=llama-3.3-70b
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: cerebras
  model: llama-3.3-70b
  api_key: env.CEREBRAS_API_KEY
```

## Authentication

Get a key from <https://cloud.cerebras.ai/>.

## Links

- Cerebras Cloud docs: <https://docs.cerebras.net/>
- Bifrost Cerebras provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/cerebras>
