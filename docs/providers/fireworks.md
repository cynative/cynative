# Fireworks AI

**Bifrost provider id:** `fireworks`

## Quick start

```bash
export FIREWORKS_API_KEY=fw_...
export CYNATIVE_LLM_PROVIDER=fireworks
export CYNATIVE_LLM_MODEL=accounts/fireworks/models/llama-v3p3-70b-instruct
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: fireworks
  model: accounts/fireworks/models/llama-v3p3-70b-instruct
  api_key: env.FIREWORKS_API_KEY
```

## Authentication

Get a key from <https://fireworks.ai/account/api-keys>.

## Links

- Fireworks API docs: <https://docs.fireworks.ai/>
- Bifrost Fireworks provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/fireworks>
