# xAI (Grok)

**Bifrost provider id:** `xai`

## Quick start

```bash
export XAI_API_KEY=xai-...
export CYNATIVE_LLM_PROVIDER=xai
export CYNATIVE_LLM_MODEL=grok-3
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: xai
  model: grok-3
  api_key: env.XAI_API_KEY
```

## Authentication

Get a key from <https://console.x.ai/>.

## Links

- xAI API docs: <https://docs.x.ai/>
- Bifrost xAI provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/xai>
