# DeepSeek

**Bifrost provider id:** `deepseek`

## Quick start

```bash
export DEEPSEEK_API_KEY=sk-...
export CYNATIVE_LLM_PROVIDER=deepseek
export CYNATIVE_LLM_MODEL=deepseek-chat
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: deepseek
  model: deepseek-chat
  api_key: env.DEEPSEEK_API_KEY
```

`deepseek-chat` is the general model; `deepseek-reasoner` is the reasoning
model. The API is OpenAI-compatible and served from
`https://api.deepseek.com` (overridable via `network_config.base_url`).

## Authentication

Get a key from <https://platform.deepseek.com/api_keys>.

## Links

- DeepSeek API docs: <https://api-docs.deepseek.com/>
- Bifrost DeepSeek provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/deepseek>
