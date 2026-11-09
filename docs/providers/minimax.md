# MiniMax

**Bifrost provider id:** `minimax`

## Quick start

```bash
export MINIMAX_API_KEY=...
export CYNATIVE_LLM_PROVIDER=minimax
export CYNATIVE_LLM_MODEL=MiniMax-M3
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: minimax
  model: MiniMax-M3
  api_key: env.MINIMAX_API_KEY
```

The API is OpenAI-compatible and served from `https://api.minimax.io`
(overridable via `network_config.base_url`, for example for the mainland China
endpoint). Model ids are case-sensitive; check the models page below for the
current list.

## Authentication

Create an API key in the MiniMax developer platform.

## Links

- MiniMax API docs: <https://platform.minimax.io/docs>
- Bifrost MiniMax provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/minimax>
