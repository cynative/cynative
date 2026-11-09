# BytePlus ModelArk

**Bifrost provider id:** `byteplus`

## Quick start

```bash
export ARK_API_KEY=...
export CYNATIVE_LLM_PROVIDER=byteplus
export CYNATIVE_LLM_MODEL=seed-2-0-lite-260228
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: byteplus
  model: seed-2-0-lite-260228
  api_key: env.ARK_API_KEY
```

The API is OpenAI-compatible and served from
`https://ark.ap-southeast.bytepluses.com` (overridable via
`network_config.base_url`). The model is a ModelArk model id or the id of an
endpoint you created in the console; both carry a date suffix.

## Authentication

Create an API key in the ModelArk console. `ARK_API_KEY` is the name BytePlus's
own SDKs and examples read.

## Links

- BytePlus ModelArk docs: <https://docs.byteplus.com/en/docs/ModelArk>
- Bifrost BytePlus provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/byteplus>
