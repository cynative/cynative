# Baseten

**Bifrost provider id:** `baseten`

## Quick start

```bash
export BASETEN_API_KEY=...
export CYNATIVE_LLM_PROVIDER=baseten
export CYNATIVE_LLM_MODEL=zai-org/GLM-5.3
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: baseten
  model: zai-org/GLM-5.3
  api_key: env.BASETEN_API_KEY
```

Cynative talks to Baseten Model APIs, the shared OpenAI-compatible host at
`https://inference.baseten.co/v1` (overridable via `network_config.base_url`).
Model ids are `<org>/<model>` slugs such as `zai-org/GLM-5.3` or
`openai/gpt-oss-120b`; the Model APIs page below lists the current ones.

## Authentication

Create an API key at <https://app.baseten.co/settings/api_keys>.

## Links

- Baseten site: <https://www.baseten.co/>
- Baseten Model APIs: <https://docs.baseten.co/development/model-apis/overview>
- Bifrost Baseten provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/baseten>
