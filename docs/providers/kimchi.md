# Kimchi

**Bifrost provider id:** `kimchi`

## Quick start

```bash
export KIMCHI_API_KEY=...
export CYNATIVE_LLM_PROVIDER=kimchi
export CYNATIVE_LLM_MODEL=deepseek-v4.1-flash
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: kimchi
  model: deepseek-v4.1-flash
  api_key: env.KIMCHI_API_KEY
```

Kimchi serves open-weight models over an OpenAI-compatible API. Bifrost's
default base URL is `https://llm.kimchi.dev/openai` and it appends
`/v1/chat/completions` itself, so a `network_config.base_url` override must
leave out the trailing `/v1`. The model APIs page below lists the current
model ids.

## Authentication

Create an API key in the Kimchi dashboard at <https://app.kimchi.dev>.

## Links

- Kimchi site: <https://kimchi.dev/>
- Kimchi model APIs: <https://docs.kimchi.dev/docs/model-apis-overview>
- Bifrost Kimchi provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/kimchi>
