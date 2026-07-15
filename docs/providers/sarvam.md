# Sarvam

**Bifrost provider id:** `sarvam`

## Quick start

```bash
export SARVAM_API_KEY=sk_...
export CYNATIVE_LLM_PROVIDER=sarvam
export CYNATIVE_LLM_MODEL=sarvam-m
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: sarvam
  model: sarvam-m
  api_key: env.SARVAM_API_KEY
```

`sarvam-m` is the general chat model; larger models (Sarvam-30B, Sarvam-105B)
are listed on the models page below. The API is OpenAI-compatible and served
from `https://api.sarvam.ai` (overridable via `network_config.base_url`).

## Authentication

Get a key (format `sk_...`) from <https://dashboard.sarvam.ai/>.

## Links

- Sarvam API docs: <https://docs.sarvam.ai/api-reference-docs/introduction>
- Sarvam models: <https://docs.sarvam.ai/api-reference-docs/chat-completion/models/sarvam-m>
- Bifrost Sarvam provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/sarvam>
