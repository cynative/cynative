# OpenAI

**Bifrost provider id:** `openai`
**Cynative chat-loop support:** ✅ supported

## Quick start

```bash
export OPENAI_API_KEY=sk-...
export CYNATIVE_LLM_PROVIDER=openai
export CYNATIVE_LLM_MODEL=gpt-5
cynative -p "list IAM users in my AWS account that have console access"
```

No YAML file is required.

## YAML

```yaml
llm:
  provider: openai
  model: gpt-5
  api_key: env.OPENAI_API_KEY     # optional — falls back to OPENAI_API_KEY
  network_config:
    base_url: https://api.openai.com/v1
    default_request_timeout_in_seconds: 60
    max_retries: 3
  openai_config:
    disable_store: true            # opt out of OpenAI's conversation storage
```

## Authentication

Cynative resolves the API key in this order:

1. `llm.api_key` in YAML (or `CYNATIVE_LLM_API_KEY` env var) — recommended for the simple case.
2. `llm.keys[]` in YAML — for explicit Bifrost-shaped key configuration (multi-key load balancing, model filters, etc.).
3. `OPENAI_API_KEY` — the canonical fallback, used when neither `llm.api_key` nor `llm.keys[]` is set.

Setting both `llm.api_key` and `llm.keys[]` is rejected at startup with a clear error — pick one.

Get a key from <https://platform.openai.com/api-keys>.

## OpenAI-specific YAML fields

`openai_config` mirrors Bifrost's `schemas.OpenAIConfig` directly. The
fields most users touch:

| Field             | Purpose                                                                 |
|-------------------|-------------------------------------------------------------------------|
| `disable_store`   | Opt out of OpenAI's persistent conversation storage (`store=false`).    |

For the full set, see Bifrost's [`schemas.OpenAIConfig`](https://github.com/maximhq/bifrost/blob/main/core/schemas/provider.go).

## Custom OpenAI-compatible endpoints

Many proxies (LiteLLM, vLLM with `--api-key`, OpenRouter) speak the OpenAI
Chat Completions API. Point cynative at them by overriding
`network_config.base_url`:

```yaml
llm:
  provider: openai
  model: my-deployment-name
  api_key: env.MY_PROXY_KEY
  network_config:
    base_url: https://my-proxy.example.com/v1
```

## Links

- OpenAI API reference: <https://platform.openai.com/docs/api-reference>
- Bifrost OpenAI provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/openai>
