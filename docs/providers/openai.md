# OpenAI

**Bifrost provider id:** `openai`

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
    base_url: https://api.openai.com
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
`network_config.base_url`. Leave `/v1` off: the provider appends
`/v1/chat/completions` itself, so a base URL ending in `/v1` requests
`/v1/v1/chat/completions` and gets a 404.

```yaml
llm:
  provider: openai
  model: my-deployment-name
  api_key: env.MY_PROXY_KEY
  network_config:
    base_url: https://my-proxy.example.com
```

## OAuth-minted bearer tokens

A gateway that takes short-lived OAuth tokens instead of a static key can be
reached through `llm.oauth`, Bifrost's `oauth_key_config`. Bifrost mints the
bearer from the token endpoint, caches it and refreshes it before it expires.

```yaml
llm:
  provider: openai
  model: my-deployment-name
  network_config:
    base_url: https://my-gateway.example.com
  oauth:
    grant_type: client_credentials       # or jwt_bearer
    token_url: https://login.example.com/oauth2/token
    client_id: env.GATEWAY_CLIENT_ID
    client_secret: env.GATEWAY_CLIENT_SECRET
    scopes: [inference]
```

Leave `llm.api_key` unset: a non-empty key value always wins and the OAuth
config is then ignored. `OPENAI_API_KEY` is not read when `llm.oauth` is set,
so an exported OpenAI key never reaches the gateway. The
`jwt_bearer` grant takes `private_key`, `issuer` and `audience` instead of the
client pair; see Bifrost's
[`schemas.OAuthKeyConfig`](https://github.com/maximhq/bifrost/blob/main/core/schemas/account.go)
for every field. Only the `openai` provider honours this block. On any other
provider Bifrost skips the key and the run fails with
`no keys found that support model`.

## Links

- OpenAI API reference: <https://platform.openai.com/docs/api-reference>
- Bifrost OpenAI provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/openai>
