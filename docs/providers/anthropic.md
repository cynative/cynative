# Anthropic

**Bifrost provider id:** `anthropic`

## Quick start

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export CYNATIVE_LLM_PROVIDER=anthropic
export CYNATIVE_LLM_MODEL=claude-opus-4-7
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: anthropic
  model: claude-opus-4-7
  api_key: env.ANTHROPIC_API_KEY
  network_config:
    extra_headers:
      anthropic-beta: tools-2024-04-04
```

## Authentication

Get a key from <https://console.anthropic.com/settings/keys>. Cynative reads
it from `llm.api_key`, `CYNATIVE_LLM_API_KEY`, or `ANTHROPIC_API_KEY` —
in that order.

## Workload identity federation

A workload that holds an OIDC identity token (a Kubernetes projected service
account token, a CI OIDC token) can authenticate without a static key through
`llm.anthropic.workload_identity`, Bifrost's `anthropic_key_config`. Bifrost
exchanges the identity token at `{base_url}/v1/oauth/token` for a short-lived
access token, caches it and exchanges again before it expires.

```yaml
llm:
  provider: anthropic
  model: claude-opus-4-7
  anthropic:
    workload_identity:
      federation_rule_id: fdrl_...
      organization_id: 00000000-0000-0000-0000-000000000000
      service_account_id: svac_...
      workspace_id: wrkspc_...           # only when the rule spans several workspaces
      identity_source:
        type: file                       # re-read on every exchange, so a rotated token is picked up
        path: /var/run/secrets/tokens/anthropic
        # or: type: inline, token: env.ANTHROPIC_IDENTITY_TOKEN
```

Leave `llm.api_key` unset: a non-empty key value always wins and the
federation is then skipped. `ANTHROPIC_API_KEY` is not read when
`llm.anthropic.workload_identity` is set, so an exported key never replaces
the federated token. Every field also has an env form, for example
`CYNATIVE_LLM_ANTHROPIC_WORKLOAD_IDENTITY_FEDERATION_RULE_ID` and
`CYNATIVE_LLM_ANTHROPIC_WORKLOAD_IDENTITY_IDENTITY_SOURCE_PATH`. Only the
`anthropic` provider honours this block. On any other provider Bifrost skips
the key, so a single-key setup fails with `no keys found that support model`.

## Reasoning (extended thinking)

```yaml
llm:
  provider: anthropic
  model: claude-opus-4-7
  api_key: env.ANTHROPIC_API_KEY
  reasoning_effort: high       # pick ONE: effort derives a budget (adaptive on Opus 4.7+)…
  reasoning_max_tokens: 8192   # …or an explicit budget (pre-4.7; takes priority over effort)
```

`reasoning_effort` alone derives a thinking budget from the effort level
(newer models use adaptive thinking). `reasoning_max_tokens` takes priority
over the effort level: on pre-4.7 models it sets the thinking budget
explicitly (minimum 1024 — smaller budgets fail at request time); on Opus
4.7+ the numeric value is discarded and any budget simply switches on
adaptive thinking. `reasoning_effort: none` disables thinking; combining it
with `reasoning_max_tokens` is rejected at config validation.

## Links

- Anthropic API reference: <https://docs.anthropic.com/en/api>
- Bifrost Anthropic provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/anthropic>
