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
