# OpenCode Zen

**Bifrost provider id:** `opencode-zen`

Zen is the pay-as-you-go OpenCode gateway at `https://opencode.ai/zen` (the
OpenAI-compatible `/v1/chat/completions` path is appended automatically). Bifrost
fills in the base URL, so you only need the provider id, a model, and a key.

## Quick start

```bash
export OPENCODE_API_KEY=...
export CYNATIVE_LLM_PROVIDER=opencode-zen
export CYNATIVE_LLM_MODEL=claude-opus-4.8
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: opencode-zen
  model: claude-opus-4.8
  api_key: env.OPENCODE_API_KEY
```

## Authentication

Sign in to OpenCode Zen, add your billing details, and copy your API key from
<https://opencode.ai/zen>. Both OpenCode gateways (`opencode-zen` and
`opencode-go`) authenticate with the same OpenCode account key, so the canonical
fallback var is `OPENCODE_API_KEY` for both; cynative reads it when neither
`llm.api_key` nor `llm.keys` is set.

Fetch the available model ids from <https://opencode.ai/zen/v1/models> — Zen
exposes models across the GPT, Claude, Gemini, and several open-weight families.

## Links

- OpenCode Zen docs: <https://opencode.ai/docs/zen/>
- Bifrost OpenCode provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/opencode>
