# OpenCode Go

**Bifrost provider id:** `opencode-go`

Go is the subscription OpenCode gateway at `https://opencode.ai/zen/go` (the
OpenAI-compatible `/v1/chat/completions` path is appended automatically). It
shares the OpenCode implementation with `opencode-zen`, differing only in the
default base URL and billing model. Bifrost fills in the base URL, so you only
need the provider id, a model, and a key.

## Quick start

```bash
export OPENCODE_API_KEY=...
export CYNATIVE_LLM_PROVIDER=opencode-go
export CYNATIVE_LLM_MODEL=claude-opus-4.8
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: opencode-go
  model: claude-opus-4.8
  api_key: env.OPENCODE_API_KEY
```

## Authentication

Sign in to OpenCode and copy your API key from <https://opencode.ai/zen>. Both
OpenCode gateways (`opencode-go` and `opencode-zen`) authenticate with the same
OpenCode account key, so the canonical fallback var is `OPENCODE_API_KEY` for
both; cynative reads it when neither `llm.api_key` nor `llm.keys` is set.

Fetch the available model ids from <https://opencode.ai/zen/go/v1/models>.

## Links

- OpenCode docs: <https://opencode.ai/docs/>
- Bifrost OpenCode provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/opencode>
