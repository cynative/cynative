# OpenRouter

**Bifrost provider id:** `openrouter`
**Cynative chat-loop support:** ✅ supported

## Quick start

```bash
export OPENROUTER_API_KEY=sk-or-...
export CYNATIVE_LLM_PROVIDER=openrouter
export CYNATIVE_LLM_MODEL=anthropic/claude-opus-4
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: openrouter
  model: anthropic/claude-opus-4
  api_key: env.OPENROUTER_API_KEY
  network_config:
    extra_headers:
      HTTP-Referer: https://yourapp.example.com
      X-Title: Cynative
```

## Authentication

Get a key from <https://openrouter.ai/keys>. The `HTTP-Referer` and
`X-Title` headers are optional but recommended (they let OpenRouter
attribute usage in your dashboard).

## Links

- OpenRouter docs: <https://openrouter.ai/docs>
- Bifrost OpenRouter provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/openrouter>
