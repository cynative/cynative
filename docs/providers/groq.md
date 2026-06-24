# Groq

**Bifrost provider id:** `groq`
**Cynative chat-loop support:** ✅ supported

## Quick start

```bash
export GROQ_API_KEY=gsk_...
export CYNATIVE_LLM_PROVIDER=groq
export CYNATIVE_LLM_MODEL=llama-3.3-70b-versatile
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: groq
  model: llama-3.3-70b-versatile
  api_key: env.GROQ_API_KEY
```

## Authentication

Get a key from <https://console.groq.com/keys>.

## Links

- Groq API docs: <https://console.groq.com/docs/api-reference>
- Bifrost Groq provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/groq>
