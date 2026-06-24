# Perplexity

**Bifrost provider id:** `perplexity`
**Cynative chat-loop support:** ✅ supported

## Quick start

```bash
export PERPLEXITY_API_KEY=pplx-...
export CYNATIVE_LLM_PROVIDER=perplexity
export CYNATIVE_LLM_MODEL=sonar-pro
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: perplexity
  model: sonar-pro
  api_key: env.PERPLEXITY_API_KEY
```

## Authentication

Get a key from <https://www.perplexity.ai/settings/api>.

## Links

- Perplexity API docs: <https://docs.perplexity.ai/>
- Bifrost Perplexity provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/perplexity>
