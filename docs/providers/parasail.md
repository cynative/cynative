# Parasail

**Bifrost provider id:** `parasail`

## Quick start

```bash
export PARASAIL_API_KEY=...
export CYNATIVE_LLM_PROVIDER=parasail
export CYNATIVE_LLM_MODEL=parasail-l3.3-70b
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: parasail
  model: parasail-l3.3-70b
  api_key: env.PARASAIL_API_KEY
```

## Authentication

Get a key from the Parasail dashboard.

## Links

- Parasail docs: <https://parasail.io/>
- Bifrost Parasail provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/parasail>
