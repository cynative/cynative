# Runware

**Bifrost provider id:** `runware`

## Quick start

```bash
export RUNWARE_API_KEY=...
export CYNATIVE_LLM_PROVIDER=runware
export CYNATIVE_LLM_MODEL=minimax:m2.7@0
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: runware
  model: minimax:m2.7@0
  api_key: env.RUNWARE_API_KEY
```

## Model names

Runware names models by their AIR identifier (`vendor:model@version`, e.g.
`minimax:m2.7@0`), not an OpenAI-style model name. Browse the catalog at
<https://runware.ai/models>.

## Authentication

Get a key from the Runware dashboard at <https://my.runware.ai/>.

## Links

- Runware OpenAI-compatibility docs: <https://runware.ai/docs/platform/openai>
- Bifrost Runware provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/runware>
