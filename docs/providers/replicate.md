# Replicate

**Bifrost provider id:** `replicate`

## Quick start

```bash
export REPLICATE_API_TOKEN=r8_...
export CYNATIVE_LLM_PROVIDER=replicate
export CYNATIVE_LLM_MODEL=meta/meta-llama-3.3-70b-instruct
cynative -p "..."
```

## YAML

Pick **one** form — a top-level `api_key` and a `keys[]` block cannot coexist
(the loader rejects that).

**Simple (single key):**

```yaml
llm:
  provider: replicate
  model: meta/meta-llama-3.3-70b-instruct
  api_key: env.REPLICATE_API_TOKEN
```

**Multi-key / load balancing:**

```yaml
llm:
  provider: replicate
  model: meta/meta-llama-3.3-70b-instruct
  keys:
    - value: env.REPLICATE_API_TOKEN
      models: ["*"]
      weight: 1.0
      replicate_key_config: {}
```

## Authentication

Replicate uses `REPLICATE_API_TOKEN` (not `_API_KEY`). Get a token from
<https://replicate.com/account/api-tokens>.

## Links

- Replicate API docs: <https://replicate.com/docs/reference/http>
- Bifrost Replicate provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/replicate>
