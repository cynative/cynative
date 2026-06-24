# vLLM

**Bifrost provider id:** `vllm`
**Cynative chat-loop support:** ✅ supported

## Quick start

```bash
export CYNATIVE_LLM_PROVIDER=vllm
export CYNATIVE_LLM_MODEL=meta-llama/Llama-3.3-70B-Instruct
export CYNATIVE_LLM_VLLM_URL=http://localhost:8000
cynative -p "..."
```

No YAML file is required. `CYNATIVE_LLM_VLLM_URL` sets `vllm_key_config.url`
directly; `CYNATIVE_LLM_VLLM_MODEL_NAME` is also accepted for per-key routing.

## YAML

```yaml
llm:
  provider: vllm
  model: meta-llama/Llama-3.3-70B-Instruct
  keys:
    - value: ""                       # set if you launched vLLM with --api-key
      models: ["*"]
      weight: 1.0
      vllm_key_config:
        url: http://localhost:8000
```

## Authentication

vLLM is unauthenticated by default. If you launched it with `--api-key <token>`,
put that token in the key's `value:` field (in the `keys[]` YAML above). The
env-only path (no YAML) instead uses `CYNATIVE_LLM_API_KEY` together with
`CYNATIVE_LLM_VLLM_URL` — that path has no `keys[]`, so there is no conflict. Do
not combine a top-level `api_key`/`CYNATIVE_LLM_API_KEY` with a `keys[]` block;
the loader rejects that.

## Links

- vLLM docs: <https://docs.vllm.ai/>
- Bifrost vLLM provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/vllm>
