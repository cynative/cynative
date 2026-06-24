# SGLang

**Bifrost provider id:** `sgl`
**Cynative chat-loop support:** ✅ supported

## Quick start

```bash
export CYNATIVE_LLM_PROVIDER=sgl
export CYNATIVE_LLM_MODEL=meta-llama/Llama-3.3-70B-Instruct
export CYNATIVE_LLM_SGL_URL=http://localhost:30000
cynative -p "..."
```

No YAML file is required. `CYNATIVE_LLM_SGL_URL` sets `sgl_key_config.url`
directly.

## YAML

```yaml
llm:
  provider: sgl
  model: meta-llama/Llama-3.3-70B-Instruct
  keys:
    - value: ""                  # no API key by default
      models: ["*"]
      weight: 1.0
      sgl_key_config:
        url: http://localhost:30000
```

## Authentication

SGLang servers are typically run without authentication. If you've put SGLang
behind an auth proxy, put the proxy token in the key's `value:` field (in the
`keys[]` YAML above), or use the env-only path (`CYNATIVE_LLM_API_KEY` +
`CYNATIVE_LLM_SGL_URL`, no `keys[]`). Do not combine a top-level
`api_key`/`CYNATIVE_LLM_API_KEY` with a `keys[]` block; the loader rejects that.

## Links

- SGLang docs: <https://docs.sglang.ai/>
- Bifrost SGL provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/sgl>
