# Ollama

**Bifrost provider id:** `ollama`
**Cynative chat-loop support:** ✅ supported

## Quick start

```bash
# Assumes Ollama running at http://localhost:11434
export CYNATIVE_LLM_PROVIDER=ollama
export CYNATIVE_LLM_MODEL=llama3.3
export CYNATIVE_LLM_OLLAMA_URL=http://localhost:11434
cynative -p "..."
```

> **Note:** Ollama takes its endpoint from `ollama_key_config.url` (env
> `CYNATIVE_LLM_OLLAMA_URL`), **not** the generic `network_config.base_url`. Setting
> `CYNATIVE_LLM_NETWORK_CONFIG_BASE_URL` for Ollama fails with "provider has no keys configured: ollama".

## YAML

```yaml
llm:
  provider: ollama
  model: llama3.3
  keys:
    - value: ""                  # no API key
      models: ["*"]
      weight: 1.0
      ollama_key_config:
        url: http://localhost:11434
```

## Authentication

Ollama doesn't require an API key; cynative talks to it over HTTP at the
URL you configure. Run `ollama serve` locally (or point at a remote
Ollama instance) and set the `url`.

## Links

- Ollama docs: <https://github.com/ollama/ollama/blob/main/docs/api.md>
- Bifrost Ollama provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/ollama>
