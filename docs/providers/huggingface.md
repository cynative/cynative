# Hugging Face Inference

**Bifrost provider id:** `huggingface`

## Quick start

```bash
export HUGGINGFACE_API_KEY=hf_...
export CYNATIVE_LLM_PROVIDER=huggingface
export CYNATIVE_LLM_MODEL=meta-llama/Llama-3.3-70B-Instruct
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: huggingface
  model: meta-llama/Llama-3.3-70B-Instruct
  api_key: env.HUGGINGFACE_API_KEY
```

## Authentication

Get a User Access Token from <https://huggingface.co/settings/tokens>.
The "read" role is sufficient for inference; "write" is not required.

## Links

- Hugging Face Inference API docs: <https://huggingface.co/docs/api-inference>
- Bifrost Hugging Face provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/huggingface>
