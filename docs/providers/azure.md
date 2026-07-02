# Azure OpenAI

**Bifrost provider id:** `azure`

## Quick start

```bash
export AZURE_OPENAI_API_KEY=...
export CYNATIVE_LLM_PROVIDER=azure
export CYNATIVE_LLM_MODEL=gpt-4o-prod-deployment   # your Azure deployment name
export CYNATIVE_LLM_AZURE_ENDPOINT=https://my-resource.openai.azure.com
cynative -p "..."
```

No YAML file is required, but the endpoint is mandatory: set
`CYNATIVE_LLM_AZURE_ENDPOINT` (or `llm.azure.endpoint`). A bare
`AZURE_OPENAI_API_KEY` with no endpoint fails at load rather than panicking at
request time. The Azure `api-version` is selected by Bifrost per route; Cynative
exposes **no setting to override it** (there is no `CYNATIVE_LLM_AZURE_API_VERSION`
env var and no top-level field — Bifrost's per-alias `api_version` lives on an
embedded alias struct that Cynative's YAML loader does not surface).

If your model id differs from the Azure
deployment name, map it with YAML key `aliases` (see below).

## YAML

The flat form (env-only equivalent) — endpoint under the `azure` block:

```yaml
llm:
  provider: azure
  model: gpt-4o-prod-deployment
  api_key: env.AZURE_OPENAI_API_KEY
  azure:
    endpoint: https://my-resource.openai.azure.com
```

The full `keys[]` form, for multi-key setups or a model→deployment alias map:

```yaml
llm:
  provider: azure
  model: my-model-id
  keys:
    - value: env.AZURE_OPENAI_API_KEY
      models: ["*"]
      weight: 1.0
      aliases:
        my-model-id:
          model_id: gpt-4o-prod-deployment   # model id → Azure deployment name
      azure_key_config:
        endpoint: https://my-resource.openai.azure.com
```

## Authentication

Get keys + endpoints from the Azure portal under Cognitive Services →
Azure OpenAI → Keys and Endpoints. By default cynative passes the model id
verbatim to Azure as the deployment name; if they differ, map model id →
deployment via the key's `aliases:` map (Bifrost's `Key.Aliases`).

## Links

- Azure OpenAI docs: <https://learn.microsoft.com/azure/ai-services/openai/>
- Bifrost Azure provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/azure>
