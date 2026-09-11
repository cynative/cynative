# Databricks

**Bifrost provider id:** `databricks`

## Quick start

```bash
export DATABRICKS_TOKEN=dapi...
export CYNATIVE_LLM_PROVIDER=databricks
export CYNATIVE_LLM_MODEL=databricks-claude-sonnet-4-5
export CYNATIVE_LLM_DATABRICKS_WORKSPACE_URL=https://my-workspace.cloud.databricks.com
cynative -p "..."
```

The workspace URL is mandatory. Set it as `CYNATIVE_LLM_DATABRICKS_WORKSPACE_URL`
(or `llm.databricks.workspace_url`), or as `llm.network_config.base_url`, which
Bifrost falls back to when the key config has no workspace URL. Neither set and
the first request fails with "databricks workspace url is not set". A scheme and
a trailing path are tolerated and stripped, so only the host survives; you cannot
point the provider at an arbitrary OpenAI-compatible endpoint the way vLLM and
Ollama allow.

## YAML

The flat form, a personal access token plus the workspace:

```yaml
llm:
  provider: databricks
  model: databricks-claude-sonnet-4-5
  api_key: env.DATABRICKS_TOKEN
  databricks:
    workspace_url: https://my-workspace.cloud.databricks.com
```

OAuth machine-to-machine, for a service principal instead of a token. Leave
`api_key` unset: Bifrost picks the token path whenever a key value is present,
so a stray `DATABRICKS_TOKEN` in the environment silently wins over the client
credentials below.

```yaml
llm:
  provider: databricks
  model: databricks-claude-sonnet-4-5
  databricks:
    workspace_url: https://my-workspace.cloud.databricks.com
    client_id: env.DATABRICKS_CLIENT_ID
    client_secret: env.DATABRICKS_CLIENT_SECRET
```

## Model names

The model id selects the inference surface, and a bare name is not passed
through unchanged:

- A name starting with `databricks-` (for example
  `databricks-claude-sonnet-4-5`) targets Model Serving, and is sent verbatim.
- A Unity Catalog three-part name (for example `system.ai.claude-sonnet-4-5`)
  targets the Unity AI Gateway.
- Anything else defaults to the AI Gateway and is rewritten on the wire with a
  `system.ai.` prefix. Setting `model: claude-sonnet-4-5` sends
  `system.ai.claude-sonnet-4-5`, which is a common source of surprise 404s.
- A key alias with a bare target is the exception: it goes to Model Serving and
  its target is sent unchanged, with no prefix added. An alias whose target is
  already catalog-qualified still goes to the AI Gateway.

A provisioned-throughput endpoint whose name carries no `databricks-` prefix
needs the surface pinned explicitly:

```yaml
llm:
  databricks:
    api_format: model_serving   # auto (default) | model_serving | ai_gateway
```

Only `model_serving` and `ai_gateway` pin the surface. `auto` and any
unrecognized value both fall back to the name-based rule above, so a typo is
ignored rather than rejected.

## Authentication

Two modes, chosen by whether a key value is present:

- **Personal access token.** Generate one under Settings, Developer, Access
  tokens in the workspace. Pass it as `DATABRICKS_TOKEN`, `llm.api_key`, or
  `CYNATIVE_LLM_API_KEY`.
- **OAuth M2M.** Create a service principal with an OAuth secret, then set
  `client_id` and `client_secret` under the `databricks` block and leave the key
  value empty. Bifrost mints tokens against the workspace's OIDC endpoint and
  caches them.

`DATABRICKS_TOKEN` is the canonical env var cynative reads when neither
`llm.api_key` nor `llm.keys` is set, matching the name the Databricks CLI,
Terraform provider and SDKs use. `DATABRICKS_HOST` is not read: the workspace
comes from the config fields above.

## Environment variables

- `CYNATIVE_LLM_DATABRICKS_WORKSPACE_URL`
- `CYNATIVE_LLM_DATABRICKS_API_FORMAT`
- `CYNATIVE_LLM_DATABRICKS_CLIENT_ID`, `CYNATIVE_LLM_DATABRICKS_CLIENT_SECRET`
- `CYNATIVE_LLM_DATABRICKS_FORWARD_GATEWAY_TAGS`

## Links

- Databricks Foundation Model APIs: <https://docs.databricks.com/aws/en/machine-learning/foundation-model-apis/>
- Databricks authentication env vars: <https://docs.databricks.com/aws/en/dev-tools/auth/env-vars>
- Bifrost Databricks provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/databricks>
