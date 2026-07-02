# Google Vertex AI

**Bifrost provider id:** `vertex`

## Quick start

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
export CYNATIVE_LLM_PROVIDER=vertex
export CYNATIVE_LLM_MODEL=gemini-2.5-pro
export CYNATIVE_LLM_VERTEX_PROJECT_ID=my-gcp-project
export CYNATIVE_LLM_VERTEX_REGION=us-central1
cynative -p "..."
```

No YAML file is required, but Vertex needs structured config: `project_id` and
`region` (above). cynative does not treat `GOOGLE_APPLICATION_CREDENTIALS` as an
API-key fallback — it is read by the Google SDK (ADC) at request time. A bare
`api_key` or env var alone is not sufficient and fails at load with a clear
error.

## YAML

The flat form (env-only equivalent):

```yaml
llm:
  provider: vertex
  model: gemini-2.5-pro
  vertex:
    project_id: my-gcp-project
    region: us-central1
```

The full `keys[]` form (e.g. for IAM-role auth, set `auth_credentials` to ""):

```yaml
llm:
  provider: vertex
  model: gemini-2.5-pro
  keys:
    - value: ""
      models: ["*"]
      weight: 1.0
      vertex_key_config:
        project_id: my-gcp-project
        region: us-central1
        auth_credentials: ""
```

## Authentication

Vertex authenticates via the `vertex` block, not via a key value. `project_id`
and `region` are required. For credentials, either set `auth_credentials` to the
service-account JSON **content** (not a file path), or leave it empty for
Application Default Credentials (ADC) — the Google SDK then finds the
credentials itself, e.g. from the `GOOGLE_APPLICATION_CREDENTIALS` file path
shown in the quick-start. cynative has no single-env key fallback for Vertex.

## Links

- Vertex AI docs: <https://cloud.google.com/vertex-ai/docs>
- Bifrost Vertex provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/vertex>
