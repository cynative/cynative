# Amazon Bedrock Mantle

**Bifrost provider id:** `bedrock_mantle`

Bedrock Mantle is the API surface served on `bedrock-mantle.<region>.api.aws`:
Claude models via the native Anthropic Messages API, and OpenAI-family
(`gpt-*`) and Gemma models via the OpenAI-compatible API. Bifrost picks the
path from the model id; the model id is sent verbatim, save for an optional
leading `region/` addressing prefix.

## Quick start

```bash
export AWS_PROFILE=my-profile          # or AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY
export CYNATIVE_LLM_PROVIDER=bedrock_mantle
export CYNATIVE_LLM_MODEL=anthropic.claude-opus-4-8
export CYNATIVE_LLM_BEDROCK_MANTLE_REGION=us-east-1
cynative -p "..."
```

No YAML file is required. With no `api_key`, requests are SigV4-signed with
credentials from the standard AWS chain.

## YAML

The flat form (env-only equivalent):

```yaml
llm:
  provider: bedrock_mantle
  model: anthropic.claude-opus-4-8
  bedrock_mantle:
    region: us-east-1
```

The full `keys[]` form (e.g. for explicit static credentials or a role ARN):

```yaml
llm:
  provider: bedrock_mantle
  model: anthropic.claude-opus-4-8
  keys:
    - value: ""                      # empty → SigV4 via AWS credentials
      models: ["*"]
      weight: 1.0
      bedrock_mantle_key_config:
        region: us-east-1
```

## Authentication

Two options:

- **AWS credentials (SigV4).** Leave `api_key` unset; Bifrost signs each
  request for the `bedrock-mantle` service using the standard chain
  (`AWS_PROFILE`, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, IAM role,
  instance metadata) or the explicit `bedrock_mantle` key config
  (access/secret key, role ARN).
- **Bedrock Mantle API key.** Set `api_key` to the key; it is sent as
  `Authorization: Bearer` and SigV4 signing is skipped.

The region comes from a `region/` model prefix, the `bedrock_mantle.region`
config, or falls back to `us-east-1`.

## Links

- Amazon Bedrock docs: <https://docs.aws.amazon.com/bedrock/>
- Bifrost Bedrock Mantle provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/bedrockmantle>
