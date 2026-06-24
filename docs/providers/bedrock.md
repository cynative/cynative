# Amazon Bedrock

**Bifrost provider id:** `bedrock`
**Cynative chat-loop support:** ✅ supported

## Quick start

```bash
export AWS_PROFILE=my-profile          # or AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY
export CYNATIVE_LLM_PROVIDER=bedrock
export CYNATIVE_LLM_MODEL=anthropic.claude-opus-4-v1:0
export CYNATIVE_LLM_BEDROCK_REGION=us-east-1
cynative -p "..."
```

No YAML file and no `api_key` are required — Bedrock uses the standard AWS
credential chain.

## YAML

The flat form (env-only equivalent):

```yaml
llm:
  provider: bedrock
  model: anthropic.claude-opus-4-v1:0
  bedrock:
    region: us-east-1
```

The full `keys[]` form (e.g. for explicit static credentials or a role ARN):

```yaml
llm:
  provider: bedrock
  model: anthropic.claude-opus-4-v1:0
  keys:
    - value: ""                      # Bedrock uses AWS credentials, not a key
      models: ["*"]
      weight: 1.0
      bedrock_key_config:
        region: us-east-1
```

## Authentication

Bifrost picks up AWS credentials from the standard chain
(`AWS_PROFILE`, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, IAM role,
instance metadata). No API key is involved.

## Links

- Amazon Bedrock docs: <https://docs.aws.amazon.com/bedrock/>
- Bifrost Bedrock provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/bedrock>
