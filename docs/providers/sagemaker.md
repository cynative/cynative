# Amazon SageMaker

**Bifrost provider id:** `sagemaker`

Calls the OpenAI-compatible route (`/openai/v1/chat/completions`) of a
SageMaker real-time endpoint, so the container behind it has to serve that
route (for example vLLM, SGLang or LMI).

## Quick start

```bash
export AWS_PROFILE=my-profile          # or AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY
export CYNATIVE_LLM_PROVIDER=sagemaker
export CYNATIVE_LLM_MODEL=my-endpoint
export CYNATIVE_LLM_SAGEMAKER_REGION=us-east-1
cynative -p "..."
```

No YAML file and no `api_key` are required: Bifrost mints a SageMaker bearer
token from the standard AWS credential chain.

## YAML

```yaml
llm:
  provider: sagemaker
  model: my-endpoint
  sagemaker:
    region: us-east-1
    # role_arn: arn:aws:iam::123456789012:role/sagemaker-invoke   # optional AssumeRole
    # endpoints:
    #   runtime: vpce-....runtime.sagemaker.us-east-1.vpce.amazonaws.com
```

## Model names

The model is the endpoint name, in the form
`[region/]endpoint-name[/inference-component-name]`. A region prefix overrides
`sagemaker.region` for that request. With neither set, the request fails with
`sagemaker_key_config.region is required`.

## Authentication

Bifrost resolves AWS credentials from the standard chain (`AWS_PROFILE`,
`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, IAM role, instance metadata), or
from `sagemaker.access_key`, `secret_key` and `session_token`, optionally
assuming `sagemaker.role_arn`. A pre-minted bearer token in `llm.api_key` is
used as is instead.

## Environment variables

- `CYNATIVE_LLM_SAGEMAKER_REGION`, `CYNATIVE_LLM_SAGEMAKER_ROLE_ARN`,
  `CYNATIVE_LLM_SAGEMAKER_ENDPOINTS_RUNTIME`

## Links

- SageMaker real-time inference: <https://docs.aws.amazon.com/sagemaker/latest/dg/realtime-endpoints.html>
- Bifrost SageMaker provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/sagemaker>
