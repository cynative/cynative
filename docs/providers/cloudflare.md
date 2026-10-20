# Cloudflare Workers AI

**Bifrost provider id:** `cloudflare`

## Quick start

```bash
export CLOUDFLARE_API_TOKEN=...
export CYNATIVE_LLM_CLOUDFLARE_ACCOUNT_ID=<32-hex account id>
export CYNATIVE_LLM_PROVIDER=cloudflare
export CYNATIVE_LLM_MODEL=@cf/meta/llama-4-scout-17b-16e-instruct
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: cloudflare
  model: "@cf/meta/llama-4-scout-17b-16e-instruct"
  api_key: env.CLOUDFLARE_API_TOKEN   # optional; falls back to CLOUDFLARE_API_TOKEN
  cloudflare:
    account_id: env.CLOUDFLARE_ACCOUNT_ID
```

Quote the model in YAML: an unquoted `@` cannot start a plain scalar.

Workers AI serves its OpenAI-compatible API per account, at
`https://api.cloudflare.com/client/v4/accounts/<account_id>/ai/v1/chat/completions`.
The account ID is required. Without it Bifrost skips the key, logs
`cloudflare_key_config is required, skipping key` to stderr, and the run fails
with `no keys found that support model`. `network_config.base_url` replaces only the
`https://api.cloudflare.com/client/v4` part; the account path is always appended.

Model names are Workers AI's full IDs, such as `@cf/meta/...` or `@cf/openai/...`.
Pick one that supports function calling, since cynative drives the model through
tool calls.

## Authentication

In the Cloudflare dashboard, open **Workers AI**, select **Use REST API**, and
use **Create a Workers AI API Token**. A token you build by hand needs both
`Workers AI - Read` and `Workers AI - Edit`. The same page shows the account ID
under **Get Account ID**.

`CLOUDFLARE_API_TOKEN` is the name Wrangler and Cloudflare's Terraform provider
read. Cloudflare's OpenAI-compatibility examples call it `CLOUDFLARE_API_KEY`;
cynative does not read that name, so set `api_key: env.CLOUDFLARE_API_KEY` if
that is what your shell exports.

## Links

- Workers AI OpenAI-compatible endpoints: <https://developers.cloudflare.com/workers-ai/configuration/open-ai-compatibility/>
- Workers AI models: <https://developers.cloudflare.com/workers-ai/models/>
- Bifrost Cloudflare provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/cloudflare>
