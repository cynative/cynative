# GitHub Copilot

**Bifrost provider id:** `github-copilot`

## Quick start

```bash
export CYNATIVE_LLM_PROVIDER=github-copilot
export CYNATIVE_LLM_MODEL=gpt-5.5
export CYNATIVE_LLM_API_KEY=github_pat_...    # a fine-grained personal access token
cynative -p "..."
```

Cynative reads no provider-specific env var here, so pass the token through
`llm.api_key` or `CYNATIVE_LLM_API_KEY`.

## YAML

```yaml
llm:
  provider: github-copilot
  model: gpt-5.5
  api_key: env.GITHUB_COPILOT_TOKEN
```

## Model names

Plain OpenAI-style ids, passed through unchanged. Bifrost's own live suite for
this provider exercises `gpt-5.5` and `gpt-5.4-mini`. Pick a model the account
can reach over chat completions, which is the only endpoint this provider calls:
availability varies by plan tier and organization policy, so two operators with
valid credentials may see different catalogs.

## Authentication

Bifrost reads the kind of token from its prefix:

- **Fine-grained personal access token (`github_pat_`).** Sent to Copilot as
  is. Bifrost looks up the account's plan host on `api.github.com` before the
  first request, unless `network_config.base_url` is set.
- **GitHub OAuth token (`ghu_` or `gho_`).** Exchanged on `api.github.com` for
  a Copilot API token, which Bifrost refreshes before it expires.
- **Anything else** is treated as a pre-minted Copilot API token and used
  verbatim. Such a token does not carry its host, so `network_config.base_url`
  is required with it: `https://api.individual.githubcopilot.com`,
  `https://api.business.githubcopilot.com` or
  `https://api.enterprise.githubcopilot.com`, depending on the plan. These
  tokens expire in about 30 minutes.

Classic personal access tokens (`ghp_`) and GitHub App installation tokens
(`ghs_`) are refused: Copilot does not accept them. The GitHub App
(server-to-server) mode earlier Bifrost releases offered is gone, and so is the
`github_copilot:` config block that fed it.

## Environment variables

- `CYNATIVE_LLM_API_KEY` (the token)
- `CYNATIVE_LLM_NETWORK_CONFIG_BASE_URL` (required with a Copilot API token,
  optional otherwise)

## Links

- Copilot SDK authentication: <https://docs.github.com/en/copilot/how-tos/copilot-sdk/auth/authenticate>
- Bifrost GitHub Copilot provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/githubcopilot>
