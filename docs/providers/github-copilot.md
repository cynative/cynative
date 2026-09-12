# GitHub Copilot

**Bifrost provider id:** `github-copilot`

> **Read this first.** On the Bifrost version cynative pins, the only auth mode
> that actually runs is a pre-minted Copilot API token, and it needs a base URL
> alongside it. The GitHub App mode described in Bifrost's own docs does not
> work here: see [GitHub App mode](#github-app-mode-does-not-work-yet) below.
> Copilot API tokens expire in about 30 minutes, so treat this provider as a
> testing path rather than something you configure once and forget.

## Quick start

```bash
export CYNATIVE_LLM_PROVIDER=github-copilot
export CYNATIVE_LLM_MODEL=gpt-5.5
export CYNATIVE_LLM_API_KEY=...                                        # a Copilot API token
export CYNATIVE_LLM_NETWORK_CONFIG_BASE_URL=https://api.business.githubcopilot.com
cynative -p "..."
```

Both settings are required. The token does not carry an inference host, so
without `base_url` the run fails at the first request. Which host is right
depends on the plan behind the token: `api.individual.githubcopilot.com`,
`api.business.githubcopilot.com` or `api.enterprise.githubcopilot.com`.

Cynative reads no provider-specific env var here, so pass the token explicitly
through `llm.api_key` or `CYNATIVE_LLM_API_KEY`. GitHub does document
`GITHUB_COPILOT_API_TOKEN` for its own SDK, but a token that lives half an hour
is not a credential worth an automatic fallback, so cynative deliberately
provides none.

## YAML

```yaml
llm:
  provider: github-copilot
  model: gpt-5.5
  api_key: env.GITHUB_COPILOT_API_TOKEN
  network_config:
    base_url: https://api.business.githubcopilot.com
```

## Model names

Plain OpenAI-style ids, passed through unchanged. Bifrost's own live suite for
this provider exercises `gpt-5.5` and `gpt-5.4-mini`. Pick a model the account
can reach over chat completions, which is the only endpoint this provider calls:
availability varies by plan tier and organization policy, so two operators with
valid credentials may see different catalogs.

## Authentication

Get a Copilot API token from whatever already mints one for your account, for
example the Copilot SDK or CLI, and pass it as `llm.api_key`. Cynative does no
minting of its own.

### GitHub App mode does not work yet

Bifrost also models a server-to-server mode where a GitHub App carrying the
Copilot Requests permission mints short-lived installation tokens, billed to the
account owning the installation. Cynative hoists that config, so this is
accepted:

```yaml
llm:
  provider: github-copilot
  model: gpt-5.5
  github_copilot:
    app_id: env.GITHUB_APP_ID
    installation_id: env.GITHUB_INSTALLATION_ID
    repository_id: env.GITHUB_REPOSITORY_ID
    private_key: env.GITHUB_APP_PRIVATE_KEY
```

It loads cleanly and then fails at the first request with "no keys found that
support model". The cause is upstream: Bifrost filters out any `github-copilot`
key whose value is empty before authentication runs, and App mode is exactly the
case with an empty value. There is no combination of cynative
settings that works around it, and setting a key value instead just selects the
token path and skips minting entirely. Use the direct-token mode above until a
later Bifrost release lifts that restriction.

Note the spelling difference: the provider id and this page keep the hyphen
(`github-copilot`), while the config block and its env vars use an underscore
(`github_copilot`), because shell assignment and `export` syntax will not accept
a hyphen in the name.

## Environment variables

- `CYNATIVE_LLM_API_KEY` (the Copilot API token) and
  `CYNATIVE_LLM_NETWORK_CONFIG_BASE_URL`, both required
- `CYNATIVE_LLM_GITHUB_COPILOT_APP_ID`,
  `CYNATIVE_LLM_GITHUB_COPILOT_INSTALLATION_ID`,
  `CYNATIVE_LLM_GITHUB_COPILOT_REPOSITORY_ID`,
  `CYNATIVE_LLM_GITHUB_COPILOT_PRIVATE_KEY`,
  `CYNATIVE_LLM_GITHUB_COPILOT_GITHUB_DOMAIN` (App mode, currently inert)

## Links

- Copilot server-to-server tokens: <https://docs.github.com/en/copilot/how-tos/copilot-sdk/auth/server-to-server-tokens>
- Copilot SDK authentication: <https://docs.github.com/en/copilot/how-tos/copilot-sdk/auth/authenticate>
- Bifrost GitHub Copilot provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/githubcopilot>
