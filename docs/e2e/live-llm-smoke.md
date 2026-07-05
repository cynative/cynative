# Live LLM smoke test

A small, live end-to-end check that the real `cynative -p` still works against a
real LLM provider. Unlike the rest of the test suite (which is hermetic), this
one talks to a real provider over the network, so it needs real credentials and
is **not** part of `make check`. It is meant to be run by repo owners on trusted
PRs and on release-please PRs, as release confidence.

## What it proves

One bounded, no-tool round-trip: the CLI starts, config loads, the Bifrost
provider is wired correctly, a real model answers, and the response is handled
and rendered. It is deliberately narrow so a failure points at exactly one of:
provider config, credentials, model access, or response handling.

The harness is provider-agnostic: everything is driven by `CYNATIVE_LLM_*` env,
so the same script covers any provider. Vertex/Gemini is the first caller
documented here.

## Run it locally

```bash
export CYNATIVE_LLM_PROVIDER=vertex
export CYNATIVE_LLM_MODEL=gemini-2.5-flash
export CYNATIVE_LLM_VERTEX_PROJECT_ID=my-gcp-project
export CYNATIVE_LLM_VERTEX_REGION=us-central1
# Credentials: either inline the service-account JSON content, or rely on ADC
# (see docs/providers/vertex.md). Inline keeps the gcp connector dark:
export CYNATIVE_LLM_VERTEX_AUTH_CREDENTIALS="$(cat /path/to/service-account.json)"

make llm-smoke
```

With no `CYNATIVE_LLM_PROVIDER`/`CYNATIVE_LLM_MODEL` set, `make llm-smoke` prints
a `skip:` line and exits 0, so it is a safe no-op.

The script builds the current checkout (`go build ./cmd/cynative`), so it
exercises your code, not a released binary. Pass a prebuilt binary path as the
first argument to skip the build:

```bash
sh test/llm.smoke.test.sh /path/to/cynative
```

### Knobs

| Env | Default | Meaning |
| --- | --- | --- |
| `SMOKE_TIMEOUT` | `60` | Wall-clock seconds for the run. |
| `SMOKE_MAX_TOKENS` | `16000` | Token ceiling (a safety backstop, not a tight budget). One turn of a thinking model like `gemini-2.5-flash` spends a few thousand tokens, and the budget is checked after the response, so too low a value discards the answer for a budget notice. |
| `SMOKE_REQUIRE_NO_CONNECTORS` | unset | When `1`, hard-fail unless no connector registers. CI sets this on its clean runner; leave it unset on a cloud host (see the caveat below). |
| `SMOKE_REQUIRE_RUN` | unset | When `1`, a missing `CYNATIVE_LLM_PROVIDER`/`CYNATIVE_LLM_MODEL` is a hard failure instead of a skip. CI sets this so a misconfigured job (for example a renamed model variable) fails loudly rather than passing green without exercising the model. |

## What it asserts

- The process exits 0.
- The model echoes a unique nonce on **stdout** (`grep -F`), so it survives
  markdown reflow and only the answer text is matched.
- The footer on **stderr** reports `0 tool calls`, proving the run used no tools
  (the CLI still registers the tools; the assertion is that none were called).
- Connectors: soft by default. If the startup inventory does not report
  `(no connectors detected)`, the script prints a `warn:` line and continues.
  With `SMOKE_REQUIRE_NO_CONNECTORS=1` this becomes a hard failure instead.

## Failure classification

The script separates stdout from stderr and reports a distinct reason per class:

| Class | Signal | Likely cause |
| --- | --- | --- |
| harness/setup | `FAIL:` before any run (build failed, tool missing) | local toolchain, not the provider |
| provider/config/access | non-zero exit with an LLM status on stderr | bad project/region, invalid or missing credentials, model not found, auth failure |
| timeout | exit 124 | provider slow or unreachable within `SMOKE_TIMEOUT` |
| unexpected response | exit 0 but nonce missing | the model did not echo, or the budget was too low and a notice replaced the answer |

## Continuous integration

`.github/workflows/llm-smoke.yaml` runs the same `make llm-smoke` against Vertex
on release-please PRs and manual dispatch (the `detect` job gates it; it never
runs on ordinary PRs and is not a required status check).

Credentials use keyless **Workload Identity Federation** into the dedicated GCP
project `cynative-cli-ci`, so no long-lived key is stored. The credential step
is gated to same-repo events, so a fork PR never reaches it. The auth step runs
with `export_environment_variables: false` and the minted credentials JSON is
fed to cynative inline via `CYNATIVE_LLM_VERTEX_AUTH_CREDENTIALS`, deliberately
**not** `GOOGLE_APPLICATION_CREDENTIALS`. That keeps the `gcp` connector from
auto-registering, so `(no connectors detected)` holds and CI can set
`SMOKE_REQUIRE_NO_CONNECTORS=1`.

Non-secret configuration lives in repo Actions variables:
`CYNATIVE_CLI_CI_PROJECT`, `CYNATIVE_CLI_CI_SA`, `CYNATIVE_CLI_CI_WIF_PROVIDER`,
`CYNATIVE_CLI_CI_VERTEX_MODEL`, `CYNATIVE_CLI_CI_VERTEX_REGION`.

## No-connectors caveat on cloud hosts

Connectors auto-discover ambient credentials. On a GCP host (for example a GCE
instance), the metadata server provides Application Default Credentials, so the
`gcp` connector can register even when no connector is configured and even with
inline Vertex credentials. That is why the local default is a soft warning: the
real safety property is `0 tool calls` (no connector was actually exercised),
which always holds. On the clean CI runner there is no metadata server and creds
are inline, so the connector set is dark and the hard check is used.

## Extending to other providers

The harness is provider-agnostic. A new provider needs only its own
`CYNATIVE_LLM_*` env block; the assertions are unchanged. For example, a Bedrock
smoke sets `CYNATIVE_LLM_PROVIDER=bedrock`, a model id, and the AWS credentials
its provider needs, then runs the same `make llm-smoke`.
