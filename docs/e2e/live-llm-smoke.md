# Live LLM smoke test

A small, live end-to-end check that the real `cynative -p` still works against a
real LLM provider. Unlike the rest of the test suite (which is hermetic), this
one talks to a real provider over the network, so it needs real credentials and
is **not** part of `make check`. It is meant to be run by repo owners on trusted
PRs and on release-please PRs, as release confidence.

There are two complementary smokes, both driven by the same `CYNATIVE_LLM_*` env
and the same skip/require conventions:

- the **no-tool smoke** (`make llm-smoke`, below) proves a bare round-trip with
  no tools;
- the **tool-use smoke** (`make llm-tools-smoke`, [below](#tool-use-smoke-code_execution))
  proves the model can drive the tool loop through `code_execution`.

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

## Tool-use smoke (`code_execution`)

The no-tool smoke proves a bare round-trip. The **tool-use smoke**
(`test/llm-tools.smoke.test.sh`, `make llm-tools-smoke`) goes one step further and
proves a real model can drive Cynative's tool loop. It hands the model a list of
random integers and tells it to use `code_execution` to compute their exact sum,
then answer with only that integer.

Where the no-tool smoke asserts that **no** tool ran, this one asserts a tool
**did** run - specifically `code_execution` - so it catches a different class of
regression: provider/tool-schema rejection, broken tool-call parsing, a broken
approval/auto-approve path, and sandbox breakage.

### What it proves

- The provider accepts our tool-schema shape and emits a well-formed
  `code_execution` call.
- The agent parses and dispatches the call.
- The approval layer approves it (the run uses `--auto-approve`).
- The sandbox actually executes the script and returns the result.
- The model reads the result and answers with it.

### Run it locally

Same `CYNATIVE_LLM_*` env as the no-tool smoke, a different target:

```bash
export CYNATIVE_LLM_PROVIDER=bedrock
export CYNATIVE_LLM_MODEL=us.anthropic.claude-opus-4-8
export CYNATIVE_LLM_BEDROCK_REGION=us-east-1
# Bedrock uses the standard AWS credential chain (see docs/providers/bedrock.md).

make llm-tools-smoke
```

With no `CYNATIVE_LLM_PROVIDER`/`CYNATIVE_LLM_MODEL` set it prints a `skip:` line
and exits 0, so `make llm-tools-smoke` is a safe no-op. Pass a prebuilt binary
path to skip the build (then `go` is not needed):
`sh test/llm-tools.smoke.test.sh /path/to/cynative`. `python3` is required (it
parses the audit log), matching the repo's other live e2e tests.

#### Knobs

| Env | Default | Meaning |
| --- | --- | --- |
| `SMOKE_TIMEOUT` | `90` | Wall-clock seconds for the run. |
| `SMOKE_MAX_TOKENS` | `40000` | Token ceiling. A tool turn is two model calls plus the echoed script, so it needs more headroom than the no-tool smoke's `16000`; too low a value discards the answer for a budget notice. |
| `SMOKE_MAX_ITERATIONS` | `6` | Agent-loop bound. Tool use needs at least 2 (call the tool, then answer). |
| `SMOKE_REQUIRE_RUN` | unset | When `1`, a missing `CYNATIVE_LLM_PROVIDER`/`CYNATIVE_LLM_MODEL` is a hard failure instead of a skip, so a misconfigured CI job fails loudly. |

There is no `SMOKE_REQUIRE_NO_CONNECTORS` here: this smoke asserts a
`code_execution` call, not the connector set, so ambient connectors on a cloud
host are harmless.

### What it asserts

- The process exits 0.
- The exact computed sum appears in the answer on **stdout** (thousands
  separators are ignored, and the value is matched whole, not inside a longer
  number).
- The footer on **stderr** reports at least one tool call.
- The audit log holds a `code_execution` **result** record with `outcome` `ok`
  whose output contains the sum, so the sandbox executed, the approval gate
  approved it, and it actually computed the answer (rather than the model doing
  it in its head alongside an unrelated tool call). This is the load-bearing
  check: it parses the record's outer JSON fields, so it is free of TTY/render
  coupling and cannot be fooled by the model-controlled arguments.
- The `--verbose` per-tool-call notice on **stderr** names `code_execution`.

### Failure classification

| Class | Signal | Likely cause |
| --- | --- | --- |
| harness/setup | `FAIL:` before any run (build failed, tool missing, fewer than 40 integers generated) | local toolchain, not the provider |
| provider/config/access | non-zero exit with an LLM status on stderr | bad config, invalid or missing credentials, model not found, tool-schema rejected |
| timeout | exit 124 | provider slow or unreachable within `SMOKE_TIMEOUT` |
| no tool use | exit 0 but the tool-call / audit checks fail | the model answered without `code_execution`, or the call was denied or errored |

### Continuous integration

`.github/workflows/llm-smoke.yaml` runs this as a second job
(`vertex-tools-smoke`) alongside the no-tool job, against Vertex, with the same
release-please/dispatch gating, same-repo fork guard, and keyless WIF into
`cynative-cli-ci`. It runs `make llm-tools-smoke` and is not a required status
check.

## Extending to other providers

The harness is provider-agnostic. A new provider needs only its own
`CYNATIVE_LLM_*` env block; the assertions are unchanged. For example, a Bedrock
smoke sets `CYNATIVE_LLM_PROVIDER=bedrock`, a model id, and the AWS credentials
its provider needs, then runs the same `make llm-smoke` (or `make
llm-tools-smoke`).
