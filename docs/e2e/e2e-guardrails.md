# Live e2e guardrails

The live e2e suites talk to real providers and cost real credits, so they share
one bounded configuration. The goal is narrow: make it hard for a broken live
run to burn credits, hang a runner, or leave a maintainer guessing what
happened. The shared library is `test/lib/e2e-guardrails.sh`; every live suite
sources it:

- `test/llm.smoke.test.sh` - the no-tool LLM smoke (`make llm-smoke`).
- `test/llm-tools.smoke.test.sh` - the `code_execution` tool-use smoke (`make llm-tools-smoke`).
- `test/connector.gcp.e2e.test.sh` - the GCP connector e2e (`make connector-gcp-e2e`).

## What the guardrails bound

Every live run gets the same isolation and the same bounds. Isolation
(`e2e_isolate_env`) writes an empty `--config` so the caller's
`~/.cynative/config.yaml` is ignored, points the cache at a temp dir, and
silences connector-discovery env unrelated to the LLM provider
(`GH_*`/`GLAB_*`/`KUBECONFIG` and the token vars). Cloud credentials
(`AWS`/`GCP`/`Azure`) are left alone, because an LLM provider may need them (for
example Bedrock).

`e2e_apply_bounds` exports the first five bounds onto a cynative knob; the
per-run wall-clock (`E2E_RUN_TIMEOUT`) is applied by `e2e_run_bounded`, not
exported. A suite overrides a default by setting the matching `E2E_*` variable
first.

| Guardrail | Default | Applied as |
| --- | --- | --- |
| `E2E_MAX_TOKENS` | `16000` | `CYNATIVE_MAX_TOTAL_TOKENS` - per-session token ceiling |
| `E2E_MAX_ITERATIONS` | `16` | `CYNATIVE_MAX_ITERATIONS` - main-loop cap |
| `E2E_SUBAGENT_ITERATIONS` | `3` | `CYNATIVE_MAX_SUBAGENT_ITERATIONS` - `task` sub-loop cap |
| `E2E_SANDBOX_CONCURRENCY` | `4` | `CYNATIVE_SANDBOX_MAX_CONCURRENCY` - concurrent inner tool calls |
| `E2E_REQUEST_TIMEOUT` | = `E2E_RUN_TIMEOUT` | `CYNATIVE_LLM_NETWORK_CONFIG_DEFAULT_REQUEST_TIMEOUT_IN_SECONDS` - per-LLM-call timeout |

`E2E_RUN_TIMEOUT` (default `60`; the llm smoke uses `60`, the connector `120`) is
the shell `timeout` wall-clock for one run - not a cynative env var, and passed
positionally to `e2e_run_bounded`. The per-LLM-call timeout defaults to it (never
firing before the run itself would) so a slow reasoning turn is not cut off
early; cynative's own default is 300s for that reason.

The token ceiling is the real credit guard (cynative halts the turn when it is
crossed). The per-run wall-clock is the real hang guard. The iteration and
concurrency caps are secondary bounds against a pathological loop or fan-out.

## Per-suite settings

Each suite keeps its own public knob names; they resolve onto the `E2E_*`
overrides, so the documented knobs keep working.

- LLM smoke: no tools, so `E2E_MAX_ITERATIONS=1`. `SMOKE_MAX_TOKENS` (default
  `16000`) sets the token ceiling and `SMOKE_TIMEOUT` (default `60`) the per-run
  wall-clock.
- Tool-use smoke: needs at least two iterations (call the tool, then answer), so
  `SMOKE_MAX_ITERATIONS` (default `6`). `SMOKE_MAX_TOKENS` (default `40000`, a
  tool turn is two model calls plus the echoed script) sets the token ceiling and
  `SMOKE_TIMEOUT` (default `90`) the per-run wall-clock. It also passes `--verbose`
  through `e2e_run_bounded` so it can assert the per-tool-call notice.
- Connector e2e: does real tool work, so it keeps the shared iteration default
  (`16`, well under cynative's own default of `32`). `GCP_E2E_MAX_TOKENS`
  (default `32000`) sets the token ceiling and `GCP_E2E_TIMEOUT` (default `120`)
  the per-run wall-clock.

## Suite-level timeout

There is no separate whole-script watchdog. The effective wall-clock ceiling is
the per-run `timeout` times the capped attempts and phases, and a budget hit is
fatal (never retried). The derived worst case:

- LLM smoke: `SMOKE_TIMEOUT` x 1 run = 60s by default.
- Tool-use smoke: `SMOKE_TIMEOUT` x 1 run = 90s by default.
- Connector e2e: `GCP_E2E_TIMEOUT` x `GCP_E2E_ATTEMPTS` x 2 phases (read +
  canary) = 120 x 2 x 2 = 480s by default.

## Clear failure output

`e2e_run_bounded` runs one bounded `cynative -p`, and `e2e_classify_run` turns
the outcome into a distinct, actionable failure:

| Outcome | Signal | Reported as |
| --- | --- | --- |
| timeout | exit 124 | `FAIL: timed out after <N>s` |
| token budget hit | `Budget reached` on stdout (the run still exits 0) | `FAIL: token budget reached - raise the token limit ...` |
| provider/config/access | any other non-zero exit | `FAIL: provider/config/access (exit <rc>)` + stderr tail |
| ok | exit 0, no budget notice | the suite runs its own assertions |

The budget case matters most: on a budget hit cynative writes
`⚠️  Budget reached — ...` to **stdout** and exits 0, so the answer never lands.
Without a dedicated check that would surface as a confusing "answer missing"
(for the LLM smoke, "nonce not found"). Classifying it directly points the
maintainer at the token ceiling. A budget hit is treated as fatal and is not
retried, so a too-low ceiling fails fast instead of re-burning credits.

## Tests

The library's pure logic (the bound exports, the isolation, the bounded-run
exit-code propagation, and the classifier) is covered by
`test/e2e-guardrails.unit.test.sh`, which runs hermetically under `make sh-test`.
The connector script's audit parser has its own offline check:
`sh test/connector.gcp.e2e.test.sh --selftest`.
