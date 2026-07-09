# Live GCP connector e2e

A live end-to-end check that the real `cynative` reads a known GCP resource
through the `gcp` connector and stays read-only. Unlike the hermetic test suite,
it talks to a real GCP project, so it needs real credentials and is **not** part
of `make check`. It is meant for repo owners on trusted PRs and release-please
PRs, as release confidence.

## What it proves

Two bounded agent runs against the fixture project (`cynative-cli-ci`):

- Read: the CLI starts, a real model drives the loop, the `gcp` connector
  registers under the default `roles/viewer`, and the model reads the project's
  own Cloud Resource Manager metadata, surfacing the stable project number.
- Canary: a deliberate write (setting a label) is denied client-side, before any
  request leaves the machine, proving the read-only boundary holds.

The read-only guarantee rests on the enforced `roles/viewer` role plus cynative's
client-side action gate; the canary is the positive proof.

## Run it locally

```bash
export CYNATIVE_LLM_PROVIDER=vertex
export CYNATIVE_LLM_MODEL=gemini-3.5-flash
export CYNATIVE_LLM_VERTEX_PROJECT_ID=cynative-cli-ci
export CYNATIVE_LLM_VERTEX_REGION=global   # gemini-3.5-flash is a global-endpoint model
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/adc.json   # lights the gcp connector
export GCP_E2E_PROJECT=cynative-cli-ci
export GCP_E2E_EXPECT=<the project's numeric projectNumber>

make connector-gcp-e2e
```

The model must be capable enough to drive a multi-step tool flow (register the
connector, read the project, attempt the write). `gemini-3.5-flash` is reliable;
`gemini-2.5-flash` is not (it stalls on the iteration limit) and is not
recommended here.

With `GCP_E2E_PROJECT` (or the LLM provider) unset, `make connector-gcp-e2e`
prints a `skip:` line and exits 0, so it is a safe no-op.

The script builds the current checkout; pass a prebuilt binary path as the first
argument to skip the build. Run `sh test/connector.gcp.e2e.test.sh --selftest`
to verify the audit parser offline, with no credentials.

### Knobs

| Env | Default | Meaning |
| --- | --- | --- |
| `GCP_E2E_TIMEOUT` | `120` | Wall-clock seconds per run (a tool-using run is slower than a no-tool turn). |
| `GCP_E2E_MAX_TOKENS` | `32000` | Token backstop, not a tight budget. |
| `GCP_E2E_CANARY` | `1` | `0` runs only the read phase, skipping the write-deny canary. |
| `GCP_E2E_ATTEMPTS` | `2` | Attempts per phase before failing. Model runs are non-deterministic, so one retry absorbs a rare miss; a real failure fails every attempt. |
| `GCP_E2E_REQUIRE_RUN` | unset | `1` hard-fails instead of skipping when required env is unset (CI sets this). |

## What it asserts

Read phase: exit 0; stdout contains `GCP_E2E_EXPECT` (the project number, fed out
of band so only a real read produces it); the startup inventory shows `gcp`
available under `role=roles/viewer` and not skipped; the footer reports at least
one tool call; the audit log holds a successful gcp `GET` to
`cloudresourcemanager` for the project.

Canary phase: the audit log shows the labelled write (`cynative-e2e` marker) was
attempted and denied client-side (result contains `gcp_hardening`), and no marked
write succeeded. A write that succeeded, or that failed only with a server 4xx
(meaning it left the machine), fails the test.

## Failure classification

| Class | Signal | Likely cause |
| --- | --- | --- |
| harness/setup | `FAIL:` before any run | local toolchain (go/timeout/python3), not the connector |
| provider/config/access | read run non-zero exit | bad project/region, invalid credentials, model not found |
| timeout | exit 124 | provider or GCP slow within `GCP_E2E_TIMEOUT` |
| connector-not-registered | inventory shows `gcp` skipped | ADC missing or unresolved project |
| unexpected read | exit 0 but number missing | model did not echo, or budget too low |
| read-only boundary | a marked write succeeded / left the machine | the read-only gate did not hold |

## Continuous integration

`.github/workflows/connector-gcp-e2e.yaml` runs `make connector-gcp-e2e` against
`cynative-cli-ci` on release-please PRs and manual dispatch (the `detect` job gates
it; it never runs on ordinary PRs and is not a required status check).

Credentials use keyless **Workload Identity Federation**, so no long-lived key is
stored. The credential step is gated to same-repo events, so a fork PR never
reaches it. Unlike the LLM smoke, `GOOGLE_APPLICATION_CREDENTIALS` **is** exported
so the `gcp` connector registers. Because the auth action's `external_account`
file carries no `quota_project_id`, the workflow injects the fixture project into
that file, so cynative resolves a project for its permission catalog.

Non-secret configuration lives in repo Actions variables: `GCP_E2E_PROJECT`,
`GCP_E2E_EXPECT`, and the existing `CYNATIVE_CLI_CI_*` set.
