# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) and other coding agents when working
with code in this repository. `CLAUDE.md` is a symlink to this file.

## Commands

All targets are wired through `make`. Lint and test rely on `go tool golangci-lint` (pinned via
`go.mod`), so no separate install is needed. `moq` is pinned the same way and `make generate`
writes the gitignored `*_mock_test.go` mocks. **Run `make generate` before
`go test ./internal/<pkg>` on a fresh checkout**, or the tests won't compile.

- `make check`: the full gate CI runs, `check-go` + `check-scripts`.
- `make check-go`: generate + lint + shell-complexity + format-diff + test + `windows-build`
  (GOOS=windows amd64/arm64 cross-compile). 100% `go.mod`-pinned and hermetic; **the pre-commit
  hook runs this**.
- `make check-scripts`: `shellcheck` (all tracked `*.sh`) + PSScriptAnalyzer on `install.ps1`,
  `test/install-script.smoke.test.ps1`, `test/scoop.smoke.test.ps1`, and
  `test/archive.smoke.test.ps1` + Pester unit tests +
  `sh-test` (the POSIX `install.sh` unit tests, a `python3`-backed loopback smoke
  test of the `CYNATIVE_BASE_URL` download-base seam and its non-loopback-HTTP reject, the
  live-e2e guardrails unit tests, the connector-e2e orchestration unit tests, the shared
  release-gate invocation-contract and gate-assert unit tests, the llm-smoke workflow golden,
  the gate trusted-caller pin check, the release publish-gate pin check, the shared
  audit-parser python syntax gate, all three connector suites' offline audit-parser
  selftests, and the shared-machinery selftest).
  Install-free: asserts each pinned tool or module is present and fails with an install hint
  otherwise (needs `shellcheck`, PowerShell 7, `python3`). The pinned
  shellcheck/Pester/PSScriptAnalyzer versions live in the `Makefile` and are bumped by hand;
  Dependabot has no PowerShell Gallery or raw-binary ecosystem.
- `make generate`: `go generate ./...` (regenerates the `moq` mocks).
- `make lint`: `go tool golangci-lint run`.
- `make format`: `go tool golangci-lint fmt --diff` (prints diffs; does not write).
- `make test`: runs `CGO_ENABLED=1 go test -race -shuffle=on ./...` with atomic coverage, then
  **fails unless every statement outside the imperative shell (`*_shell.go`) and the
  test-support package `internal/auth/authtest` is covered**, printing each uncovered
  `file:line`. Add tests alongside new code or the gate fails. The authtest exemption carries a
  companion import guard, run once per goreleaser-shipped platform (linux/windows/darwin x
  amd64/arm64 at `CGO_ENABLED=0`, since a build-tagged importer is invisible to other build
  contexts): `go list` must show no non-test importer of `internal/auth/authtest`, so
  coverage-exempt code can mechanically never reach a shipped binary. The fakes themselves are
  load-bearing in six consumer test suites, which is what pins their behavior.
- `make shell-complexity`: `go tool gocyclo`/`gocognit` over every `*_shell.go` file; **fails if
  any function exceeds cyclomatic or cognitive complexity 6**. Shell files are coverage-exempt,
  so this keeps them thin: a violation means *extract the logic into gated (covered) core*,
  never raise the budget. No per-function escape hatch by design: the standalone tools ignore
  golangci `//nolint`, and the gate also rejects their native `//gocyclo:ignore` and
  `//gocognit:ignore` directives in shell files. AST-only (no `make generate` needed); fails
  closed on any non-zero exit. Core (non-shell) files stay under `.golangci.yaml` (`cyclop` 30,
  `gocognit` 20).
- Run a single test: `go test ./internal/agent -run TestName` (add `-v` for output, `-count=1`
  to skip cache).
- Build the binary: `go build ./cmd/cynative` (or `go run ./cmd/cynative -p "..."`).
- `make snapshot`: builds the release archives via a goreleaser snapshot (no publish;
  `--skip=before` keeps it hermetic/offline). `make install-e2e`: standalone release-confidence
  check, not part of `make check`; builds the snapshot, then runs the real `install.sh` against
  a loopback fixture server (`test/install.e2e.test.sh`, needs `python3`), verifying install,
  `--version`, uninstall, and the fail-closed checksum-mismatch path. `make llm-smoke`:
  standalone live LLM smoke (not part of `make check`); runs the real `cynative -p` against a
  real provider chosen via `CYNATIVE_LLM_*` env (nonce echo, no tools; `test/llm.smoke.test.sh`),
  asserting the nonce on stdout and `0 tool calls` in the footer, and skips cleanly when no
  provider is set. `make connector-gcp-e2e`: standalone
  live GCP connector e2e (not part of `make check`); runs the real `cynative -p` against a real
  GCP fixture project through the `gcp` connector (`test/connector.gcp.e2e.test.sh`, needs
  `python3`), asserting a read of the project's own Cloud Resource Manager metadata and a
  client-side-denied write canary, and skipping cleanly when `GCP_E2E_*`/creds are unset (the
  script header documents its env and knobs). `make connector-aws-e2e`: standalone live AWS
  connector e2e (not part of `make check`); runs the real `cynative -p` against a real AWS fixture
  account through the `aws` connector (`test/connector.aws.e2e.test.sh`, needs `python3`),
  asserting a read of an inert fixture IAM role's tag (the value arrives out of band and never
  appears in the prompt, and the audit parser binds it to the bytes AWS returned) plus a
  `TagRole` write canary denied before the request leaves the machine, and skipping cleanly when
  `AWS_E2E_*`/creds are unset (the script header documents its env and knobs). `make
  connector-github-e2e`: standalone live GitHub connector e2e (not part of `make check`); runs the
  real `cynative -p` against a private fixture repo through the `github` connector
  (`test/connector.github.e2e.test.sh`, needs `python3`), asserting a read of the fixture repo's
  description (the marker arrives out of band and never appears in the prompt, and the audit parser
  binds it to the bytes GitHub returned, requiring a private 200 so the read also proves credential
  injection) plus a `PATCH` write canary and a secret-scanning-read canary, each denied before the
  request leaves the machine, and skipping cleanly when `GH_E2E_*`/creds are unset (the script
  header documents its env and knobs). The three suites share one audit parser, the importable
  Python package `test/lib/connector_audit/` (engine plus a per-provider spec in
  `connector_audit/specs/<provider>.py` and a runnable `connector-audit-parser.py` entrypoint), and
  one shell orchestration library `test/lib/connector-e2e.sh` (sourcing the generic
  `e2e-guardrails.sh`); each suite is a thin delta of knobs, fixtures, prompts, and posture asserts.
  The parser is what stops a suite going green while the read-only boundary is broken: its exit code
  is the phase status (1 = retryable miss, 4 = boundary failure, never retried, since the per-attempt
  audit truncation would erase the evidence), and a first-line credential prepass fails closed (4) if
  credential material was logged. `make sh-test` gates the parser: each suite's offline `--selftest`
  drives it and pins the suite's frozen case-name/code set
  (`connector_audit/testdata/<provider>.names.txt`), plus a shared-machinery `--selftest` that
  exercises the engine's own fail-closed and prepass cases. `make homebrew-smoke`: standalone post-release
  Homebrew install smoke (not part of `make check`); installs cynative from the public tap via the
  documented `brew install cynative/tap/cynative`, asserts `cynative --version` reports the expected
  release (`SMOKE_VERSION`, default: latest published), uninstalls, and asserts it is gone
  (`test/homebrew.smoke.test.sh`, needs brew; no skip path; the script header documents its env and
  knobs). `make install-script-smoke`: standalone post-release public install-script smoke (not part
  of `make check`); runs the documented `curl .../install.sh | sh` path against the public release
  assets - install, exact `cynative --version` assert (`SMOKE_VERSION`, default: latest published),
  documented uninstall, gone-assert (`test/install-script.smoke.test.sh`, needs curl and network; no
  skip path). The Windows sibling (`test/install-script.smoke.test.ps1`, Windows PowerShell 5.1)
  runs in CI via `.github/workflows/install-script-smoke.yaml`. The Scoop channel smoke is
  Windows-only and has no make target: `test/scoop.smoke.test.ps1` (Windows PowerShell 5.1)
  adds the public bucket, runs the documented `scoop install cynative`, asserts exact
  `--version` and cynative-bucket provenance, uninstalls, and asserts it is gone; it runs in CI
  via `.github/workflows/scoop-smoke.yaml` (Release Pipeline call + maintainer dispatch;
  `SMOKE_VERSION` pins the expected release; no skip path; the script header documents its env
  and knobs).

Two linters shape every new test: `paralleltest` requires each test and subtest to call
`t.Parallel()`, and `forbidigo` bans `os.Getenv`/`LookupEnv`/`Environ` and `t.Setenv` outside
the composition root and config shell, so code and tests resolve env through an injected seam,
never the process environment.

## Architecture

`cynative` is a single Go binary that drives an LLM-based "research" loop over the user's
cloud/source environments. The agent's primary tool is `code_execution`: the model writes
JavaScript that runs in an embedded sandbox and calls the host tools (currently `http_request`)
programmatically, looping, filtering, and chaining calls without a round-trip per call. The loop
is an in-house, hand-rolled DeepAgents-style agent (`internal/agent`): call the model, dispatch
every tool call it returns, append the results, repeat until the assistant answers with no tool
calls. Two host orchestration tools augment it, `write_todos` (planning) and `task` (a
context-quarantined sub-agent that re-enters the same loop), plus the always-on `verify_findings`
adversarial verifier. The provider-agnostic message/tool currency is `internal/schema` (this
repo's own types, not a framework's); the LLM backend is an embedded Bifrost SDK wrapped as a
single custom `schema.ChatModel`, so any of Bifrost's ~23 Chat Completions providers can be
selected from config without code changes. Cynative configures exactly one provider per run.

The spine is cmd → cli → agent → tools → transport → auth: `code_execution` drives the
`internal/sandbox` runtime, `http_request` drives `internal/transport`, `internal/schema`
supplies the shared message/tool types, and `internal/llm` supplies the Bifrost-backed
`schema.ChatModel` the loop drives.

- **`cmd/cynative`**: a thin `main` that calls `cli.Execute()`.

- **`internal/cli`**: cobra commands and the **composition root**. `wire_shell.go`'s `newDeps`
  is the one place that reads the real environment (`os.LookupEnv` into `config.NewLoader`,
  `auth.GetProviders`, `ui.New`, stdio, and the `llm`/`tools`/`agent` constructors); every
  collaborator is a field on the `deps` struct (no package globals), the orchestration core is
  tested with fakes, and `wire_shell.go` is the excluded shell. The root command replaces the
  old `research` subcommand: `-p`/`--print` (or any piped/non-TTY invocation) runs the task
  once; a TTY without `-p` enters an interactive follow-up loop (optionally seeded by a
  positional arg) that survives transient turn errors; `exit`/`quit`/EOF ends it, and it
  aborts only on context cancellation, a fail-closed audit-write failure, or an LLM generation
  failure before the first successful turn. Piped stdin (1 MiB-capped, UTF-8-repaired)
  combined with a positional task is folded in as untrusted `<piped_input>` context
  (`agent.WrapPipedInput`).
  Invariants:
  - Every I/O tool is **approval-wrapped unconditionally** (`tools.NewApprovalTool`);
    `--auto-approve` swaps the prompter for `ui.AutoApproveToolCall` (prints and approves), it
    never skips the wrapper. The orchestration tools (`write_todos`/`task`) are registered
    unwrapped: surfaced, not gated.
  - Approval prompts use the controlling terminal (`/dev/tty` via the build-tagged
    `resolveInteraction`) when stdin is piped, so a piped one-shot can still prompt; a run with
    no usable terminal and no `--auto-approve` fails closed with `ErrNoApprovalTerminal` (empty
    non-interactive input fails with `ErrNoTask`).
  - `auth.GetProviders` receives a single `auth.HardeningConfig` bundling one config per
    connector, built from `cfg.Connectors.*` (permission maps, policy/role names,
    ClusterRoles); the cached connectors (github/gitlab/aws/gcp/azure) additionally embed a
    `cache.Config` namespaced per provider via `filepath.Join(cfg.Cache.Dir, "<provider>")`,
    while the four K8s connector configs carry only a ClusterRole.
  - Operational footers render on **stderr** (`ui.RenderFooter`): a `turn` footer per
    interactive turn plus one cumulative `session` footer at session end (`-p` prints only the
    `session` footer), so redirecting stdout keeps the answer clean. One `metrics.Accumulator`
    (with `metrics.WithBudget(cfg.MaxTotalTokens)`) spans the session and is threaded to both
    the chat model (`llm.WithUsageRecorder`) and the agent. `--verbose`/`-v` routes per-tool-call
    output to stderr.
  - SIGINT/SIGTERM: a two-stage handler shares a leaf-package `interrupt.State` with the
    optional ui `TerminalController`. SIGTERM always restores the terminal and exits 143; a
    first in-turn SIGINT is graceful (the agent loop handles it), a second in-turn press or any
    idle press restores and exits 130. On an editor TTY the `TerminalController` is the
    `deps.interrupter`; otherwise the shared `*interrupt.State` itself is. There is no no-op
    interrupter type; an inert one is a zero `*interrupt.State`.

- **`internal/schema`**: the provider-agnostic message/tool currency shared by `llm`, `agent`,
  `tools`, and `ui`. A pure leaf: it imports only the standard library and
  `github.com/invopop/jsonschema`, and **no internal import may ever be added** (nothing it
  depends on can create a cycle). `Message{Role, Content []Block}` with three sealed block
  variants: `TextBlock`, `ToolCallBlock` (the raw JSON arguments as the model produced them),
  `ToolResultBlock`. `ChatModel{Generate}` takes the offered tools as a direct
  `tools []*ToolInfo` argument (tool-less calls pass nil; there is no per-call options
  machinery). `InvokableTool{Info, Run}` plus the optional `StructuredRunner`; `Usage` is the
  per-call token accounting. `ReflectParams[T]()` generates a tool's JSON Schema from a Go
  struct via invopop/jsonschema, configured with inlined definitions and
  `additionalProperties:false` so strict-mode providers accept it.

- **`internal/llm`**: owns the embedded Bifrost SDK and adapts it to `internal/schema`.
  `BifrostChatModel` implements `schema.ChatModel` (plus `Shutdown`) over a `BifrostBackend`
  port (moq'd in tests; the real client is built in `bifrost_shell.go` and injected as a
  defaulted factory field). The Anthropic rolling cache-breakpoint marking is applied per
  request. `ProviderEntry` embeds Bifrost's `schemas.ProviderConfig` via `json:",squash"` so
  every Bifrost field (including `network_config` for proxy/timeout/retries/headers) is exposed
  without per-field translation, plus the cynative selectors (`provider`, `model`), the
  `api_key` top-level alias, and hoisted per-provider key-config aliases
  (`azure`/`vertex`/`bedrock`/`bedrock_mantle`/`vllm`/`ollama`/`sgl`/`replicate`). Invariants:
  - The provider catalog is **derived**: `ChatProviders()` is Bifrost's `StandardProviders`
    minus the hand-triaged `nonChatProviders` exclusions (providers whose Bifrost impl cannot
    chat, rejected by `config.ValidateLLM`). `CanonicalEnvKeyLookup` backs the single-env-var
    fallback.
  - Env references resolve through the injected `LookupEnv`, never the process environment:
    `ResolveEnvVar` turns `env.X` strings into Bifrost `SecretVar`s, `ProviderEnvKeys` enumerates
    the dotted key paths that `CYNATIVE_LLM_*` vars map onto, and `ValidateEnvVars` verifies
    referenced vars are set.
  - `ValidateKeyConfigs` guards the providers whose Bifrost impl dereferences a per-key config
    without a nil check (azure, vertex), with direct field checks so an upstream rename fails at
    compile time. `ValidateReasoning` validates `llm.reasoning_effort` (none through high) and
    `llm.reasoning_max_tokens`, and rejects effort "none" combined with a budget, which
    Bifrost's Anthropic-style converters would otherwise let silently re-enable thinking.
  - `WithUsageRecorder` is the one production `ChatModelOption`: a sink invoked with the
    `schema.Usage` of every successful `Generate` (the cli wires it to the metrics accumulator).

- **`internal/agent`**: the in-house DeepAgents-style research loop, pure Go, tested directly
  against a fake `schema.ChatModel` (no framework runner, no checkpoint store, no
  interrupt/resume). `Agent.run` (`loop.go`) calls `model.Generate`, renders the assistant turn,
  and returns its text when there are no tool calls; otherwise it dispatches each tool call,
  appends a `ToolMessage` per result, and loops (terminating after `maxIter` iterations with an
  empty answer). Tool failures and unknown-tool names come back as tool-result content, never a
  Go error, so the model can self-correct. `Run` seeds the working transcript from the agent's
  clean Q&A history (prior questions and final answers only; intermediate plans/steps/tool
  output render live but are not replayed) plus the system message and the new question, then
  records the exchange. `Config.MaxIterations` bounds the main loop,
  `Config.MaxSubagentIterations` the `task` sub-loop. Key invariants:
  - **Untrusted fencing**: every plain-`Run` (I/O) tool result is fenced via `wrapUntrusted`
    (`framing.go`: `<tool_output tool="...">` with `</tool_output>` escaping) before it
    re-enters the transcript, and `task` self-frames its summary; the orchestration acks (todo
    checklist, verification panel) stay unframed as trusted host rendering with echoed finding
    fields escaped. `prompt.go` carries the matching untrusted-data clause and `verify.go`
    shares the same `escapeFence` helper.
  - **Halt conditions.** Budget: when a token budget is configured (`metrics.WithBudget`) the
    loop checks `BudgetExceeded()` at the top of every iteration, after each model response,
    and after each tool dispatch; on exceed it returns the `errBudgetExceeded` sentinel and
    `Run` renders a
    one-line notice and stops the turn with no partial answer recorded. The bound is cumulative
    across the main loop, `task` sub-runs, and the verifier, and is per-session (it survives
    `StartTurn`). Interrupt: Esc or a first Ctrl-C (via the host `Interrupter`, checked at the
    top of each iteration, after `Generate`, and before every I/O dispatch) surfaces as
    `ErrInterrupted`, non-fatal in an interactive session, exit 130 in one-shot. Failures:
    `max_consecutive_failures` consecutive no-progress tool calls (a tool error, a denial, or an
    `http_request` response >= 400) trigger `failureSummary`: one tool-less `Generate` asking
    the model to name the wall and the required input, returned and recorded as the turn's
    answer (a blank or errored summary falls back to a deterministic notice). The
    `haltAndAskClause` in the system prompt steers the model to stop and ask the operator for a
    missing identifier rather than guess or probe candidates.
  - **Orchestration tools live in this package** (not `internal/tools`, avoiding a
    `tools`→`agent` import cycle) and are registered unwrapped since they perform no credentialed
    I/O. `write_todos` records and renders the todo checklist (tolerating a double-encoded
    payload, normalizing unknown statuses to `pending`); `task` re-enters the same `run` loop
    with a fresh transcript seeded only with the system prompt + task description (context
    quarantine, depth+1, fresh `runState`) while **reusing the parent's approval-wrapped I/O
    tools**, so approval and auth still propagate; that invariant is pinned by
    `TestIntegration_SubagentIOStaysGated`. Per-run mutable state lives in `runState`, never on
    `*Agent`, so concurrent sub-runs are race-free (pinned by
    `TestRun_ConcurrentRunsShareNoMutableState`).
  - **`verify_findings`** (`verify.go`) is always on, with no config knob: exactly two batched
    tool-less `Generate` passes (a benign-explanation lens, then an evidence-sufficiency lens),
    each sending all findings in one prompt and requiring strict JSON keyed by host-assigned
    finding ID. Refuted in either pass → REFUTED; confirmed in both → VERIFIED; else UNVERIFIED.
    Depth-0 only, max 16 findings per call, 16 KiB evidence clamp with `</evidence>` escaping,
    and **strict fail-closed parsing**: a missing, unknown, malformed, refused, truncated,
    timed-out, or budget-skipped verdict degrades to insufficient_evidence, so no parse problem
    can mint VERIFIED. Each pass has a coarse budget backstop (`BudgetExceeded()` checked before
    the pass).
  - `prompt.go` teaches the workflow (plan with `write_todos`, script with `code_execution` over
    `http_request`, delegate with `task`, stop and answer when done), carries a
    positively-framed `SCOPE:` clause near the top (right after the identity preamble and
    optional About block) anchoring the agent to the question's subject (narrowest
    enumeration; imperatives rather than prohibitions, so the guidance travels to small/local
    models too), and lists the available auth providers so the model knows the valid
    `auth_provider` values.

- **`internal/tools`**: the I/O `schema.InvokableTool`s. `http_request` builds its JSON Schema
  from `transport.RequestArgs` via `schema.ReflectParams` and forwards the model's raw JSON
  arguments straight to `transport.Client.Execute` (preserving auth's raw-bytes contract); it
  also implements `StructuredRunner`, so sandbox scripts receive a parsed object.
  `code_execution` wraps the other tools as async JS functions inside an `internal/sandbox`
  runtime, capped at `cfg.SandboxMaxConcurrency` concurrent inner calls; a tool's
  `StructuredRun` is preferred and `Run` is the fallback. `approval.go` is a **synchronous,
  blocking** decorator: each `Run` first calls the host `Prompter`
  (`func(name, arguments, style string, alreadyGranted bool) Decision`; `Decision` is `Deny`,
  the zero value, so an undecided prompt fails closed, `ApproveOnce`, or `ApproveSession`,
  which latches a per-tool session grant so later calls to that tool are displayed and
  auto-approved without pausing; every decision is recorded to the audit log) and either runs
  the inner tool or returns `DeniedMessage` as a result string (not a Go error), so the loop
  continues and the model can adapt. New I/O tools are added here; every tool handed to
  `code_execution` is exposed to scripts automatically, and implementing
  `schema.StructuredRunner` makes scripts receive a parsed object instead of a string.

- **`internal/sandbox`**: runs untrusted, model-authored JavaScript in an embedded Grafana
  **sobek** runtime, exposing host capabilities only through explicitly registered `ToolFunc`s;
  there is no `fetch`, `require`, filesystem, network, timers, or Node/browser API. One
  persistent, mutex-serialized runtime per session; each `Run` is wrapped in an async IIFE so
  top-level `await` works and top-level declarations are call-scoped (state survives across
  `Run`s only via `globalThis`). Each `Run` has a timeout context with a watchdog that calls
  `vm.Interrupt`; output is captured from `console.log/error`, truncated to `maxOutput`, and
  UTF-8-repaired; script errors and timeouts are included in the result string AND signaled
  with the `ErrScript` sentinel (nil error only on success), so callers can record the failure
  without parsing text; the `code_execution` tool converts `ErrScript` back into a plain
  result string so the model can self-correct.
  Tool calls are async: each returns a JS Promise backed by a worker goroutine bounded by a
  `maxConcurrency` semaphore (a non-positive value clamps to `DefaultMaxConcurrency` = 16), a
  single loop goroutine drains worker postbacks, and `Run` waits for all workers. The
  `redact func(string) string` passed to `New` is a required security boundary: a nil redactor
  panics on first use rather than silently leaking unredacted content. `mapConcurrent(items,
  fn, limit)` (a pure-JS prelude installed non-writable on `globalThis`) gives bounded,
  order-preserving fan-out that stops launching after the first failure; `xml.parse` and
  `jmespath.search` are synchronous natives. `sandbox_shell.go` builds the runtime; the package
  has no `agent`/`tools`/Bifrost dependency (`tools.codeexec` adapts it via the `codeRunner`
  port, defaulting to a 32 KiB output cap and `redact.New().RedactPreservingLocation`).

- **`internal/transport`**: executes `http_request` calls. The gauntlet, in order: parse args
  (the model must name an `auth_provider`, one of `github`/`gitlab`/`aws`/`eks`/`gcp`/`gke`/
  `azure`/`aks`/`kubernetes`), clamp timeout and body limits, **reject any non-`https` URL**
  (credentials never traverse plaintext), never follow redirects (`CheckRedirect` returns
  `http.ErrUseLastResponse`, so a 3xx is surfaced to the model and any follow-up hop is a
  fresh, fully-gated request), authorize a model-supplied `Host` header override through
  `auth.AuthorizeHost` like the URL host (the wire authority cannot slip host pinning), then run
  the three auth gates: `auth.AuthorizeHost`, `auth.AuthorizeAction`, `auth.Inject`.
  `configureTransport` installs a fresh per-request `*http.Transport` built from scratch, never
  the shared default (Proxy intentionally nil, no inherited DialTLS, so an embedding process
  that customized the global transport cannot bypass the guard), TLS-aware when the provider
  supplies a CA cert or client cert (mTLS), and **always** wired with `dialGuard`: a
  `net.Dialer.ControlContext` hook that authorizes the DNS-resolved IP via `auth.AuthorizeAddr`
  before the connection is established, the dial-time chokepoint against DNS-rebinding/TOCTOU
  SSRF (Go fires Control on every dial, including IP literals). Responses are redacted at the
  source via `internal/redact` on **both** exits, `FormatResponse` (the direct `Execute` path)
  and `ExecuteStructured` (the sandbox path), before dumping and truncation. `Execute` returns
  the HTTP status code (0 on a transport-level error); `http_request`'s `Run` marks a transport
  error or a >= 400 response as a no-progress outcome for the agent's consecutive-failure
  counter.

- **`internal/auth`**: the extensible provider registry. `GetProviders` takes a single
  `auth.HardeningConfig` (bundling one config per connector: github, gitlab, aws, eks, gcp,
  gke, azure, aks, kubernetes) plus an `onStatus` callback that receives a `ConnectorStatus`
  per connector for the startup inventory, probes the environment, and returns whatever
  registers. Registration is eager where it matters:
  - github validates its token live with a hardened `GET /user` probe over `githubDialAllowed`,
    a public-internet dial guard that denies all internal and special-use ranges (CGNAT,
    benchmarking, documentation, 0.0.0.0/8, 240.0.0.0/4, non-global-unicast) plus
    IPv4-embedding IPv6 (NAT64, 6to4) whose embedded IPv4 is internal, while a NAT64-wrapped
    public GitHub IPv4 stays allowed so IPv6-only/DNS64 hosts work.
  - gitlab discovers its token (`GITLAB_TOKEN`/`GITLAB_ACCESS_TOKEN`/`OAUTH_TOKEN`, else the
    pinned `glab auth credential-helper`) and validates it with a dial-guarded
    `GET /api/v4/user` through the provider's own host-pinned/CA path.
  - AWS+EKS register via default AWS config, GCP+GKE via ADC, Azure+AKS via a credential chain
    with managed identity demoted to last and made non-fatal (so the IMDS probe cannot abort the
    chain on a non-Azure host whose metadata server shares 169.254.169.254), and a self-managed
    `kubernetes` provider via the local kubeconfig using kubectl's own discovery
    (`KUBECONFIG`, then `~/.kube/config`, current-context, no Cynative-level override); it
    eagerly validates the cluster by fetching the configured ClusterRole over the same
    dial-guarded path used at request time. The managed K8s connectors do not probe the API at
    registration.
  - "Available" means validated-live this startup: an invalid/expired/unreachable credential
    shows unavailable with a reason, a genuinely absent ambient credential is a silent skip, and
    an unbuildable hardened provider is a logged skip.

  Core contracts:
  - Every provider implements `Name`/`Description`/`InjectAuth` **and `AuthorizesHost`** (host
    pinning is a baseline control, not optional). Optional interfaces: `CACertProvider`,
    `ClientCertProvider` (how the K8s providers supply per-cluster CA bundles and client
    certs), `ActionAuthorizer` (per-request action authorization, implemented by every provider
    today), and `AddrAuthorizer` (dial-time authorization of the resolved IP; the four K8s
    providers pin the dial to the cluster endpoint's exact resolved IPs, and providers that
    don't implement it inherit the fail-safe default: deny internal ranges, loopback,
    link-local including cloud metadata, RFC1918, ULA, IPv4-mapped forms, plus the exact Azure
    WireServer and Alibaba metadata addresses; allow everything else).
  - `auth.Inject`, the dispatcher every credentialed request flows through, rejects
    model-supplied credentials before dispatching (`ErrModelSuppliedCredential`):
    `Authorization`/`Proxy-Authorization`/`X-Ms-Authorization-Auxiliary` header values and URL
    userinfo (which Go's client would otherwise turn into `Authorization: Basic ...` exactly
    when an mTLS provider sets no header). The header match scans the raw header map keys
    case-insensitively with `_` normalized to `-`, not via `Header.Values`, which would miss a
    non-canonical key set by direct map assignment; presence is what matters, so duplicate or
    empty values still count. Provider `InjectAuth` implementations are the sole setters of
    credential material;
    the Azure SAS `sig=` query check lives with the Azure provider.
  - The GitHub provider gates each request against a configurable exposure ceiling
    (`internal/auth/github`): classify the request to its category/subcategory and required
    access level over a distilled OpenAPI category table (fetched anonymously by the shared
    dial-guarded github/gitlab bootstrap fetcher in `bootstrap_fetch.go`, TTL-cached via
    `internal/cache`), then allow it only when the operator's `Exposure`
    (`category[/subcategory]` → read|write|none, secure baseline read-all-except
    `secret-scanning`, resolved most-specific-first) permits that level. An unclassifiable
    request, a missing table, an over-ceiling request, or a configured key naming no real
    category each **fail closed**. `AdmitTable` rejects a fetched or cached table that remaps a
    secret-scanning template (cache-poison defense); no request-time segment override is used,
    to avoid false-positive denials from user-controlled path segments. `InjectAuth` strips any
    model-supplied `X-GitHub-Api-Version` header so the model cannot select an API surface the
    table did not model. GitHub-owned download hosts (`codeload.github.com`, release/objects
    `githubusercontent.com`) are authorized GET/HEAD-only regardless of the ceiling; every
    allow-listed host must be GitHub-operated because `InjectAuth` attaches the token
    unconditionally. A best-effort post-response audit (`auth.ResponseAuditor`) compares
    GitHub's `X-Accepted-GitHub-Permissions` header against the classification and logs drift,
    advisory only. The github posture is computed at registration and surfaced in the startup
    connector inventory (`ConnectorStatus.Posture`, warn-flagged by `PostureLoud` when the
    default is write, `secret-scanning` is opened, or any category is widened); nothing is
    emitted at request time.
  - `k8sGate[A]` is the shared K8s authorization path all four K8s providers compose: it owns
    the identical validate → resolve-view → classify → authorize sequence and the per-cluster
    ClusterRole-policy cache, while credential and cluster-fact mechanics stay per-provider.
    `syncCache[T]` coalesces concurrent CA/cert lookups via singleflight and caches successes,
    not errors.

- **`internal/auth/aws`**: AWS request hardening (pure core + `*_shell.go` fetchers), three
  layers. (1) **Credential scoping**: `ScopedProvider` re-vends the base credentials via STS
  `AssumeRole` scoped to the configured read-only managed policy (default `SecurityAudit`) via
  `PolicyArns`, **only for assumed-role identities** (self-chain), degrading to disabled on a
  definitive `AccessDenied` (e.g. an SSO trust policy forbidding self-assumption) and
  propagating transient errors. IAM-user and root identities run unscoped, gated by the other
  two layers alone; cynative no longer mints `GetFederationToken` sessions, which cannot call
  IAM and so defeated IAM auditing. (2) **Host pinning**: `ParseHost` maps the request host to
  a `(service, region)` and verifies it against the model's `aws_auth` claim, rejecting IP
  literals, localhost, and VPC endpoints. It also recognizes account-scoped S3 Control hosts
  and account-prefixed S3 access-point hosts (which resolve to the plain `s3` path: their
  virtual-hosted requests are classified by prepending the host-implied bucket to the path);
  `Verify` compares the service claim case- and hyphen-insensitively so endpoint-prefix and
  SDK-id spellings reconcile, while signing uses the host-resolved canonical signing name.
  (3) **Action authorization**: resolve the request to a service model via the cached
  `ModelArchive`, classify the operation, resolve its required IAM action(s) through a
  three-tier chain (Service Reference API → iam-dataset → `namespace:op` derivation), and
  require the configured policy to allow every action via `iam:SimulateCustomPolicy`, failing
  closed on any unresolved action. Namespace-shadowed services (e.g. S3 Control living under
  the `s3` IAM namespace) are resolved only by their own identity, excluding the foreign
  namespace key and the derivation tier, and fail closed on a miss, so account-level S3 Control
  operations authorize against their own actions. All AWS I/O is lazy (first use) and cached
  under `<cache>/aws`; a definitive scoping degrade emits a one-line `aws_hardening: degraded`
  notice to stderr.

- **`internal/auth/gcp`**: pure GCP request hardening composed via `AuthorizeAction`. Resolves
  the request host to a Google API service through a live API Discovery-directory catalog
  (TTL-cached via `internal/cache`; a transient partial fetch is cached fail-closed, denying
  dropped services until the next refresh), classifies the operation, resolves its required
  IAM permissions (pinned overrides first, then derive-and-validate against the live
  testable-permissions catalog, with the cached iam-dataset as a read-fallback and write-union
  tier), and authorizes every permission against the single configured role (default
  `roles/viewer`; predefined or custom), failing closed on anything unresolved. I/O is lazy
  and cached under `<cache>/gcp`; the role definition is fetched live per run (no role cache);
  the `role=<configured role>` posture surfaces in the startup connector inventory.

- **`internal/auth/azure`**: pure Azure request hardening composed via `AuthorizeAction`. Azure
  has no credential-downscoping primitive, so this in-process action gate is the sole
  client-side control: resolve the service via a cached catalog, classify the operation, and
  authorize it against the single configured RBAC role definition (default `Reader`).
  Data-plane operations (Key Vault secrets, Blob/Queue/Table data, SQL/Cosmos data) are out of
  scope: Cynative is control-plane only and denies data-plane hosts at the network layer. I/O
  is lazy and cached under `<cache>/azure`; the role definition is fetched live per run; the
  `role definition=<name> (<guid>)` posture surfaces in the startup connector inventory.

- **`internal/auth/k8s`**: the shared Kubernetes authorization core (pure, no network) used by
  the `eks`/`gke`/`aks`/`kubernetes` providers through `k8sGate`: a faithful kube-apiserver
  `RequestInfo` classifier, an allow-only RBAC matcher built from the cluster's live
  **configured** ClusterRole (default `view`, set via `connectors.<connector>.cluster_role`,
  path-escaped into the fetch path), a fail-closed ClusterRole-JSON parser, and an `Authorize`
  combiner with a safe non-resource GET allow-set. The providers fetch and cache each cluster's
  ClusterRole (the HTTPS fetch lives in the excluded shells) and **fail closed** when it cannot
  be resolved; the `cluster role=<name>` posture surfaces in the startup connector inventory.
  Kubernetes decouples authn from authz, so there is no credential downscoping; the in-process
  gate is the sole client-side control. The ClusterRole fetch is an internal bootstrap call
  that bypasses `AuthorizeAction` to avoid circularity.

- **`internal/auth/gitlab`** (the exposure-classifier subpackage) plus the parent-package
  `gitlabProvider` implement the GitLab connector (gitlab.com and self-managed). The provider
  injects `Authorization: Bearer`, which authenticates PAT, project/group, **and** OAuth tokens
  (`glab auth login` defaults to an OAuth token that `PRIVATE-TOKEN` would 401). Token
  discovery: the env vars above, else delegation to the pinned `glab auth credential-helper`
  binary; cynative sets `GITLAB_HOST` to the login host (the explicit `host`, or the `api_host`
  when only that is configured, never the un-configured `gitlab.com` default) and
  `GITLAB_API_HOST` to the served API authority including any `:port`, then validates the
  returned `instance_url` against the login or api host. glab owns the token lifecycle,
  config.yml, and refresh (cynative reads and writes neither; glab needs **v1.85.2+** for the
  neutral-cwd host fallback). The exec is hardened: one absolute path (no shell), an
  allowlisted child env with cynative's secrets dropped, a neutral cwd, timeout + `WaitDelay`,
  `/dev/null` stdin, size-capped drain-to-EOF output that never echoes the token, and a parser
  that trusts the JSON `type` field rather than the exit code (glab exits 0 on error),
  accepting only `oauth2`-with-expiry and `pat` token types. Behind the `tokenSource` seam sit
  a static source for env/PAT tokens and a caching `glabHelperSource` (60s skew, failure
  cooldown, adopt-on-failure). Startup classification (`decideGlab`) uses a config-presence
  signal: keyring tokens work, and a config.yml with a missing or too-old glab is a loud skip
  steering to `GITLAB_TOKEN`. Authorization mirrors github: a per-category exposure ceiling
  (`connectors.gitlab.permissions`, secure baseline `{default: read, ci-variables: none}`)
  classified over GitLab's distilled first-party OpenAPI v3 spec (anonymous, dial-guarded,
  size-capped fetch; TTL-cached; `Lookup` anchors at the root, requiring the path's first two
  decoded segments to be exactly `api`/`v4`, so a subpath-mounted install is denied rather
  than classified; subpath installs cannot register anyway since the eager `/api/v4/user`
  probe runs at the host root). `GET`/`HEAD`/`OPTIONS` plus `POST /api/v4/markdown`
  are reads; the GraphQL API is denied entirely; unclassifiable routes, a missing table,
  over-ceiling requests, and unknown configured keys fail closed. `ci-variables` is the
  secret-leak-on-read category: the mapping happens at distill time on the trusted spec
  templates (so a `variables` path-parameter value cannot inherit an opened ceiling) and
  `AdmitTable` rejects a table that downgrades a `variables` template (cache-poison defense).
  `AuthorizeAction` also pins the request/Host-override port to the configured port and
  rejects sudo impersonation and smuggled credential params (`token`/`private_token`/
  `access_token`/`job_token` in query and urlencoded/multipart/JSON bodies, matched on the base
  name so Rack `[...]` and `_`/`-` folding can't evade it). `AuthorizesAddr` denies internal
  IPs (RFC1918 allowed only behind `connectors.gitlab.allow_private_network`; the
  loopback/link-local/metadata/ULA floor always stays), then fresh-resolves and exact-IP-pins
  the served host; `CACertProvider` supplies a configured `ca_cert` (which governs cynative's
  request path, not glab's own refresh handshake). The GitLab credential headers
  (`Private-Token`/`Job-Token`/`Deploy-Token`/`X-Gitlab-Static-Object-Token`/`Cookie`) and the
  `feed_token`/`rss_token` query params are folded into the central credential denylist and
  the redactor. The exposure ceiling renders in the startup connector-inventory line (built at
  registration via `gitlabPosture`, warn-flagged by `PostureLoud` when the default is write,
  `ci-variables` is opened, or any category is widened); the compact
  `CYNATIVE_CONNECTORS_GITLAB_PERMISSIONS` env scalar replaces the file map wholesale.

- **`internal/cache`**: stdlib-only leaf holding the one on-disk cache primitive,
  `TTLCache[T]` (in-memory → on-disk per TTL → fetch, with stale-on-error fallback), plus
  `Config{Dir, TTL, Clock}`, which every connector cache embeds. It imports nothing from
  `internal/auth`, so all auth subpackages depend on it without a cycle.

- **`internal/interrupt`**: stdlib-only leaf providing the mutex-guarded two-stage interrupt
  `State` shared by the cli signal handler and the ui `TerminalController`; a separate package
  purely to prevent a cli↔ui import cycle. `BeginTurn`/`EndTurn` arm and disarm (clearing any
  stale trip); `Trip()` classifies a press: idle or second in-turn press means kill, first
  in-turn press means graceful (sets `Interrupted`).

- **`internal/redact`**: stdlib-only leaf holding the response redactor. `Redact` replaces
  secret-shaped content (PEM private keys, JWTs, GitHub/GitLab/Slack/Google tokens, AWS
  access-key IDs, credential-named field values, signed-URL signatures) with type-labeled
  `[REDACTED:<type>]` placeholders via high-precision keyword-pre-gated RE2 rules (no entropy
  heuristics; patterns sourced from the gitleaks default ruleset). `RedactHeader` blanks
  denylisted credential headers wholesale while exempting `Location` (redirect-following needs
  the signed URL) and content-redacting other header values. `transport.Client` injects it via
  a small local interface and applies it at both response exits, so credential material is
  scrubbed at the source before reaching the model or the sandbox.

- **`internal/config`**: a `Loader` (`config.NewLoader(env llm.LookupEnv, ...)`, with an
  injected `homeDir` for `~` expansion) that loads `~/.cynative/config.yaml` (overridable via
  `--config`) and `CYNATIVE_*` env vars. It uses a fresh `viper.New()` per load and no
  `AutomaticEnv`: `applyEnv` walks a generated key list (`llm.ProviderEnvKeys()`, every field
  of each non-llm nested struct, every top-level scalar) and `v.Set`s any that are present
  (whitespace-only counts as unset, so a blank env var never silently wipes a file map). The
  active provider is a single flat `llm:` block unmarshaled into `llm.ProviderEntry`;
  `detectAliasConflicts` rejects setting both an alias and its nested form, alias folding
  (`materializeLLM`) then folds the aliases into the squashed Bifrost fields, and the
  `api_key` `env.X` form and canonical-env fallback both resolve through the injected env.
  Unmarshal runs mapstructure with `TagName:"json"` and the `llm` decode-hook chain; `Load`
  then runs the connector validators and `go-playground/validator` over the top-level fields.
  The LLM-block checks (`llm.provider`/`llm.model` presence plus the `llm`
  provider/key/env/reasoning validators) live in `config.ValidateLLM`, which `Load` does not
  call: the CLI invokes it and renders a missing or invalid `llm:` block as an LLM
  startup-status block instead of failing config loading. Nested connector defaults are registered
  recursively (durations stored as their `.String()` form for the strict duration hook). The
  permission maps (`connectors.{github,gitlab}.permissions`) also accept a compact
  `key=value,...` env scalar that replaces the file map wholesale (duplicate keys rejected).
  Knobs and defaults: `render_style` `adaptive`; `max_iterations` 32;
  `max_subagent_iterations` 10; `sandbox_max_concurrency` 16 (min 1, max 64);
  `max_total_tokens` 0 = unbounded; `max_consecutive_failures` 5 (0 disables); `cache.dir`
  `~/.cynative/cache`; `cache.ttl` 24h (min 1m); `connectors.aws.policy` an IAM policy ARN
  (default `SecurityAudit`); `connectors.gcp.role` `roles/viewer` (accepts predefined or
  custom project/org roles); `connectors.azure.role_definition` `Reader` (required);
  `connectors.{eks,gke,aks,kubernetes}.cluster_role` `view` (validated as a safe URL path
  segment, fail-closed on empty); `llm.network_config.max_retries` 3 (the one llm-block
  default, registered by hand since ProviderEntry embeds Bifrost's untaggable struct;
  Bifrost retries 429/500/502/503/504, recognized rate-limit errors, and transport errors
  with backoff; an explicit file/env value including 0 wins, and a negative value is
  rejected by `llm.ValidateNetworkConfig`). Each knob has a matching `CYNATIVE_*` env var.
  `verify_findings` has no knob; it always runs.

- **`internal/metrics`**: session-cumulative operational telemetry (token usage, model
  round-trips, tool calls, sub-agent spawns, verifiers, active compute time) for the stderr
  footer; a pure leaf over `internal/schema`. Counters and usage **never reset**: a session is
  one continuous tally, which keeps the per-turn footer from being misread as a session total.
  `StartTurn`/`EndTurn` bracket each turn's active-compute window (both called by `Agent.Run`,
  `EndTurn` via defer), and `Snapshot().Elapsed` excludes idle time between interactive
  follow-ups. Every method is nil-receiver-safe (an `Agent` built without an accumulator is a
  no-op); the clock is injected. It also carries the optional per-session token ceiling
  (`WithBudget`): the basis is the per-call sum of usage tokens (`TotalTokens`, falling back to
  prompt+completion), kept as a per-call sum rather than derived from the summed usage, which
  would diverge under inconsistent provider `total_tokens` reporting; `BudgetExceeded()`/
  `BudgetReason()`/`HasBudget()` answer the threshold query the loop and verifier enforce.

- **`internal/ui`**: wraps `charm.land/glamour/v2` for markdown rendering and provides the
  approval prompter, `PromptUserInput`, and `PrintToolCall`. `formatToolCall` detects a
  `code_execution`-style payload (non-empty `code` field) and renders it as a reviewable
  fenced-javascript block so the host can inspect sandboxed code before approving; other
  payloads pretty-print as JSON. Markdown renders with the default `adaptive` style: body text
  inherits the terminal foreground, and the accent palette comes from a one-time, cached
  dark-background probe: editor-TTY (controller) runs prime it up front via `PrimeBackground`
  before the keystroke watcher starts, so the OSC 11/DA1 probe reply cannot be stolen by a
  concurrent reader and misread as Esc, while non-controller runs detect lazily on the first
  `adaptive` render (non-TTY/`NO_COLOR` runs are forced to `notty` and never query the
  terminal). `RenderFooter` writes single-scope
  footers (`turn`/`session`) to stderr at the terminal-default foreground; displayed input is
  split fresh vs `cached` (cached always shown, including `0 cached`), with cache-write as a
  parenthetical subset omitted when zero; the token line is omitted when no usage was
  reported, and the sub-agent/verifier chrome segments are omitted when zero. The interactive
  `>` prompt is a raw-mode line editor (`golang.org/x/term`; a fresh
  `term.Terminal` per read, shared bounded history of 100) behind the `lineReader` seam, with a
  cooked scanner fallback for non-editor input. On a unix editor TTY the `TerminalController`
  (shell) owns the interaction fd: `BeginTurn` arms the interrupt state and enters cbreak,
  starting a single keystroke-watcher goroutine; if cbreak entry fails the turn degrades (no
  watcher, fd stays canonical, SIGINT still works via the signal handler). `EndTurn` joins the
  watcher and restores the tty; signal and panic paths also restore. The watcher feeds
  `keyDecoder`, a pure state machine that disambiguates a lone Esc (interrupt) from CSI/SS3
  sequences via a timeout tick, recognizes Ctrl-C, and during an approval window maps `y`/`a`
  to approve-once/approve-session and **fails closed** (any other printable key denies,
  matching the cooked parser). Interrupt dominates approval: a pre-read interrupt check plus a
  post-decision re-check means a stop that raced in with the keystroke still denies; on a
  degraded turn `BeginApproval` returns a pre-closed channel so the approval denies at once.

- **`internal/audit`**: records every tool call to a fail-closed JSONL audit log
  (`~/.cynative/audit.log`). The gated core's `Logger.Log` stamps `Time`/`Seq`/`Actor`,
  **always** redacts the `Result`, and writes the call arguments verbatim unless `RedactArgs`
  is set (inner `code_execution`, ungated-orchestration, and unknown-tool records set it).
  Age-based rotation lives in core over an injected writer and clock (fail-closed on a
  triggered rotate error); the shell (`Open`) seeds the oldest-record time from the existing
  file's first line, adds size rotation via lumberjack, and forces mode 0600. Mapped from
  `config.AuditConfig` (`enabled`/`path`/`max_size_mb`/`retention_days`/`compress`).

### Conventions

- **Ports & adapters with constructor injection.** The lint config bans `init()` and mutable
  globals (`gochecknoglobals`, `gochecknoinits`); the old injectable-global-swapper pattern is
  gone, do not reintroduce it. Each package splits into a pure **core** (100% coverage-gated,
  every test parallel under `-race`) and a thin imperative **shell** (`*_shell.go`,
  coverage-exempt, integration-tested, complexity-capped at 6; keep shells to untestable glue
  and push branchy logic into gated core). Anything that touches the outside world (cloud SDKs,
  `os`/env, filesystem, network `Do`, stdio, `term`, `json.Marshal`, the Bifrost client, the
  sobek runtime) is injected, never reached for directly:
  - Required deps become small consumer-owned interfaces or func fields defaulted to the real
    impl in the constructor; tests inject fakes via `With*` functional options exposed in
    `export_test.go`.
  - Multi-method ports get `moq` mocks
    (`//go:generate go tool moq -out <pkg>_mock_test.go . <Iface>`; output gitignored,
    regenerated by `make generate`). A thin one-call seam stays a func field. Where an external
    interface can't be moq'd directly (it pulls internal symbols), mirror it with a
    drift-pinned local interface (see `internal/auth`, `internal/auth/aws`).
  - A default factory whose real impl has an unreachable error path is a factory field
    defaulted **branch-free** to a shell function, so core stays 100% with no injectable global
    (see `bifrost_shell.go`, `sandbox_shell.go`).
  - Env resolves once at the edge: `wire_shell.go` passes `os.LookupEnv` to `config.NewLoader`,
    and everything downstream takes an injected `llm.LookupEnv`. No test uses `t.Setenv`.
- **Test package layout.** `foo_test.go` (external `package foo_test`, exercises the public
  API); `foo_internal_test.go` (internal package, for tests needing unexported access);
  `export_test.go` (internal; exposes `With*` options and small test constructors, never
  global-swappers); `*_mock_test.go` (moq-generated, gitignored; run `make generate` first).
  `internal/auth/authtest` is a sibling package of reusable fake `Provider` implementations:
  test support imported only from `_test.go` files, coverage-exempt, and guarded by the
  `make test` import check.
- **Lint config is strict** (`.golangci.yaml`, based on the maratori golden config):
  `modernize`, `mnd`, `funlen`, `cyclop`, `godot`, `gochecknoglobals`, `gochecknoinits`,
  `paralleltest`, `forbidigo`, and many more are on (`exhaustruct` is configured but commented
  out, so its `//nolint:exhaustruct` markers are inert). Line length is **120** (golines);
  the local goimports prefix is `github.com/cynative/cynative`. `*_shell.go` and
  `internal/cli/{root,wire_shell}.go` are exempt from `forbidigo` (legitimate edge env reads);
  `*_shell_test.go` from `paralleltest`. Most violations are intentional in this code; if you
  must suppress, mirror the existing `//nolint:rule // reason` comments, always with the
  reason. Comments end in a period (`godot`). Errors wrap with `%w`; sentinels are named
  `ErrX`, error types `XError`. The only permitted `//nolint:gochecknoglobals` exceptions are
  stateless singletons (a `validator.New()`, cached `reflect.Type`s) and `// test export`
  aliases in `export_test.go`.
- **Derived catalogs are test-enforced.** Package tests pin the `nonChatProviders` exclusions
  and fail unless the `CanonicalEnvKeyLookup` keys are set-equal to the LLM provider catalog
  and every catalog entry has a `docs/providers/<name>.md` guide; chat capability is not
  mechanically verifiable, so re-check each provider's `ChatCompletion` body on every Bifrost
  bump and update the exclusions, env row, and doc together. The connector registry has the
  same convention: `internal/auth/connector_docs_test.go` fails unless every connector id
  `GetProviders` can register has a guide at `docs/connectors/<file>.md`; when adding a
  connector, add its doc and the test-table row together.

### CI and release

- `.github/workflows/ci.yaml` runs `make check` as the single **`Lint & Test`** job on every PR
  against `main`; a bootstrap step installs the pinned shellcheck (download + SHA-256 verify) and
  the pinned Pester/PSScriptAnalyzer modules, versions read from the `Makefile` via `make -s
  print-*`. The job is gated to pull requests (the workflow also fires on push to `main`, where
  it skips). Direct pushes to `main` are **blocked** by an active GitHub **ruleset** (squash-only
  merges, linear history, required review-thread resolution, no human bypass) whose required
  status checks, under a strict up-to-date policy, are **`Lint & Test`**, **`Validate PR title`**
  (`semantic-pr.yaml`), and **`Build & smoke-test macOS packaging toolchain`**
  (`pkg-tools.yaml`); the ruleset also runs Copilot code review on each
  push. The pre-commit hook runs the fast hermetic `make check-go`, a local mirror of the Go half
  of the gate, not the enforcement boundary.
- `.github/workflows/install-e2e.yaml` exercises the real installer against the goreleaser
  release archives for release confidence. It does not run on normal PRs: a `detect` job flags
  release-please PRs and manual `workflow_dispatch`, one `snapshot` job builds the archives
  (`make snapshot`), and per-OS jobs run the installer tests: Linux via
  `test/install.e2e.test.sh`, Windows via the Pester suite under Windows PowerShell 5.1 (the
  `install.ps1` floor), hermetic via a stubbed `gh` and a loopback fixture server. None is a
  required status check, so they gate release-please PRs and on-demand runs, never normal
  merges.
- `.github/workflows/llm-smoke.yaml` runs the live LLM smoke against real providers as a
  PRE-PUBLISH RELEASE GATE, not on pull requests. Two entry points: `workflow_call` (the
  Release Pipeline, with `ref: <release SHA>`) and `workflow_dispatch` for maintainers.
  There is deliberately no filter input, so every invocation is the full roster and a
  caller cannot weaken the gate. Six legs across three credential families, as static
  `strategy.matrix.include` rows: `gcp-wif` (Vertex via Workload Identity Federation,
  no-tool + tools), `aws-oidc` (Bedrock via GitHub OIDC under a static
  `environment: aws-ci`, no-tool + tools), and the api-key family (direct OpenAI and
  Anthropic, tools). The api-key family is TWO mutually exclusive jobs because
  `environment:` must stay a static literal: `api-key-release` uses the un-reviewed
  `llm-api-keys-release` (so a release cannot pend up to 30 days on an approval while
  holding the `release-pipeline` concurrency group with an unpublished draft), and
  `api-key-manual` uses the reviewer-gated `llm-api-keys` for ad-hoc dispatches. The two
  no-tool legs are the connector-dark tripwire that keeps WIF/OIDC credentials out of the
  ambient environment; that assertion exists ONLY in the no-tool suite, so
  `SMOKE_REQUIRE_NO_CONNECTORS` is derived from the suite inside the run step rather than
  carried as a matrix key, and `SMOKE_REQUIRE_RUN` is a hardcoded `"1"` with no optional
  legs. `test/llm-smoke-roster.unit.test.sh` pins the workflow's static contract as a
  golden under `make sh-test`, replacing the deleted JSON manifest and its Go validator:
  each leg's full id/family/suite/provider/model-variable tuple (ids alone would let a
  leg silently change suite or provider while staying green), the gate-assert
  ROSTER/JOBS/PROOFS literals derived from the same canonical rows (a leg dropped from
  the fan-in is invisible to the runtime checks while the remaining legs stay green),
  and each smoke step's operational seam (the matrix suite/provider/model bindings and
  the suite dispatcher that derives the connector-dark tripwire).
- Releases are automated by **release-please** (`release-please-config.json`,
  `.release-please-manifest.json`); Conventional Commit prefixes in PR titles determine the
  version bump, enforced by `semantic-pr.yaml`. Dependency bumps use the `deps:` type
  (Dependabot's commit prefix) and render under a dedicated Dependencies changelog section, one
  entry per updated package: the auto-merge workflow writes a release-please commit-override
  block into the PR body via `scripts/ci/dependabot-commit-override.sh` (unit-tested by `make
  sh-test`), falling back to the group title when the metadata cannot be parsed. `deps` commits
  still cut patch releases; `release-please-config.json` pins the visible section list
  explicitly, so re-check it when release-please is bumped. `.goreleaser.yaml` handles binary
  builds for release tags. The Release Pipeline splits at the publish boundary: the `release`
  job builds, signs, and statically asserts everything, then hands the draft's exact asset set
  (pkgs, archives, manifests) to downstream jobs as the `release-artifacts` workflow artifact;
  the `macos-pkg-smoke` job (pinned `macos-26` + `macos-26-intel`, no secrets) runs
  `test/pkg.smoke.test.sh` against each pkg on its native arch (sha256 vs manifest, pkgutil
  signature, stapler validate, gating spctl Gatekeeper assess, real `installer` install, receipt
  version, exact `--version`); the `archive-smoke` job (ubuntu-latest, ubuntu-24.04-arm,
  windows-latest, windows-11-arm; no secrets) runs `test/archive.smoke.test.sh` and
  `test/archive.smoke.test.ps1` (Windows PowerShell 5.1) against each Linux tar and Windows zip
  on its native arch (sha256 vs manifest, checksums.txt row cross-check, exact-member tar
  extraction on Linux, `Expand-Archive` with a root-layout check on Windows, executable bit on
  Linux, PE machine arch on Windows, exact `--version`); the `connector-e2e` job calls
  `.github/workflows/connector-e2e.yaml` (`workflow_call` with `ref: <release SHA>`) against the
  real GCP, AWS, and GitHub fixture accounts, so a release whose connector cannot authenticate,
  cannot read, or **fails to deny a write** cannot publish. The `llm-smoke` job calls
  `.github/workflows/llm-smoke.yaml` the same way (`workflow_call` with `ref: <release SHA>`,
  ceiling raised to `id-token: write`), so a release whose model path cannot authenticate,
  answer, or drive the tool loop cannot publish. `publish` gates on both gates the same way: an
  exact `== 'success'` result AND an `outputs.gate_sha` equal to the release SHA, because a
  result check alone is satisfied by a gate that tested nothing. One workflow now covers what
  used to be three separate per-connector reusable workflows; it still receives the fixture App's
  private key through a declared `workflow_call` secret (never `secrets: inherit`). It exercises the
  source at the **release** SHA, not the triggering SHA (release-please re-derives its work from
  repository state, so the two can diverge, and a gate that tested the wrong commit would be
  worthless) and not the built artifacts, so it needs no `release-artifacts` hand-off and runs in
  parallel with the install smokes; the calling job must raise the token ceiling to
  `id-token: write`, since a reusable workflow can never exceed its caller's grant.
  **The gate's danger is fail-OPEN, and this is still why the machinery exists.** GitHub reports a
  conditionally **skipped job as a SUCCESS** to its caller, and a workflow run concludes success
  once at least one job has succeeded and none has failed, so a gate whose live connector jobs all
  skipped, sitting next to one cheap job that passed, would read GREEN. `connector-e2e.yaml` has
  two entry points: `workflow_call`, which is always the full gate, and `workflow_dispatch`, which
  adds a connector filter so a maintainer can rerun one suite. There is no `pull_request` trigger
  and no `detect` job any more, so the connector e2es no longer run on release-please PRs; a
  broken connector now surfaces for the first time at this pre-publish gate, while the draft is
  still unpublished. There is also deliberately no `gate:` input: the old per-suite workflows took
  one, and a caller passing `gate: false` got a green result from a run that tested nothing. Every
  `workflow_call` IS the full gate now, and the contract script
  (`scripts/ci/ci-gate-contract.sh`) rejects a call that carries a connector filter, so
  narrowing the roster exists only on the manual-dispatch side. Because a called workflow sees the
  *caller's* event (`push` on the release path), `github.event_name` cannot identify the release
  call; the discriminator is structural instead: `github.workflow_ref` names the caller's workflow
  file, `job.workflow_ref` names the file defining the current job, and equal-vs-different means
  direct-dispatch-vs-reusable-call. On the reusable-call path the caller is then pinned to the
  exact string `cynative/cynative/.github/workflows/release.yaml@refs/heads/main`. One job now
  covers each credential family rather than each connector: `gcp-wif` and `aws-oidc` are
  single-row matrices today (GKE #117 and EKS #116 reuse the same federation, so onboarding them
  is a data change, not a new job), and `github-app` is a static singleton; each family job still
  carries an explicit `github.repository` guard, since these are **public** reusable workflows and
  cloud trust alone does not prove a fork never reaches the credential step. Each leg's sentinel
  step asserts `steps.e2e.outcome`, the value from before `continue-on-error` is applied so it
  catches a skipped or merely tolerated step, and emits a connector-specific proof output; a
  closing `gate-assert` job runs under a bare `always()` and requires the full connector roster,
  cross-checking that roster against the job's actual `needs` set so a family dropped from `needs`
  (or never added to the roster) cannot silently disappear. `publish` then gates on a single
  `== 'success'` term for the whole `connector-e2e` job plus a `gate_sha` equality check, so a
  fan-in that is removed, skipped, or short one connector returns an empty proof and blocks the
  release rather than waving it through. The fail-closed logic, the invocation contract and the
  roster assertion, lives in `scripts/ci/ci-gate-contract.sh` and `scripts/ci/ci-gate-assert.sh`,
  each with offline unit tests gated by `make sh-test`, so it is exercised on every PR rather
  than only on a live release run; `make sh-test` also asserts the trusted-caller pin in both
  gate workflows directly and pins the publish gate's required conjuncts (the two gate result
  and gate_sha terms plus the non-empty release SHA) against `release.yaml`. Both scripts are
  now shared with the LLM gate: the connector
  gate passes `DISPATCH_POLICY: filtered` (a dispatch must carry a selector from an allowlist),
  while the LLM gate passes `full-only` (a dispatch must not carry one). The
  `publish` job re-asserts the
  still-editable draft (same id,
  same exact asset set) immediately before publishing, then verifies and pushes the tap; a
  separate `candidate-pr` job (gated on `publish`) then runs release-please phase 2. Phase 2
  lives in its own job, not inside `publish`, so a flake computing the next-release candidate
  can never fail `publish` and skip the post-publish channel jobs (cynative#140). Publish is
  additionally gated on `scripts/release/audit-formula.sh`
  (offline `brew audit --strict` of the rendered formula in a throwaway tap, in the `release`
  job); any pre-publish failure leaves the draft intact. Publish requires
  `result == 'success'` from every gate job (not `!= 'failure'`), so a cancelled gate blocks the
  publish; that is also why `connector-e2e.yaml` scopes `cancel-in-progress` to `workflow_dispatch`
  runs and gives the gate path its own run-id concurrency group (a called workflow's concurrency
  group is evaluated in the caller's context, so it would otherwise collide with a standalone run
  on the same ref). After the tap push, the pipeline calls
  the reusable `.github/workflows/homebrew-smoke.yaml`
  (also maintainer-dispatchable), which waits for the tap to serve the new version and runs
  the Homebrew install smoke on macOS and Linux. It also calls the reusable
  `.github/workflows/install-script-smoke.yaml` (also maintainer-dispatchable) once the
  `publish` job completes, which runs the documented `curl | sh` install path on Linux and macOS
  and the `irm | iex` path on Windows PowerShell 5.1 against the public release assets. It also
  calls the reusable `.github/workflows/scoop-smoke.yaml` (also maintainer-dispatchable), which
  waits for the public Scoop bucket to serve the new version and runs the Scoop install smoke on
  windows-latest. For all three: a red channel smoke with a green `publish` job means
  public-channel drift, nothing to roll back.
- The macOS packaging toolchain (the `pkg-tools.yaml` required check) is built by
  `scripts/release/install-pkg-tools.sh` from two git submodules, `third_party/bomutils` and
  `third_party/xar`, plus `tools/rcodesign` (a Cargo stub that pins the `apple-codesign`
  version so Dependabot tracks it). A normal clone does not need the submodules: `make check`
  never touches them. Run `git submodule update --init third_party/bomutils third_party/xar`
  only when working on the packaging scripts; the workflow rebuilds only when those paths
  change.
