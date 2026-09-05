# AGENTS.md

Guidance for Claude Code (claude.ai/code) and other coding agents working in this repository.
`CLAUDE.md` is a symlink to this file, so writing either path rewrites the same file.

## Project

cynative is a single Go binary (Go 1.27, cobra) that drives an LLM research loop over cloud and
source-control environments. The model writes JavaScript that runs in an embedded sobek sandbox and
calls host tools from there. Every credentialed request passes a client-side read-only gate before
the credential is attached, and a request the gate cannot classify is denied. The LLM backend is an
embedded Bifrost SDK, one provider per run. `docs/project/architecture.md` has the component map and
`docs/project/threat-model.md` the security model; read the second before changing anything under
`internal/auth`, `internal/transport`, `internal/redact` or `internal/sandbox`.

## Commands

- `make check` is the CI gate: `check-go` (mod-tidy-check, generate, lint, shell-complexity, format diff, race tests with the coverage gate, windows cross-build) plus `check-scripts` (shellcheck, PSScriptAnalyzer, Pester, `sh-test`). `make check-go` needs Go, the module cache and a C compiler for the race tests; run it before every commit.
- `.pre-commit-config.yaml` wires `make check-go` as a hook, but the hook exists only where `pre-commit install` was run. A `git commit` that succeeds proves nothing about the gate unless that hook is installed.
- Run `make generate` before `go test ./internal/<pkg>` on a fresh checkout. The moq mocks (`*_mock_test.go`) are gitignored and package tests do not compile without them; `make test` and `make lint` regenerate them. A new `//go:generate go tool moq -out <name>_mock_test.go . <Iface>` must keep that suffix or the mock gets committed.
- One test: `go test ./internal/agent -run TestName -count=1`. Add `-race` to match CI (it needs CGO).
- `make format` regenerates the gitignored mocks, then runs `go tool golangci-lint fmt --diff`, which prints a diff and fails without rewriting sources. To rewrite files run `go tool golangci-lint fmt`.
- The Go tools the gates use (golangci-lint, moq, gocyclo, gocognit, goreleaser) are declared in the `tool` block of `go.mod`, pinned by its `require` entries and invoked as `go tool <name>`. Do not install them separately; Dependabot bumps them.
- `make check-scripts` installs nothing. It needs shellcheck at the exact `SHELLCHECK_VERSION`, PowerShell 7 with the pinned Pester and PSScriptAnalyzer, python3, PyYAML and jq. Those pins sit at the top of the `Makefile` and are bumped by hand.
- A new `test/*.unit.test.sh` suite runs only once you add it to the `sh-test` recipe in the `Makefile`. Connector selftests, tracked `*.sh` files (shellcheck), tracked `*.ps1` files (`pwsh-lint`) and `test/*.Tests.ps1` suites (`pwsh-test`) are discovered by glob.
- The live suites are standalone and never part of `make check`. `llm-smoke`, `llm-tools-smoke` and `connector-<provider>-e2e` skip with exit 0 when their env is unset unless the suite's `*_REQUIRE_RUN=1` knob is set; every CI leg sets that knob, so set it when wiring a suite into a workflow or the job passes by skipping. `install-e2e` builds a snapshot and runs on Linux and macOS regardless of env (it skips only on an unsupported OS or arch); `homebrew-smoke` and `install-script-smoke` install from the public release assets and never skip.
- Do not search with `find .` or `grep -r .` from the repo root. `.claude/worktrees/` can hold dozens of full repo copies that git excludes but the filesystem does not; use `git ls-files` and `git grep`. `make shell-complexity` walks with `find .` and scans those copies too, so a violation it reports under `./.claude/worktrees/` is a stale copy, not the tracked file.

## Gates that shape every change

- IMPORTANT: `make test` fails on any uncovered statement outside `*_shell.go` files and `internal/auth/authtest`, and `make shell-complexity` fails any `*_shell.go` function over cyclomatic or cognitive complexity 6 (it also rejects `//gocyclo:ignore` and `//gocognit:ignore`). Fix uncovered core code with a test that reaches it, and fix an over-budget shell function by moving the logic into a covered core file. Never raise a budget, never add an unreachable defensive branch to satisfy a linter, never park logic in a shell file to dodge coverage.
- A core error path that no test can reach (a constructor whose real implementation cannot fail) is handled by a factory field defaulted, branch-free, to a `*_shell.go` function. See `build: buildRuntime` in `internal/sandbox/sandbox.go` and `newBackend: bifrostShellInit` in `internal/llm/chatmodel.go`. A nolint is not the fix.
- `internal/auth/authtest` may be imported only from `_test.go` files. `make test` runs a `go list` import guard across every shipped GOOS/GOARCH and fails on a non-test importer.
- `mod-tidy-check` runs `go mod tidy -diff`, which fails on an untidy `go.mod` or `go.sum` without rewriting them. Run `go mod tidy` after any dependency change.
- `catalog-check` (in `check-go`) renders `docs/agents-catalog.md` from the staged `agents/*.md` and compares it with the staged catalog, so a staged agent name or description change fails until `make generate` has run and the regenerated catalog is staged too. Both sides are raw index blobs, never the working tree. The catalog is generated; do not edit it by hand.
- `windows-build` cross-compiles for windows/amd64 and windows/arm64. Unix-only calls need a build-tagged sibling, as in `internal/cli/tty_unix_shell.go` and `tty_other_shell.go`.

## Code style where it differs from Go defaults

- `.golangci.yaml` (golangci-lint v2) is strict: golines at 120 columns, goimports local prefix `github.com/cynative/cynative`, gofumpt, `godot` (every comment ends in a period), `mnd` (no magic numbers), `funlen` at 100 lines or 50 statements, `cyclop` 30, `gocognit` 20, `nestif`, `funcorder`, `testpackage`, `paralleltest`, `nonamedreturns`, `exhaustive`, `errname`.
- No `init()` and no mutable package globals. `//nolint:gochecknoglobals` is accepted for immutable lookup tables, stateless singletons such as `validator.New()` or a cached `reflect.Type`, and `// test export` aliases in `export_test.go`.
- IMPORTANT: read the process environment only in the composition root and the `*_shell.go` files. `forbidigo` bans `os.Getenv`, `os.LookupEnv`, `os.Environ` and `t.Setenv` everywhere except `*_shell.go`, `internal/cli/root.go` and `internal/cli/wire_shell.go`. Everything downstream takes an injected lookup func (`llm.LookupEnv`, or a local `func(string) (string, bool)`), and tests pass a fake.

  ```go
  key, _ := os.LookupEnv("OPENAI_API_KEY") // wrong inside a core package: forbidigo fails lint
  key, _ := lookupEnv("OPENAI_API_KEY")    // right: lookupEnv is the llm.LookupEnv the constructor received
  ```

- `forbidigo` also bans `http.Request.Host` everywhere. Go derives the wire authority from the URL, and a second authority is how the classified host and the sent host once diverged (#243).
- Ports and adapters: anything that touches the outside world (cloud SDKs, os, filesystem, network, stdio, term, the Bifrost client, the sobek runtime) is a constructor-injected interface or func field defaulted to the real implementation. Tests swap it through a `With*` option in `export_test.go`, never by reassigning a package var. Multi-method ports get moq mocks. A `json.Marshal` whose error path no test can reach is either passed in as a func, the way `codeDescription` in `internal/tools/codeexec.go` takes it, or has its error discarded under a comment saying why it cannot fail, as `internal/tools/httptool.go` does.
- Every `//nolint` is `//nolint:<linter> // reason`. nolintlint rejects a bare marker and a missing reason, except for `funlen`, `gocognit` and `golines`, where it allows the omission; write the reason anyway. The `//nolint:exhaustruct`, `//nolint:lll` and `//nolint:errchkjson` markers in the tree are inert (those linters are commented out), so do not add new ones.
- Errors wrap with `%w`. Sentinels are named `ErrX` and error types `XError` (`errname` enforces it).
- `internal/schema` imports only the standard library and `github.com/invopop/jsonschema`, pinned by the depguard rule `schema-pure-leaf` and `TestPackageIsPureLeaf`. `internal/auth/authreq`, `internal/auth/exposure`, `internal/auth/cloudauth`, `internal/cache`, `internal/interrupt` and `internal/redact` are leaves by convention: never import another internal package from them.

## Tests

- Every test and subtest calls `t.Parallel()` (`paralleltest`; exempt are `*_shell_test.go` and the entry-point tests that mutate `os.Args` under `//nolint:paralleltest`). The suite runs under `-race -shuffle=on`, so tests share no mutable state and assume no ordering.
- Layout: `foo_test.go` is external `package foo_test` (`testpackage` enforces it), `foo_internal_test.go` is in-package, `export_test.go` exposes `With*` options, small constructors and `// test export` aliases, `*_mock_test.go` is moq output, `*_fuzz_test.go` or `*_fuzz_internal_test.go` guards a parser on the trust boundary.
- No fuzz corpus is committed and `make check` never passes `-fuzz`, so a fuzz target's `f.Add` seeds are the whole gate. Add a seed for every branch you add to a fuzzed parser.
- A new connector needs `docs/connectors/<file>.md` plus a row in both `connectorDocs` (`internal/auth/connector_docs_test.go`) and `connectorArgsKeys` (`connector_args_test.go`). If it takes per-call arguments, its block in `transport.RequestArgs` is tagged exactly `<name>_auth` and that tag is the row's value; a connector with no block, like `github` and `gitlab`, gets an empty value. Neither table is checked against the connector registry, so a forgotten connector fails a test only if it adds a `<name>_auth` block.
- A Bifrost bump that adds a provider fails `TestCanonicalEnvKeyLookup_MatchesChatProviders` and `TestEveryChatProviderHasADocFile` in `internal/llm`. Read the provider's `ChatCompletion` body upstream, then either add a `CanonicalEnvKeyLookup` row plus `docs/providers/<name>.md`, or add it to `nonChatProviders` and `TestChatProviders_ExcludedPair`. A provider that gains chat support upstream fails no test, so re-read the exclusions on every bump.
- The AWS policy, GCP role and Azure role-definition defaults in `internal/config` are mirrored in `internal/auth/defaults.go`, and the Kubernetes cluster-role default in `internal/auth/k8sgate.go`; `defaults_internal_test.go` pins the four pairs, so change both sides.

## Architecture rules

The spine is cmd -> cli -> agent -> tools -> transport -> auth. `newDeps` in `internal/cli/wire_shell.go` is the composition root. Each package is a covered core plus a thin `*_shell.go` for glue that cannot be tested.

- New I/O tool: build it in `internal/tools` and append it to `primitives` in `buildToolSet` (`internal/cli/research.go`). That wraps it in the approval decorator at top level and exposes it raw inside `code_execution`. Scripts call inner tools with no approval prompt, so the tool has to enforce its own gates, the way `http_request` does through `internal/transport`. Implement `schema.StructuredRunner` so scripts receive a parsed object.
- An I/O tool that reports failure as a nil-error result string must call `audit.MarkFailed(ctx)`, as `internal/tools/httptool.go` does for a transport error or a status of 400 or more. Without it the call is audited `ok`, the failure streak resets and `max_consecutive_failures` never fires. Call `audit.MarkProgress(ctx)` on a useful result the same way, as `httptool.go` does for a sub-400 response; the sandbox forwards both counts from its inner calls, so a fan-out with some progress does not count as stuck.
- The orchestration tools (`write_todos`, `task`, `verify_findings`) live in `internal/agent`, not `internal/tools`, because they drive the loop's unexported `runState` (and `internal/agent`'s tests import `internal/tools`, so the reverse import would cycle the test build); they are registered without the approval wrapper because they do no credentialed I/O.
- Every nil-error I/O result re-enters the transcript through `wrapUntrusted`. The only unfenced returns are host-authored constants that carry no backend, provider or tool text, and a new one must be too.
- Per-run mutable state lives on `runState` in `internal/agent/loop.go`, never on `*Agent`: concurrent runs, each with its own `task` sub-runs, share one Agent, and `TestRun_ConcurrentRunsShareNoMutableState` runs them under `-race`.
- A new per-run stop sentinel in `loop.go`, the kind that ends a run without an answer, must be returned through `haltOr` and added to both `stopNotice` (agent.go) and `subagentStop` (task.go). Session-wide halts such as interrupt, budget and audit failure stay out of `subagentStop` so they propagate out of a sub-run. Those are hand tables, so an unmapped sentinel passes CI while `Run` exits 1 instead of `ErrNoAnswer`'s 2.
- A connector's credential header names live in two hand-synced lists that no test ties together: `credentialHeaders` in `rejectModelSuppliedCredential` (`internal/auth/provider.go`, request-side reject) and `denylistedHeaders` in `internal/redact/rules.go` (response-side scrub). Credential query params go in `credentialParams` beside the first and in `credentialRules` beside the second.
- The gate fails closed everywhere: an unclassifiable request, a missing catalog, an unresolved permission or an unparseable verifier verdict denies. Fix a false denial in the classifier or the pin, never with an allow fallback.
- `README.md` between `<!-- BEGIN agent-about -->` and `<!-- END agent-about -->` is embedded by root `about.go` and becomes the agent's system prompt; the `quickstart-example` block feeds first-run onboarding. Treat edits there as prompt changes. Tests require the sentence "Cynative runs frontier models" to survive.
- Root `agents.go` uses `//go:embed agents/*.md`, so only agent markdown enters the binary; the 45 built-in agents ship there and the manifest test in `internal/cli` pins the exact set. `--agent` files come only from `~/.cynative/agents/` and that embedded tree. Never add a working-directory tier: a checkout must not be able to supply the run's prompt.

## Package map

- `cmd/cynative`: `main`, calls `cli.Execute()` and exits with `cli.ExitCodeFor(err)`.
- `about.go`, `agents.go` (module root): `go:embed` of `README.md` and `agents/`; at the root because embed cannot reach a parent directory.
- `internal/cli`: cobra commands (root, `doctor`, `agents`), the composition root, exit codes, signal handling.
- `internal/agent`: the research loop, `write_todos`/`task`/`verify_findings`, untrusted fencing, halt conditions.
- `internal/agentcatalog`: named markdown agents for `--agent`; user tier plus embedded built-ins; closed frontmatter schema.
- `internal/schema`: provider-agnostic message and tool types; pure leaf.
- `internal/llm`: Bifrost adapter behind `schema.ChatModel`; derived provider catalog; env-var resolution.
- `internal/tools`: the I/O tools `http_request` and `code_execution`, plus the approval decorator.
- `internal/sandbox`: sobek JS runtime; tools exposed as async functions; rebuild-when-unusable rule.
- `internal/transport`: executes `http_request`: https only, no redirects, `Host` header rejected, dial-time IP guard, redaction on both exits.
- `internal/auth`: connector registry and the shared gates (`AuthorizeHost`, `AuthorizeAction`, `AuthorizeAddr`, `Inject`).
- `internal/auth/authreq`: the narrowed views (`View`, `AuditView`, `ProviderArgs`) the gates receive; stdlib only.
- `internal/auth/authtest`: fake providers for tests; test-only import.
- `internal/auth/aws`, `gcp`, `azure`: per-cloud host pinning and action authorization against a configured read-only policy or role.
- `internal/auth/k8s`: shared Kubernetes request classifier and RBAC matcher for `eks`, `gke`, `aks` and `kubernetes`.
- `internal/auth/github`, `gitlab`: request classifiers behind a per-category exposure ceiling.
- `internal/auth/exposure`, `internal/auth/cloudauth`: leaves; the first is the exposure-level lattice behind `github` and `gitlab`, the second the host normalizer and fetch shells behind `aws`, `gcp` and `azure`.
- `internal/cache`: on-disk TTL cache primitive.
- `internal/config`: loader for `~/.cynative/config.yaml` and the `CYNATIVE_*` env vars derived from struct tags; validators.
- `internal/audit`: fail-closed JSONL audit log and the per-call recorders (`Scope`, `Decision`, `Failure`, `Fatal`).
- `internal/redact`: secret redactor wired at transport responses, sandbox tool results before JavaScript sees them, every model call (`llm.NewRedactingChatModel` in `research.go`), the audit log and doctor output.
- `internal/metrics`: session-cumulative telemetry and the token budget.
- `internal/ui`: glamour rendering, approval prompter, raw-mode line editor, terminal controller.
- `internal/interrupt`: two-stage interrupt state shared by cli and ui.
- `scripts/ci`, `scripts/release`, `scripts/demo`: the gate contract and assert scripts plus the llm-smoke secret pin and the Dependabot commit override; release renderers, signing and macOS pkg assembly; demo capture.
- `test/`: shell and Pester unit suites, the live smoke and e2e suites, and `lib/connector_audit/`, the Python audit parser they share.
- `third_party/` (submodules `bomutils` and `xar`), `tools/rcodesign`: the macOS pkg toolchain that `scripts/release/install-pkg-tools.sh` installs and `pkg-tools.yaml` checks.
- `docs/connectors/`, `docs/providers/`: one guide per connector and per provider; the first is checked against the hand-kept `connectorDocs` roster, the second against the derived provider catalog.

## Boundaries

Always:
- Run `make check-go` before committing and `make check` before opening a PR.
- Add tests with every new branch. The coverage gate is exact.
- Update this file in the same PR when a change alters a command, gate or invariant it describes.
- Give the PR body the why and the verification evidence (the commands you ran and what they printed), not only the template checklist.

Ask first:
- Adding a dependency, a third-party GitHub Action or a config knob.
- Changing anything under `.github/workflows/`, `.goreleaser.yaml`, `.github/dependabot.yml` or `scripts/release/`.
- Widening an allowlist, a ceiling, a default role or policy, or a fail-closed branch in `internal/auth`, `internal/transport`, `internal/redact` or `internal/sandbox`.

Never:
- Hand-edit `CHANGELOG.md` or `.release-please-manifest.json`; release-please writes both.
- Hand-edit `docs/assets/demo*`. Regenerate with `scripts/demo/capture.sh` (`sanitize <raw>`, then `all`), which no make target or CI job runs. Raw captures and `scripts/demo/sanitize.map.local` hold real identifiers and are gitignored. `demo.gif` is composed outside the repo, so re-rendered SVGs leave it stale; say so rather than rebuilding it by hand.
- Raise a coverage or complexity budget, or add `//gocyclo:ignore` or `//gocognit:ignore`.
- Read the process environment or call `t.Setenv` outside the composition root and the shells.
- Loosen a golden test to a membership check so a workflow edit passes.
- Delete a Dependabot `ignore:` entry before the exit condition written above it is met, or hand-pin a module in `go.mod` to work around one.
- Log, print or return credential material. The redactor and the audit log are the boundaries.
- Commit secrets, real account or project identifiers, or fixture credentials.

## Git and PRs

- Branch from `main` as `<type>/<short-description>`, for example `fix/exit-code-no-answer` or `ci/release-dispatch-retrigger`. A ruleset blocks direct pushes to `main` for everyone except org admins and one GitHub App, so do not lean on it; always branch.
- PR titles are Conventional Commits, validated by `semantic-pr.yaml`; the allowed types are `build chore ci deps docs feat fix perf refactor revert style test`. Use `deps:` for dependency-only bumps and `fix:` only for product defects; mark breaking changes with `!` and a `BREAKING CHANGE:` footer. release-please derives the version and the changelog from these titles.
- Merges are squash-only with linear history. The ruleset requires `Lint & Test`, `Validate PR title` and `Build & smoke-test macOS packaging toolchain` to pass on an up-to-date branch, every review thread resolved and no open CodeQL alerts; it requires no approving review. Rebase onto `main` before asking for a merge, since a stale branch cannot merge.

## CI and release

- `connector-e2e.yaml` and `llm-smoke.yaml` are pre-publish release gates called from `release.yaml`, and both are pinned by goldens in `make sh-test`: `test/connector-e2e-roster.unit.test.sh` (parses the YAML and compares matrix rows, the whole `if:` of each credential-bearing job, of its `e2e` and `sentinel` steps and of the `gate-assert` job, step run bodies, step env key sets, step order and the fan-in literals), `test/llm-smoke-roster.unit.test.sh` (matrix tuples, fan-in literals, the `case "$SUITE"` dispatcher) and `scripts/ci/check-llm-smoke-secrets.py` (the exact two api-key secret names, which `release.yaml` forwards by name, never `secrets: inherit`). Edit workflow and golden in the same change.
- `connector-e2e.yaml` also carries a static `agent-e2e` job (`make agent-e2e`, `test/agent.e2e.test.sh`): a live run of a shipped built-in agent against the GCP fixture, a read plus a write canary, under the same golden.
- The gates exist because GitHub reports a skipped job as success. Every leg asserts its own outcome, and `publish` requires both `== 'success'` and a `gate_sha` equal to the release SHA from each gate. Keep both conjuncts.
- The workflow paths and the caller string `cynative/cynative/.github/workflows/release.yaml@refs/heads/main` are pinned literally: `EXPECTED_CALLER` in both gates, `TRUSTED_CALLER` and `GATE_WORKFLOWS` in the `Makefile`, and the GCP Workload Identity Federation condition outside the repo. Renaming a workflow file fails the pin check and the goldens until those references move, and then breaks cloud auth with no in-repo failure until the WIF condition is updated too.
- Live connector suites are named `test/connector.<provider>.e2e.test.sh`. `make connector-<provider>-e2e` is one pattern rule over that name and `make sh-test` discovers each suite's `--selftest` by that glob, so a renamed suite drops out of both.
- `install.ps1` and the `test/*.smoke.test.ps1` suites run under Windows PowerShell 5.1 in production, while `make pwsh-lint` lints every tracked `*.ps1` and `pwsh-test` runs the `test/*.Tests.ps1` suites under pwsh 7 on Linux. Syntax that only 7 accepts passes the gate and breaks the shipped installer.
- Never re-run a failed Release Pipeline run (secrets are snapshotted when the run is created) and never expect a fix commit to reach it (it rebuilds release-please's SHA, not HEAD). Follow the RECOVERY notes in `release.yaml`, retrigger with `scripts/release/retrigger.sh`, and ship a code fix as the next patch release. Post-publish red runs in `channel-smoke.yaml` and `attestation.yaml` are alarms, not rollbacks.
- A third-party GitHub Action must be on the repo's Actions allowlist (`gh api repos/cynative/cynative/actions/permissions/selected-actions`) or the run dies at `startup_failure` with no step logs. For a tool that is not listed, download and SHA-256-pin the binary the way `COSIGN_*` and `SHELLCHECK_*` are pinned in the `Makefile`.
- In `.goreleaser.yaml`, `draft: true` with `use_existing_draft: true` and `mode: keep-existing` is the handshake that adopts release-please's draft; `scoops[0].skip_upload: true` keeps goreleaser's Scoop manifest inert; the `signs:` stanza signs `checksums.txt` with cosign. `.goreleaser/entitlements.plist` must keep `allow-unsigned-executable-memory`, or the notarized macOS binary is SIGKILLed on the first Bifrost JSON marshal. `test/release-signing.unit.test.sh` pins the signing contract, and `make snapshot` keeps `--skip=sign`.
- `scripts/release/render-formula.sh` keeps the Formula `version` stanza because Homebrew misparses our asset names as versions, and `audit-formula.sh` runs `brew audit --strict --except=version` because the audit calls that stanza redundant and would fail the release over it. Keep both.

## Maintaining this file

Keep it under 200 lines. Add a line when an agent makes the same mistake twice. Remove a line agents follow without it, or turn it into a test or a hook. The reasoning behind each rule is in this file's git history and in the PRs that added the tests named above.

When a long session's context is summarized, keep the list of modified files and the make targets already run.
