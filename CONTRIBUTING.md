# Contributing to Cynative

Thanks for your interest in improving Cynative! Contributions are welcome — new
connectors and providers, evaluation datasets, documentation, and fixes across the
board.

## Development Prerequisites

- A Go toolchain matching the version in [`go.mod`](go.mod).
- `make` and a POSIX shell.
- Go tooling (`golangci-lint`, `moq`, complexity checkers) is pinned via `go.mod`
  and invoked through `make` — no separate installs. The shell/PowerShell gate
  (`make check-scripts`) additionally needs `shellcheck`, PowerShell 7 with
  Pester/PSScriptAnalyzer, `python3` (the `install.sh` loopback smoke test's
  fixture server), and `jq` (used by the Scoop-renderer and release asset-set
  suites inside `sh-test`); those versions are pinned in the `Makefile` and
  installed separately (`make check-scripts` prints an install hint if one is
  missing; `jq` is presence-checked one level down by the suites that need it).

On a fresh checkout, generate the gitignored mocks before running package tests:

```bash
make generate
```

## The gate: `make check`

Every PR must pass `make check`, which runs two halves:

- `make check-go` — `mod-tidy-check` + generate + lint + shell-complexity +
  format-diff + the full race-enabled test suite + `windows-build` (GOOS=windows
  amd64 and arm64). 100% `go.mod`-pinned; `mod-tidy-check` may consult the module
  cache, so the gate is not fully network-free. **The pre-commit hook runs this.**
- `make check-scripts` — `shellcheck` over every tracked `*.sh`, PSScriptAnalyzer over
  every tracked `*.ps1`, Pester over every tracked `test/*.Tests.ps1`, and `sh-test`
  (install.sh unit + loopback smoke, e2e-guardrails / connector-e2e / render-scoop /
  dependabot-override / assert-assets / ci-gate / llm-smoke-roster / retrigger unit
  tests, the connector audit-parser selftests, and the release-gate pins for trusted
  caller, publish `if:`, recovery triggers, and llm-smoke secret references). Needs
  `python3` and `jq`; tool versions are pinned in the `Makefile`.

```bash
make check
```

`check-go` enforces, among other things:

- **100% statement coverage** of core code (everything except `*_shell.go` files
  and the test-support package `internal/auth/authtest`, which an import guard
  keeps out of the shipped binary);
- the whole suite under `-race -shuffle=on`;
- **cyclomatic and cognitive complexity ≤ 6** on `*_shell.go` files (push branchy
  logic into covered core; never raise the budget);
- strict linting (`.golangci.yaml`) and formatting.

Add tests alongside any new code, or the coverage gate fails. Useful targets:
`make check-go`, `make check-scripts`, `make lint`, `make test`, `make format`, `make generate`.

## Pull Requests

- **Branch** from `main`; direct pushes to `main` are blocked.
- **Conventional-Commit PR titles** are required (CI enforces this): `feat:`,
  `fix:`, `docs:`, `refactor:`, `chore:`, etc. Dependency-only updates use
  `deps:` (rendered in the changelog's Dependencies section); reserve `fix:`
  for product defects. Use `!` and a `BREAKING CHANGE:` footer for breaking
  changes. Releases and the changelog are automated by release-please from
  these titles — **do not hand-edit `CHANGELOG.md`**.
- PRs are **squash-merged** with linear history; keep them focused.
- Required checks (`Lint & Test`, `Validate PR title`, `Build & smoke-test macOS
  packaging toolchain`) must pass and review threads must be resolved before merge.

## Reporting issues

- **Bugs / features:** open a GitHub issue with repro steps, the Cynative version,
  and your environment.
- **Security vulnerabilities:** do **not** open a public issue — follow
  [SECURITY.md](SECURITY.md).
