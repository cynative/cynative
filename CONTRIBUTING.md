# Contributing to Cynative

Thanks for your interest in improving Cynative! Contributions are welcome — new
connectors and providers, evaluation datasets, documentation, and fixes across the
board.

## Development prerequisites

- A Go toolchain matching the version in [`go.mod`](go.mod).
- `make` and a POSIX shell.
- Go tooling (`golangci-lint`, `moq`, complexity checkers) is pinned via `go.mod`
  and invoked through `make` — no separate installs. The shell/PowerShell gate
  (`make check-scripts`) additionally needs `shellcheck`, PowerShell 7 with
  Pester/PSScriptAnalyzer, and `python3` (the `install.sh` loopback smoke test's
  fixture server); those versions are pinned in the `Makefile` and installed
  separately (`make check-scripts` prints an install hint if one is missing).

On a fresh checkout, generate the gitignored mocks before running package tests:

```bash
make generate
```

## The gate: `make check`

Every PR must pass `make check`, which runs two halves:

- `make check-go` — the hermetic Go gate (generate + lint + shell-complexity +
  format-diff + the full race-enabled test suite + a `GOOS=windows` cross-build);
  100% `go.mod`-pinned. **The pre-commit hook runs this.**
- `make check-scripts` — `shellcheck` over every tracked `*.sh`, PSScriptAnalyzer on
  `install.ps1`, `test/install-script.smoke.test.ps1`, and `test/scoop.smoke.test.ps1`, the
  Pester unit tests, and the POSIX `install.sh` unit + loopback smoke tests (`sh-test`, which
  needs `python3`), each at a version pinned in the `Makefile`.

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

## Pull requests

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
