# Contributing to Cynative

Thanks for your interest in improving Cynative! Contributions are welcome — new
connectors and providers, evaluation datasets, documentation, and fixes across the
board.

## Development prerequisites

- A Go toolchain matching the version in [`go.mod`](go.mod).
- `make` and a POSIX shell.
- All tooling (`golangci-lint`, `moq`, complexity checkers) is pinned via `go.mod`
  and invoked through `make` — no separate installs.

On a fresh checkout, generate the gitignored mocks before running package tests:

```bash
make generate
```

## The gate: `make check`

Every PR must pass `make check` (generate + lint + shell-complexity + format-diff +
the full race-enabled test suite):

```bash
make check
```

It enforces, among other things:

- **100% statement coverage** of core (non-`*_shell.go`) code;
- the whole suite under `-race -shuffle=on`;
- **cyclomatic and cognitive complexity ≤ 6** on `*_shell.go` files (push branchy
  logic into covered core; never raise the budget);
- strict linting (`.golangci.yaml`) and formatting.

Add tests alongside any new code, or the coverage gate fails. Useful targets:
`make lint`, `make test`, `make format`, `make generate`.

## Pull requests

- **Branch** from `main`; direct pushes to `main` are blocked.
- **Conventional-Commit PR titles** are required (CI enforces this): `feat:`,
  `fix:`, `docs:`, `refactor:`, `chore:`, etc. Use `!` and a `BREAKING CHANGE:`
  footer for breaking changes. Releases and the changelog are automated by
  release-please from these titles — **do not hand-edit `CHANGELOG.md`**.
- PRs are **squash-merged** with linear history; keep them focused.
- Required checks (`Lint & Test`, `Validate PR title`) must pass and review threads
  must be resolved before merge.

## Reporting issues

- **Bugs / features:** open a GitHub issue with repro steps, the Cynative version,
  and your environment.
- **Security vulnerabilities:** do **not** open a public issue — follow
  [SECURITY.md](SECURITY.md).
