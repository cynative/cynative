# Homebrew install smoke

A small, live post-release check that the documented public Homebrew path
works: `brew install cynative/tap/cynative` installs the expected version,
`cynative --version` reports it, and `brew uninstall` removes it cleanly.
Unlike the hermetic test suite it talks to the public tap and GitHub releases
over the network, so it is **not** part of `make check`. It exists to catch
public-channel drift: a stale tap, a broken formula, a tarball that does not
install.

## When it runs

`.github/workflows/homebrew-smoke.yaml` is a reusable workflow with two entry
points and no PR trigger:

- The Release Pipeline calls it (`workflow_call` with the release tag) as the
  `homebrew-smoke` job, right after publishing the release and pushing the
  tap. A failure turns the release run red. Read the two-job color split: a
  red `release` job means the release itself needs recovery; a green
  `release` job with a red `homebrew-smoke` job means the release published
  fine but the public Homebrew channel is broken - investigate and re-run,
  nothing to roll back.
- Maintainers can dispatch it manually (`workflow_dispatch`); it then smokes
  the latest published release.

Inside, a `resolve` job pins the expected version and polls the tap (an
anonymous shallow git clone, the same mechanism brew itself uses to fetch a
tap; 30s interval, 10 minute budget) until the formula serves that version -
propagation defense on the call path, and cover for a manual dispatch racing
a still-running release. A matrix job then runs the
script on `macos-latest` (darwin/arm64) and `ubuntu-latest` (linux/x86_64),
the two documented platforms; the darwin/x86_64 and linux/arm64 tarballs
share the same formula logic and goreleaser build and are not separately
exercised.

## Run it locally

Needs brew on PATH (Linux: `eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"`).

```bash
make homebrew-smoke                      # smoke the latest published release
SMOKE_VERSION=0.4.0 make homebrew-smoke  # smoke an exact version (bare, no v)
```

There is no skip path: a missing brew or an unresolvable release is a hard
failure. Unlike the credential-gated live suites, "not configured" is not a
legitimate state for this script. A local run leaves the `cynative/tap` tap
tapped, which is harmless: the script refreshes an already-tapped
`cynative/tap` itself before installing (auto-update is disabled), so
repeated local runs stay accurate. `brew untap cynative/tap` removes it.

## What it asserts

- `cynative` is not already on PATH before the install (pollution guard).
- `brew install cynative/tap/cynative` succeeds.
- The first line of `cynative --version` is exactly `cynative <version>`: an
  exact match, not a substring grep, so a stale tap serving the previous
  release fails loudly.
- `brew uninstall --formula cynative` succeeds, after which
  `brew list --formula cynative` and `command -v cynative` both come up
  empty.

## The pre-publish audit gate

The smoke's sibling control runs BEFORE publish: the Release Pipeline renders
the formula from the asserted asset manifest and runs `brew audit --strict`
against it in a throwaway local tap (`scripts/release/audit-formula.sh`). A
failure stops the release with the draft intact and the tap untouched, so a
broken formula can never strand a published release behind a stale tap. The
audit is offline: draft assets are not publicly downloadable pre-publish, so
`--online` checks are impossible there. Any rule exclusion in the script is
narrow (`--except` for audit methods, `--except-cops` for style cops) and
justified inline.
