#!/bin/sh
# homebrew.smoke.test.sh - post-release Homebrew install smoke (cynative#45).
#
# Installs cynative from the public tap via the documented
# `brew install cynative/tap/cynative`, asserts `cynative --version` reports
# exactly the expected version, uninstalls, and asserts it is gone. Catches
# public-channel drift: a stale tap, a broken formula, an uninstallable
# tarball. NOT hermetic: talks to the public tap and GitHub releases, and
# there is deliberately no skip path (no legitimate "not configured" state).
#
# Usage: sh test/homebrew.smoke.test.sh
#
# Env:
#   SMOKE_VERSION  expected version, bare, no leading v (e.g. 0.4.0). When
#                  unset, resolved from the latest published GitHub release.
set -eu

command -v brew >/dev/null 2>&1 || {
	# shellcheck disable=SC2016 # the $(...) is a hint for the user to run, not to expand here.
	printf 'FAIL: brew not found (https://brew.sh; Linux: eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)")\n' >&2
	exit 1
}

# No auto-update: the install needs no updated core, and auto-update is
# avoidable latency and flake surface, in CI and locally.
HOMEBREW_NO_AUTO_UPDATE=1
export HOMEBREW_NO_AUTO_UPDATE

version=${SMOKE_VERSION:-}
if [ -z "$version" ]; then
	command -v curl >/dev/null 2>&1 || { printf 'FAIL: curl not found (needed to resolve the latest release)\n' >&2; exit 1; }
	# releases/latest 404s when no published full release exists; -f turns that
	# into a non-zero exit. Wrapped so set -e does not abort before the message.
	set +e
	body=$(curl -fsSL https://api.github.com/repos/cynative/cynative/releases/latest)
	rc=$?
	set -e
	[ "$rc" -eq 0 ] || { printf 'FAIL: no published release to smoke (releases/latest returned an error)\n' >&2; exit 1; }
	# Minimal parser, no jq: first "tag_name": "vX.Y.Z" wins.
	tag=$(printf '%s\n' "$body" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
	[ -n "$tag" ] || { printf 'FAIL: could not parse tag_name from releases/latest\n' >&2; exit 1; }
	version=${tag#v}
fi

printf '== SMOKE == cynative %s via brew\n' "$version" >&2

# Auto-update is off, so an already-tapped cynative/tap from an earlier local
# run would serve a stale formula; refresh it explicitly. A no-op in CI (clean
# runner, never pre-tapped).
if brew tap | grep -qx 'cynative/tap'; then
	git -C "$(brew --repository cynative/tap)" pull --ff-only --quiet || {
		printf 'FAIL: could not refresh the already-tapped cynative/tap\n' >&2
		exit 1
	}
fi

# Pollution guard: a preexisting binary would make every later assertion lie.
if command -v cynative >/dev/null 2>&1; then
	printf 'FAIL: cynative already on PATH (%s); refusing to smoke a polluted environment\n' "$(command -v cynative)" >&2
	exit 1
fi

brew install cynative/tap/cynative || { printf 'FAIL: brew install cynative/tap/cynative failed\n' >&2; exit 1; }

# Exact first-line match, not a substring grep: prefix/substring false
# positives are a known trap, and a stale tap serving the previous release
# must fail loudly.
first_line=$(cynative --version | head -n 1)
if [ "$first_line" != "cynative $version" ]; then
	printf 'FAIL: --version reported "%s", expected "cynative %s" (stale tap?)\n' "$first_line" "$version" >&2
	exit 1
fi

brew uninstall --formula cynative || { printf 'FAIL: brew uninstall failed\n' >&2; exit 1; }
if brew list --formula cynative >/dev/null 2>&1; then
	printf 'FAIL: cynative still listed by brew after uninstall\n' >&2
	exit 1
fi
if command -v cynative >/dev/null 2>&1; then
	printf 'FAIL: cynative still on PATH after uninstall (%s)\n' "$(command -v cynative)" >&2
	exit 1
fi

printf 'homebrew.smoke: OK (cynative %s installed, verified, uninstalled)\n' "$version" >&2
