#!/bin/sh
# install-script.smoke.test.sh - post-release public install-script smoke (cynative#47).
#
# Runs the documented public install path end to end: fetches install.sh from
# raw.githubusercontent.com at main (never the local checkout - public-channel
# fidelity is the point), installs the expected release from the public GitHub
# release assets, asserts the installed binary reports exactly the expected
# version, uninstalls via the documented paired path, and asserts the binary is
# gone. The install-script sibling of homebrew.smoke.test.sh. NOT hermetic:
# talks to raw.githubusercontent.com and GitHub releases, and there is
# deliberately no skip path (no legitimate "not configured" state).
#
# The version is always pinned via the documented CYNATIVE_VERSION knob:
# deterministic, and the installer's own anonymous releases/latest call risks
# rate-limit flakes on shared runner IPs. Attestation stays advisory
# (CYNATIVE_REQUIRE_ATTESTATION=0): GitHub produces release attestations
# asynchronously, 15-20+ minutes after publish, so requiring them here would
# flake; neither the verified nor the warning message is asserted.
#
# Usage: sh test/install-script.smoke.test.sh
#
# Env:
#   SMOKE_VERSION  expected version, bare, no leading v (e.g. 0.4.0). When
#                  unset, resolved from the latest published GitHub release.
set -eu

INSTALLER_URL='https://raw.githubusercontent.com/cynative/cynative/main/install.sh'

command -v curl >/dev/null 2>&1 || { printf 'FAIL: curl not found (needed to fetch the public installer)\n' >&2; exit 1; }
# An empty HOME would point the guard, install, and cleanup at /.local/bin.
[ -n "${HOME:-}" ] || { printf 'FAIL: HOME is unset or empty\n' >&2; exit 1; }

# Env hygiene: a run must not silently dodge the public channel, the default
# install dir, or main-under-test execution.
unset CYNATIVE_BASE_URL CYNATIVE_INSTALL_DIR CYNATIVE_TEST_SOURCE

version=${SMOKE_VERSION:-}
if [ -z "$version" ]; then
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
	# Fail closed on a tag of exactly "v": an empty version would un-pin the install.
	[ -n "$version" ] || { printf 'FAIL: resolved an empty version from tag "%s"\n' "$tag" >&2; exit 1; }
fi

printf '== SMOKE == cynative %s via the public install.sh\n' "$version" >&2

target="$HOME/.local/bin/cynative"

# Pollution guard: a preexisting binary or dangling symlink would make every
# later assertion lie.
if [ -e "$target" ] || [ -L "$target" ]; then
	printf 'FAIL: %s already exists; refusing to smoke a polluted environment (a previous failed run may have left it behind: rm %s)\n' "$target" "$target" >&2
	exit 1
fi

# Best-effort failure cleanup: armed only after the pollution guard (so a
# preexisting binary is never deleted), disarmed once the uninstall assertions
# pass, and nonfatal so it preserves the primary exit status. Signals must
# terminate, not resume: a caught INT/TERM whose handler returns would let the
# script run on after cancellation, so those traps exit (which fires the EXIT
# trap and runs cleanup).
armed=1
cleanup() {
	[ "$armed" = 1 ] || return 0
	rm -f "$target" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Install: the real documented one-liner. The pins are exported variables, not
# inline assignments on curl, so they reach the downstream sh.
CYNATIVE_VERSION="v$version"
CYNATIVE_REQUIRE_ATTESTATION=0
export CYNATIVE_VERSION CYNATIVE_REQUIRE_ATTESTATION
curl -fsSL "$INSTALLER_URL" | sh || { printf 'FAIL: documented install one-liner failed\n' >&2; exit 1; }
# A failed curl feeds sh an empty script that exits 0, so assert the outcome
# explicitly rather than trusting the pipeline status.
[ -e "$target" ] || { printf 'FAIL: %s not installed (did the installer download fail?)\n' "$target" >&2; exit 1; }

# Verify by absolute path (runners do not have ~/.local/bin on PATH): exit
# status first, never masked behind a pipe, then the exact first line - a
# stale asset serving the previous release must fail loudly.
set +e
out=$("$target" --version)
rc=$?
set -e
[ "$rc" -eq 0 ] || { printf 'FAIL: %s --version exited %s\n' "$target" "$rc" >&2; exit 1; }
first_line=$(printf '%s\n' "$out" | head -n 1)
if [ "$first_line" != "cynative $version" ]; then
	printf 'FAIL: --version reported "%s", expected "cynative %s" (stale release asset?)\n' "$first_line" "$version" >&2
	exit 1
fi

# Uninstall: the documented paired path.
curl -fsSL "$INSTALLER_URL" | sh -s -- --uninstall || { printf 'FAIL: documented uninstall one-liner failed\n' >&2; exit 1; }
# The uninstaller's own existence check is -e, so a dangling symlink would be
# reported as "nothing to remove" and left behind; assert full absence,
# matching the pollution guard's definition.
if [ -e "$target" ] || [ -L "$target" ]; then
	printf 'FAIL: %s still present after uninstall\n' "$target" >&2
	exit 1
fi
armed=0

printf 'install-script.smoke: OK (cynative %s installed, verified, uninstalled)\n' "$version" >&2
