#!/bin/sh
# pkg.smoke.test.sh - pre-publish macOS pkg install smoke (cynative#44).
#
# Installs a built cynative_Darwin_<arch>.pkg with the real macOS Installer
# and proves the user-facing layer the pipeline's static Linux-side checks
# (scripts/release/assert-pkg.sh) cannot: Gatekeeper accepts the package on
# a current macOS, installer(8) places /usr/local/bin/cynative with a valid
# receipt, and the installed binary runs and reports exactly the expected
# version. No LLM or connector coverage by design. No uninstall: the
# release-pipeline consumer is an ephemeral runner, and macOS ships no pkg
# uninstaller (a local run leaves /usr/local/bin/cynative and the
# com.cynative.cynative receipt behind; remove with rm plus pkgutil
# --forget).
#
# macOS-only. installer(8) needs root; the script invokes `sudo installer`
# (passwordless on GitHub macOS runners; a local run prompts).
#
# Usage: sh test/pkg.smoke.test.sh
#
# Env (all required, no fallbacks):
#   PKG_PATH         path to the .pkg to smoke
#   SMOKE_VERSION    expected version, bare, no leading v (e.g. 1.5.1)
#   EXPECTED_SHA256  sha256 the pkg bytes must match (as asserted against
#                    the draft release by the release job)
set -eu

fail() {
	printf 'FAIL: %s\n' "$1" >&2
	exit 1
}

[ "$(uname -s)" = "Darwin" ] || fail "requires macOS (uname -s: $(uname -s))"

[ -n "${PKG_PATH:-}" ] || fail "PKG_PATH is required"
[ -f "$PKG_PATH" ] || fail "PKG_PATH does not name a regular file: $PKG_PATH"
[ -n "${SMOKE_VERSION:-}" ] || fail "SMOKE_VERSION is required"
case "$SMOKE_VERSION" in
v*) fail "SMOKE_VERSION must be bare, without a leading v: $SMOKE_VERSION" ;;
esac
printf '%s' "${EXPECTED_SHA256:-}" | grep -Eq '^[0-9a-f]{64}$' \
	|| fail "EXPECTED_SHA256 must be exactly 64 lowercase hex chars"

printf '== SMOKE == %s (expecting cynative %s)\n' "$PKG_PATH" "$SMOKE_VERSION" >&2

# Integrity: the artifact hand-off delivered the exact bytes the release job
# asserted against the draft release. No pipeline: POSIX pipeline status
# would let a masked shasum failure through.
sha_line=$(shasum -a 256 "$PKG_PATH") || fail "shasum failed on $PKG_PATH"
actual=${sha_line%% *}
[ "$actual" = "$EXPECTED_SHA256" ] || fail "pkg sha256 $actual != expected $EXPECTED_SHA256"

# Pollution guard: a preexisting binary or receipt would let every later
# assertion pass against leftovers instead of this install.
[ ! -e /usr/local/bin/cynative ] \
	|| fail "/usr/local/bin/cynative already exists; refusing to smoke a polluted host"
if pkgutil --pkg-info com.cynative.cynative >/dev/null 2>&1; then
	fail "receipt com.cynative.cynative already present; refusing to smoke a polluted host"
fi

# Signature against the real macOS trust store. Gate on exit status plus the
# one stable substring; the wording of the status and notarization lines
# varies across macOS releases (stapler and spctl below are the notarization
# and policy gates).
sig=$(pkgutil --check-signature "$PKG_PATH" 2>&1) || fail "pkgutil --check-signature failed"
printf '%s\n' "$sig" >&2
printf '%s\n' "$sig" | grep -Fq 'Developer ID Installer:' \
	|| fail "signature is not a Developer ID Installer certificate"

# Staple: validation can consult Apple's ticketing service, a network flake
# surface, so retry (sleep only between attempts, never after the last).
attempt=1
until xcrun stapler validate -v "$PKG_PATH"; do
	[ "$attempt" -lt 3 ] || fail "stapler validate failed after 3 attempts"
	attempt=$((attempt + 1))
	sleep 10
done

# Gatekeeper must actually be assessing, or the policy verdict below would
# not reflect end-user behavior (a disabled Gatekeeper makes the gate
# vacuous). Fail-closed on either a non-zero exit or unexpected wording.
gk_status=$(spctl --status) || fail "spctl --status failed (assessments likely disabled)"
[ "$gk_status" = "assessments enabled" ] \
	|| fail "Gatekeeper assessments not enabled ('$gk_status'); install-policy gate would be vacuous"

# Gatekeeper install policy, the user-facing acceptance gate. Exit status
# only; the verbose output is diagnostics for the log, never parsed.
if ! spctl --assess --type install --verbose=4 "$PKG_PATH"; then
	sleep 5
	spctl --assess --type install --verbose=4 "$PKG_PATH" \
		|| fail "spctl rejected the pkg (Gatekeeper install policy)"
fi

# The real install. -dumplog mirrors package-scoped diagnostics into the CI
# log, so a failure is debuggable without shipping the runner-global
# /var/log/install.log.
sudo installer -dumplog -pkg "$PKG_PATH" -target / || fail "installer failed"

# Receipt: the plist form is the contract; the human-readable --pkg-info
# wording is not.
receipt=$(pkgutil --pkg-info-plist com.cynative.cynative) \
	|| fail "no receipt for com.cynative.cynative after install"
got=$(printf '%s\n' "$receipt" | plutil -extract pkg-version raw -o - -- -) \
	|| fail "could not extract pkg-version from the receipt plist"
[ "$got" = "$SMOKE_VERSION" ] || fail "receipt pkg-version '$got' != expected '$SMOKE_VERSION'"

# The installed binary actually runs: absolute path (no PATH ambiguity),
# exit code checked before the first-line comparison, exact match per repo
# convention (a prefix match would accept 1.2.30 for 1.2.3).
[ -x /usr/local/bin/cynative ] || fail "/usr/local/bin/cynative missing or not executable"
out=$(/usr/local/bin/cynative --version) || fail "cynative --version exited non-zero"
first_line=$(printf '%s\n' "$out" | head -n 1)
[ "$first_line" = "cynative $SMOKE_VERSION" ] \
	|| fail "--version reported '$first_line', expected 'cynative $SMOKE_VERSION'"

printf 'pkg.smoke: OK (%s installed, receipt com.cynative.cynative, cynative %s runs)\n' \
	"$PKG_PATH" "$SMOKE_VERSION" >&2
