#!/bin/sh
# archive.smoke.test.sh - pre-publish release-archive install smoke (cynative#43).
#
# Proves a built cynative_Linux_<arch>.tar.gz release archive is installable:
# the archive bytes match the manifest digest the release job asserted against
# the draft release, checksums.txt describes those same bytes, the tar carries
# the binary at its root under the literal member name install.sh requests,
# the executable bit survived, and the binary runs and reports exactly the
# expected version. No chmod anywhere: install.sh repairs a wrong mode with
# chmod +x, so this smoke is the one gate that can catch a non-executable tar
# member. No LLM or connector coverage by design. The release pipeline runs it
# on the archive's native arch so --version execution is native; needs a POSIX
# sh, GNU tar, and sha256sum.
#
# Usage: sh test/archive.smoke.test.sh
#
# Env (all required, no fallbacks):
#   ARCHIVE_PATH     path to the .tar.gz to smoke
#   SMOKE_VERSION    expected version, bare, no leading v (e.g. 1.5.1)
#   EXPECTED_SHA256  sha256 the archive bytes must match (as asserted against
#                    the draft release by the release job)
#   CHECKSUMS_PATH   path to the checksums.txt release asset
set -eu

fail() {
	printf 'FAIL: %s\n' "$1" >&2
	exit 1
}

[ -n "${ARCHIVE_PATH:-}" ] || fail "ARCHIVE_PATH is required"
[ -f "$ARCHIVE_PATH" ] || fail "ARCHIVE_PATH does not name a regular file: $ARCHIVE_PATH"
[ -n "${SMOKE_VERSION:-}" ] || fail "SMOKE_VERSION is required"
case "$SMOKE_VERSION" in
v*) fail "SMOKE_VERSION must be bare, without a leading v: $SMOKE_VERSION" ;;
esac
printf '%s' "${EXPECTED_SHA256:-}" | grep -Eq '^[0-9a-f]{64}$' \
	|| fail "EXPECTED_SHA256 must be exactly 64 lowercase hex chars"
[ -n "${CHECKSUMS_PATH:-}" ] || fail "CHECKSUMS_PATH is required"
[ -f "$CHECKSUMS_PATH" ] || fail "CHECKSUMS_PATH does not name a regular file: $CHECKSUMS_PATH"

archive_name=$(basename "$ARCHIVE_PATH")
printf '== SMOKE == %s (expecting cynative %s)\n' "$archive_name" "$SMOKE_VERSION" >&2

# Integrity: the artifact hand-off delivered the exact bytes the release job
# asserted against the draft release. No pipeline: POSIX pipeline status would
# let a masked sha256sum failure through.
sha_line=$(sha256sum "$ARCHIVE_PATH") || fail "sha256sum failed on $ARCHIVE_PATH"
actual=${sha_line%% *}
[ "$actual" = "$EXPECTED_SHA256" ] || fail "archive sha256 $actual != expected $EXPECTED_SHA256"

# checksums.txt must describe these same bytes: both installers trust it, and
# nothing else in the pipeline compares its rows to the archives. Same awk
# shape and exactly-one-row contract as install.sh's verifier.
matches=$(awk -v f="$archive_name" '$2==f {print $1}' "$CHECKSUMS_PATH")
count=$(printf '%s' "$matches" | grep -c . || true)
[ "$count" = "1" ] || fail "expected exactly one checksums.txt row for ${archive_name}, found ${count}"
[ "$matches" = "$EXPECTED_SHA256" ] || fail "checksums.txt digest $matches != archive digest $EXPECTED_SHA256"

tmp=$(mktemp -d) || fail "mktemp failed"
trap 'rm -rf "$tmp"' EXIT INT TERM

# Selective extraction under the literal member name, the same shape
# install.sh runs: a ./-prefixed, renamed, or nested binary fails here exactly
# as it would for users.
tar -xzf "$ARCHIVE_PATH" -C "$tmp" cynative \
	|| fail "member 'cynative' not extractable from $archive_name (missing, nested, or ./-prefixed?)"

# A regular file (not a symlink smuggled under the member name) with the
# executable bit preserved; -x is the assertion install.sh masks with chmod.
[ ! -L "$tmp/cynative" ] || fail "extracted 'cynative' is a symlink, expected a regular file"
[ -f "$tmp/cynative" ] || fail "extracted 'cynative' is not a regular file"
[ -x "$tmp/cynative" ] || fail "extracted 'cynative' is not executable (archive lost the mode bit)"

# The extracted binary actually runs: absolute path, exit code checked before
# the first-line comparison, exact match per repo convention (a prefix match
# would accept 1.2.30 for 1.2.3).
set +e
out=$("$tmp/cynative" --version)
rc=$?
set -e
[ "$rc" -eq 0 ] || fail "cynative --version exited $rc"
first_line=$(printf '%s\n' "$out" | head -n 1)
[ "$first_line" = "cynative $SMOKE_VERSION" ] \
	|| fail "--version reported '$first_line', expected 'cynative $SMOKE_VERSION'"

printf 'archive.smoke: OK (%s extracts, cynative %s runs)\n' "$archive_name" "$SMOKE_VERSION" >&2
