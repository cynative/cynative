#!/bin/sh
# render-formula.unit.test.sh - offline unit tests for the Homebrew Formula
# renderer (scripts/release/render-formula.sh), the Homebrew twin of
# test/render-scoop.unit.test.sh.
#
# Hermetic: no network, no brew, no credentials. Exercises the pure renderer's
# output shape, fail-closed version/hash validation, and byte-for-byte golden
# parity. Run by `make sh-test`.
set -eu

here=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
root=$(CDPATH='' cd -- "$here/.." && pwd)
render="$root/scripts/release/render-formula.sh"

fails=0
pass() { printf 'ok: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; fails=$((fails + 1)); }

sha_a=5c712baad9179d576da1f8cff632b840b4b03495fd565a79fea8fe1a2b8b6be1
sha_b=1321513cd9c9a8bd117c0ec1986845daf9face1ccdc35441b2b1910e50ce7be8
sha_c=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
sha_d=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
desc='Agentic security research across your code, cloud, and runtime (read-only)'

# ---- happy path: required fields and four arch urls/hashes ------------------
if (
	out=$("$render" 1.5.1 "$sha_a" "$sha_b" "$sha_c" "$sha_d") || exit 1
	printf '%s' "$out" | grep -q 'class Cynative < Formula' || exit 1
	printf '%s' "$out" | grep -Fq "desc \"$desc\"" || exit 1
	printf '%s' "$out" | grep -Fq 'homepage "https://github.com/cynative/cynative"' || exit 1
	printf '%s' "$out" | grep -Fq 'license "Apache-2.0"' || exit 1
	printf '%s' "$out" | grep -Fq 'depends_on macos: :monterey' || exit 1
	printf '%s' "$out" | grep -Fq 'cynative_Darwin_arm64.tar.gz' || exit 1
	printf '%s' "$out" | grep -Fq 'cynative_Darwin_x86_64.tar.gz' || exit 1
	printf '%s' "$out" | grep -Fq 'cynative_Linux_arm64.tar.gz' || exit 1
	printf '%s' "$out" | grep -Fq 'cynative_Linux_x86_64.tar.gz' || exit 1
	printf '%s' "$out" | grep -Fq "sha256 \"$sha_a\"" || exit 1
	printf '%s' "$out" | grep -Fq "sha256 \"$sha_b\"" || exit 1
	printf '%s' "$out" | grep -Fq "sha256 \"$sha_c\"" || exit 1
	printf '%s' "$out" | grep -Fq "sha256 \"$sha_d\"" || exit 1
	printf '%s' "$out" | grep -Fq 'bin.install "cynative"' || exit 1
	exit 0
); then pass "render-formula renders arches/urls/hashes/meta and the :monterey floor"; else fail "render-formula happy path"; fi

# ---- no version stanza; the tag in every url is the sole version source ------
# `brew audit --strict` rejects a `version` that restates what it scans from the
# URL (Homebrew/brew#23336 made it scan the release tag rather than misreading
# `x86_64`), so re-adding the stanza breaks the release gate. All four urls must
# carry the literal tag: brew evaluates each arch block only on its own
# platform, and a Ruby-interpolated `v#{version}` would resolve to nothing once
# the stanza is gone.
if (
	out=$("$render" 1.5.1 "$sha_a" "$sha_b" "$sha_c" "$sha_d") || exit 1
	! printf '%s' "$out" | grep -Eq '^[[:space:]]*version ' || exit 1
	! printf '%s' "$out" | grep -Fq '#{version}' || exit 1
	[ "$(printf '%s\n' "$out" | grep -Fc '/releases/download/v1.5.1/')" -eq 4 ] || exit 1
	exit 0
); then pass "render-formula omits the version stanza and pins the tag in all four urls"; else fail "render-formula version sourcing"; fi

# ---- byte-for-byte golden ----------------------------------------------------
golden="$here/testdata/homebrew-cynative.golden.rb"
if "$render" 1.5.1 "$sha_a" "$sha_b" "$sha_c" "$sha_d" | diff -u "$golden" - >/dev/null 2>&1; then
	pass "render-formula output matches the frozen golden byte-for-byte"
else
	"$render" 1.5.1 "$sha_a" "$sha_b" "$sha_c" "$sha_d" | diff -u "$golden" - >&2 || true
	fail "render-formula golden byte parity (regenerate test/testdata/homebrew-cynative.golden.rb if intentional)"
fi

# ---- fail-closed on malformed hash / empty / unsafe version ------------------
if "$render" 1.5.1 not-a-hash "$sha_b" "$sha_c" "$sha_d" >/dev/null 2>&1; then
	fail "render-formula malformed hash should fail"
else
	pass "render-formula fails on a malformed hash"
fi

if "$render" "" "$sha_a" "$sha_b" "$sha_c" "$sha_d" >/dev/null 2>&1; then
	fail "render-formula empty version should fail"
else
	pass "render-formula fails on an empty version"
fi

# Unquoted heredoc would otherwise expand shell metacharacters in version.
# shellcheck disable=SC2016 # fixture must keep $(...) literal; do not expand here.
if "$render" '1.0$(echo pwned)' "$sha_a" "$sha_b" "$sha_c" "$sha_d" >/dev/null 2>&1; then
	fail "render-formula shell-metachar version should fail"
else
	pass "render-formula fails on a shell-metachar version"
fi

if [ "$fails" -ne 0 ]; then
	printf 'render-formula.unit: %d case(s) FAILED\n' "$fails" >&2
	exit 1
fi
printf 'render-formula.unit: OK\n' >&2
