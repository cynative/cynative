#!/bin/sh
# render-scoop.unit.test.sh - offline unit tests for the Scoop manifest renderer
# (scripts/release/render-scoop.sh) and the strict checksums lookup
# (scripts/release/assets-lib.sh: sha_for_checksums), cynative#103.
#
# Hermetic: no network, no credentials, no bucket clone. Exercises the pure
# renderer's output shape and its fail-closed hash validation, plus the
# duplicate/missing/malformed handling of the checksums parser the post-publish
# push derives its two Windows-zip hashes from. Run by `make sh-test`.
set -eu

here=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
root=$(CDPATH='' cd -- "$here/.." && pwd)
render="$root/scripts/release/render-scoop.sh"
lib="$root/scripts/release/assets-lib.sh"

command -v jq >/dev/null 2>&1 || { printf 'FAIL: jq not found (required by render-scoop.sh)\n' >&2; exit 1; }

fails=0
pass() { printf 'ok: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; fails=$((fails + 1)); }

sha_a=5c712baad9179d576da1f8cff632b840b4b03495fd565a79fea8fe1a2b8b6be1
sha_b=1321513cd9c9a8bd117c0ec1986845daf9face1ccdc35441b2b1910e50ce7be8
desc='Agentic security research across your code, cloud, and runtime (read-only)'

# ---- render-scoop.sh: happy path renders every required field ----------------
if (
	out=$("$render" 1.5.1 "$sha_a" "$sha_b") || exit 1
	printf '%s' "$out" | jq -e . >/dev/null || exit 1                                   # valid JSON
	[ "$(printf '%s' "$out" | jq -r '.version')" = "1.5.1" ] || exit 1                  # nonempty exact version
	[ "$(printf '%s' "$out" | jq -r '.architecture | keys | sort | join(",")')" = "64bit,arm64" ] || exit 1  # exactly the two arches
	[ "$(printf '%s' "$out" | jq -r '.architecture."64bit".url')" = "https://github.com/cynative/cynative/releases/download/v1.5.1/cynative_Windows_x86_64.zip" ] || exit 1
	[ "$(printf '%s' "$out" | jq -r '.architecture."arm64".url')" = "https://github.com/cynative/cynative/releases/download/v1.5.1/cynative_Windows_arm64.zip" ] || exit 1
	[ "$(printf '%s' "$out" | jq -r '.architecture."64bit".hash')" = "$sha_a" ] || exit 1
	[ "$(printf '%s' "$out" | jq -r '.architecture."arm64".hash')" = "$sha_b" ] || exit 1
	[ "$(printf '%s' "$out" | jq -r '.architecture."64bit".bin | join(",")')" = "cynative.exe" ] || exit 1
	[ "$(printf '%s' "$out" | jq -r '.architecture."arm64".bin | join(",")')" = "cynative.exe" ] || exit 1
	[ "$(printf '%s' "$out" | jq -r '.homepage')" = "https://github.com/cynative/cynative" ] || exit 1
	[ "$(printf '%s' "$out" | jq -r '.license')" = "Apache-2.0" ] || exit 1
	[ "$(printf '%s' "$out" | jq -r '.description')" = "$desc" ] || exit 1
	# No checkver/autoupdate blocks.
	[ "$(printf '%s' "$out" | jq -r 'has("checkver"), has("autoupdate") | select(. == true)')" = "" ] || exit 1
	# No em dash anywhere in the rendered manifest.
	printf '%s' "$out" | grep -q '—' && exit 1
	exit 0
); then pass "render-scoop renders version/arches/urls/bin/hash/meta, no checkver/autoupdate, no em dash"; else fail "render-scoop happy path"; fi

# ---- render-scoop.sh: fail-closed on a malformed hash ------------------------
if "$render" 1.5.1 not-a-hash "$sha_b" >/dev/null 2>&1; then fail "render-scoop malformed hash should fail"; else pass "render-scoop fails on a malformed hash"; fi

# ---- render-scoop.sh: fail-closed on an empty version ------------------------
if "$render" "" "$sha_a" "$sha_b" >/dev/null 2>&1; then fail "render-scoop empty version should fail"; else pass "render-scoop fails on an empty version"; fi

# ---- sha_for_checksums: exactly-one, malformed, missing, duplicate ----------
# Bash function (uses [[ =~ ]]); exercise it through a bash subprocess so this
# POSIX-sh harness stays dialect-clean.
checkfn() { bash -c '. "$1"; sha_for_checksums "$2" "$3"' _ "$lib" "$1" "$2"; }

if (
	td=$(mktemp -d)
	trap 'rm -rf "$td"' EXIT
	{
		printf '%s  cynative_Darwin_arm64.tar.gz\n' aaaa
		printf '%s  cynative_Windows_x86_64.zip\n' "$sha_a"
		printf '%s  cynative_Windows_arm64.zip\n' "$sha_b"
	} > "$td/checksums.txt"
	[ "$(checkfn "$td/checksums.txt" cynative_Windows_x86_64.zip)" = "$sha_a" ] || exit 1  # exactly one -> value
	[ "$(checkfn "$td/checksums.txt" cynative_Windows_arm64.zip)" = "$sha_b" ] || exit 1
	if checkfn "$td/checksums.txt" cynative_Windows_386.zip >/dev/null 2>&1; then exit 1; fi   # missing -> fail
	if checkfn "$td/checksums.txt" cynative_Darwin_arm64.tar.gz >/dev/null 2>&1; then exit 1; fi # malformed (aaaa) -> fail
	# Append a duplicate arm64 row -> fail.
	printf '%s  cynative_Windows_arm64.zip\n' "$sha_b" >> "$td/checksums.txt"
	if checkfn "$td/checksums.txt" cynative_Windows_arm64.zip >/dev/null 2>&1; then exit 1; fi   # duplicate -> fail
	exit 0
); then pass "sha_for_checksums returns the unique digest, fails on missing/malformed/duplicate"; else fail "sha_for_checksums"; fi

if [ "$fails" -ne 0 ]; then
	printf 'render-scoop.unit: %d case(s) FAILED\n' "$fails" >&2
	exit 1
fi
printf 'render-scoop.unit: OK\n' >&2
