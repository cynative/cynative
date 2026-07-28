#!/bin/sh
# assert-assets.unit.test.sh - offline unit tests for the release asset-set
# assertion script (scripts/release/assert-assets.sh), cynative#155 item 3 and #180.
#
# Hermetic: no network, no credentials, no real gh CLI. Two halves:
#   assert mode - stubs `gh` on PATH to serve a fixed release-assets listing,
#   exercising the branch where the GitHub API reports a null/empty digest for an
#   asset: the script must fail closed (nonzero exit, an ::error line) rather than
#   falling back to downloading the asset body and hashing it locally.
#   generate mode - drives a synthetic dist/artifacts.json and pins the artifact-type
#   allowlist (Archive, Checksum, Signature; never Binary or Certificate), the
#   LC_ALL=C row ordering, the frozen digests, and the missing-path abort.
# Run by `make sh-test`.
set -eu

here=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
root=$(CDPATH='' cd -- "$here/.." && pwd)
assert="$root/scripts/release/assert-assets.sh"

command -v jq >/dev/null 2>&1 || { printf 'FAIL: jq not found (required by assert-assets.sh)\n' >&2; exit 1; }

fails=0
pass() { printf 'ok: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; fails=$((fails + 1)); }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

stub_bin="$tmp/bin"
mkdir -p "$stub_bin"

# Fake gh: serves a fixed release-assets listing over `gh api --paginate ...`
# and records whether the raw asset-download endpoint
# (releases/assets/<id>) is ever invoked, without touching the network.
cat > "$stub_bin/gh" <<'EOF'
#!/bin/sh
set -eu

marker="${GH_STUB_DOWNLOAD_MARKER:?}"
fixture="${GH_STUB_ASSETS_FIXTURE:?}"

if [ "$1" = "api" ]; then
	shift
	if [ "$1" = "--paginate" ]; then
		shift
		case "$1" in
			repos/*/releases/*/assets\?per_page=100)
				cat "$fixture"
				exit 0
				;;
		esac
	fi
	case "$1" in
		repos/*/releases/assets/*)
			echo called >> "$marker"
			printf 'fake-asset-body'
			exit 0
			;;
	esac
fi

echo "fake gh: unhandled invocation: $*" >&2
exit 1
EOF
chmod +x "$stub_bin/gh"

# ---- null digest from the API: fail closed, never download the asset --------
if (
	download_marker="$tmp/download-called"
	: > "$download_marker"
	fixture="$tmp/assets.json"
	printf '[{"id":9001,"name":"cynative_Linux_x86_64.tar.gz","digest":null}]\n' > "$fixture"
	manifest="$tmp/manifest.tsv"
	printf 'cynative_Linux_x86_64.tar.gz\tdeadbeef\tdist/cynative_Linux_x86_64.tar.gz\n' > "$manifest"

	rc=0
	PATH="$stub_bin:$PATH" \
		GH_STUB_DOWNLOAD_MARKER="$download_marker" \
		GH_STUB_ASSETS_FIXTURE="$fixture" \
		GH_TOKEN=fake-token \
		"$assert" cynative/cynative 999 "$manifest" >"$tmp/out.log" 2>"$tmp/err.log" || rc=$?

	[ "$rc" -ne 0 ] || exit 1                          # must fail closed, not exit 0
	[ ! -s "$download_marker" ] || exit 1              # must never hit the download endpoint
	grep -q 'no API digest' "$tmp/err.log" || exit 1   # explicit ::error, not a silent failure
	exit 0
); then pass "assert-assets fails closed on a null digest, never downloads the asset"; else fail "null digest fail-closed"; fi

# ---- empty-string digest from the API: same fail-closed path -----------------
if (
	download_marker="$tmp/download-called-empty"
	: > "$download_marker"
	fixture="$tmp/assets-empty.json"
	printf '[{"id":9002,"name":"cynative_Darwin_arm64.tar.gz","digest":""}]\n' > "$fixture"
	manifest="$tmp/manifest-empty.tsv"
	printf 'cynative_Darwin_arm64.tar.gz\tdeadbeef\tdist/cynative_Darwin_arm64.tar.gz\n' > "$manifest"

	rc=0
	PATH="$stub_bin:$PATH" \
		GH_STUB_DOWNLOAD_MARKER="$download_marker" \
		GH_STUB_ASSETS_FIXTURE="$fixture" \
		GH_TOKEN=fake-token \
		"$assert" cynative/cynative 999 "$manifest" >"$tmp/out2.log" 2>"$tmp/err2.log" || rc=$?

	[ "$rc" -ne 0 ] || exit 1                          # must fail closed, not exit 0
	[ ! -s "$download_marker" ] || exit 1              # must never hit the download endpoint
	grep -q 'no API digest' "$tmp/err2.log" || exit 1  # explicit ::error, not a silent failure
	exit 0
); then pass "assert-assets fails closed on an empty-string digest, never downloads the asset"; else fail "empty digest fail-closed"; fi

# ---- generate: exactly the release-uploadable types, sorted, with real digests ----
# One deliberately scrambled fixture proves four things at once: the two long-standing
# inclusions (Archive, Checksum), the signature bundle (Signature), and both intentional
# exclusions (Binary is not a release asset; Certificate is excluded so that adding a
# `certificate:` field to .goreleaser.yaml's signs block fails the release closed on a
# surplus asset instead of publishing an unasserted one). Digests are frozen: the
# fixture files hold fixed content whose sha256 is hardcoded below, so a change to how
# the digest is computed fails rather than silently agreeing with itself.
if (
	fix="$tmp/fix"
	mkdir -p "$fix"
	printf '%s' alpha   > "$fix/darwin"
	printf '%s' bravo   > "$fix/linux"
	printf '%s' charlie > "$fix/sums"
	printf '%s' delta   > "$fix/sig"
	printf '%s' alpha   > "$fix/bin"
	printf '%s' alpha   > "$fix/cert"

	cat > "$fix/artifacts.json" <<JSON
[{"name":"cynative_Linux_x86_64.tar.gz","path":"$fix/linux","type":"Archive"},
 {"name":"cynative","path":"$fix/bin","type":"Binary"},
 {"name":"checksums.txt.sigstore.json","path":"$fix/sig","type":"Signature"},
 {"name":"checksums.txt","path":"$fix/sums","type":"Checksum"},
 {"name":"checksums.txt.pem","path":"$fix/cert","type":"Certificate"},
 {"name":"cynative_Darwin_arm64.tar.gz","path":"$fix/darwin","type":"Archive"}]
JSON

	cat > "$fix/expected.tsv" <<TSV
checksums.txt	b9dd960c1753459a78115d3cb845a57d924b6877e805b08bd01086ccdf34433c	$fix/sums
checksums.txt.sigstore.json	4f4a9410ffcdf895c4adb880659e9b5c0dd1f23a30790684340b3eaacb045398	$fix/sig
cynative_Darwin_arm64.tar.gz	8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8	$fix/darwin
cynative_Linux_x86_64.tar.gz	f144a6907dc4284d1f9fe6a7d9b9ff53c02c1d07ba68f24d413d7ff7f757a782	$fix/linux
TSV

	"$assert" generate "$fix" > "$fix/actual.tsv" 2>"$fix/err.log" || exit 1
	diff "$fix/expected.tsv" "$fix/actual.tsv" >&2 || exit 1
	exit 0
); then pass "assert-assets generate emits exactly Archive+Checksum+Signature, sorted, with correct digests"; else fail "generate golden fixture"; fi

# ---- generate: a missing artifact path aborts instead of emitting an empty digest ---
# The script uses a bare `digest=$(sha256sum ...)` assignment precisely so a failure
# aborts under `set -euo pipefail`. Rows already flushed to the sort stay on stdout, so
# assert the exit status and the absence of an empty-digest row, never empty output.
if (
	miss="$tmp/miss"
	mkdir -p "$miss"
	printf '%s' alpha > "$miss/present"
	cat > "$miss/artifacts.json" <<JSON
[{"name":"a_present.tar.gz","path":"$miss/present","type":"Archive"},
 {"name":"b_gone.txt","path":"$miss/does-not-exist","type":"Checksum"}]
JSON

	rc=0
	"$assert" generate "$miss" > "$miss/out.tsv" 2>"$miss/err.log" || rc=$?
	[ "$rc" -ne 0 ] || exit 1                        # must fail closed
	# Never an empty digest column. awk with a tab FS, not a grep pattern: grep does
	# not interpret \t, so a '\t\t' pattern would match a literal backslash-t instead.
	awk -F'\t' '$2 == "" { bad = 1 } END { exit bad ? 1 : 0 }' "$miss/out.tsv" || exit 1
	! grep -q 'b_gone.txt' "$miss/out.tsv" || exit 1 # the bad artifact is never emitted
	exit 0
); then pass "assert-assets generate fails closed on a missing artifact path"; else fail "generate missing-path fail-closed"; fi

[ "$fails" -eq 0 ] || { printf '%d failure(s)\n' "$fails" >&2; exit 1; }
printf 'OK: assert-assets unit tests\n'
