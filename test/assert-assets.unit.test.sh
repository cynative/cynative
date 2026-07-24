#!/bin/sh
# assert-assets.unit.test.sh - offline unit tests for the release asset-set
# assertion script (scripts/release/assert-assets.sh), cynative#155 item 3.
#
# Hermetic: no network, no credentials, no real gh CLI. Stubs `gh` on PATH to
# serve a fixed release-assets listing, exercising the branch where the GitHub
# API reports a null/empty digest for an asset: the script must fail closed
# (nonzero exit, an ::error line) rather than falling back to downloading the
# asset body and hashing it locally. Run by `make sh-test`.
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

	[ "$rc" -ne 0 ] || exit 1
	[ ! -s "$download_marker" ] || exit 1
	exit 0
); then pass "assert-assets fails closed on an empty-string digest, never downloads the asset"; else fail "empty digest fail-closed"; fi

[ "$fails" -eq 0 ] || { printf '%d failure(s)\n' "$fails" >&2; exit 1; }
printf 'OK: assert-assets unit tests\n'
