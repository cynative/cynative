#!/bin/sh
# Real-artifact install e2e for release confidence (issue #41).
# Serves a goreleaser-built Linux archive from a loopback fixture server, runs the
# real install.sh, verifies `cynative --version`, uninstalls, and proves a checksum
# failure is fail-closed. Hermetic: no public releases, Homebrew, Scoop, LLM, or
# cloud access (CYNATIVE_VERSION is pinned and gh is stubbed to keep attestation
# offline; the server is loopback-only).
# Usage: test/install.e2e.test.sh [DIST_DIR]   (default: <repo>/dist)
set -eu

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
installer="$root/install.sh"
dist=${1:-"$root/dist"}

server_pid=''
workdir=''
cleanup() {
  [ -z "${server_pid:-}" ] || kill "$server_pid" 2>/dev/null || true
  [ -z "${workdir:-}" ] || rm -rf "$workdir"
}
trap cleanup EXIT INT TERM

command -v python3 >/dev/null 2>&1 || { printf 'FAIL: python3 not found (fixture server)\n' >&2; exit 1; }

case "$(uname -s)" in
  Linux) os=Linux ;;
  Darwin) os=Darwin ;;
  *) printf 'skip: unsupported OS %s\n' "$(uname -s)" >&2; exit 0 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=x86_64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) printf 'skip: unsupported arch %s\n' "$(uname -m)" >&2; exit 0 ;;
esac
archive="cynative_${os}_${arch}.tar.gz"

[ -f "$dist/$archive" ] || { printf 'FAIL: %s not found (run goreleaser snapshot first)\n' "$dist/$archive" >&2; exit 1; }
[ -f "$dist/checksums.txt" ] || { printf 'FAIL: %s/checksums.txt not found\n' "$dist" >&2; exit 1; }
[ -f "$dist/metadata.json" ] || { printf 'FAIL: %s/metadata.json not found\n' "$dist" >&2; exit 1; }

# Expected `cynative --version` string: the version goreleaser stamped, v-normalized.
want=$(python3 -c 'import json,sys; v=json.load(open(sys.argv[1]))["version"]; print(v[1:] if v.startswith("v") else v)' "$dist/metadata.json")
[ -n "$want" ] || { printf 'FAIL: could not read version from metadata.json\n' >&2; exit 1; }

workdir=$(mktemp -d)
srv="$workdir/srv"; bin="$workdir/bin"; bad="$workdir/bad"; stub="$workdir/stub"
mkdir -p "$srv" "$bin" "$bad" "$stub"

# Serve a COPY of dist so the checksum-failure phase can tamper without touching dist.
cp "$dist/$archive" "$dist/checksums.txt" "$srv/"

# Offline attestation: a gh stub whose verify-asset always fails (keeps gh offline).
printf '#!/bin/sh\nexit 1\n' > "$stub/gh"
chmod +x "$stub/gh"

portfile="$workdir/port"
python3 "$root/test/serve-fixture.py" "$srv" "$portfile" &
server_pid=$!

i=0
while [ ! -s "$portfile" ]; do
  i=$((i + 1))
  [ "$i" -lt 100 ] || { printf 'FAIL: fixture server did not start\n' >&2; exit 1; }
  sleep 0.1
done
base="http://127.0.0.1:$(cat "$portfile")"

run_install() { # install_dir : run the real installer against the loopback base
  CYNATIVE_BASE_URL="$base" \
  CYNATIVE_VERSION="v0.0.0-e2e" \
  CYNATIVE_REQUIRE_ATTESTATION=0 \
  CYNATIVE_INSTALL_DIR="$1" \
  PATH="$stub:$PATH" \
    sh "$installer"
}

printf '== INSTALL ==\n' >&2
run_install "$bin"
[ -x "$bin/cynative" ] || { printf 'FAIL: binary not installed\n' >&2; exit 1; }

printf '== VERSION ==\n' >&2
got=$("$bin/cynative" --version | head -n1)
case "$got" in
  "cynative $want") : ;;
  *) printf 'FAIL: version mismatch: want "cynative %s" got "%s"\n' "$want" "$got" >&2; exit 1 ;;
esac

printf '== UNINSTALL ==\n' >&2
CYNATIVE_INSTALL_DIR="$bin" sh "$installer" --uninstall
[ ! -e "$bin/cynative" ] || { printf 'FAIL: uninstall left the binary in place\n' >&2; exit 1; }

printf '== CHECKSUM-FAILURE ==\n' >&2
# Tamper the served archive so its sha no longer matches the unchanged checksums.txt.
printf 'tamper' >> "$srv/$archive"
set +e
out=$(run_install "$bad" 2>&1); rc=$?
set -e
[ "$rc" -ne 0 ] || { printf 'FAIL: tampered archive did not fail install\n' >&2; exit 1; }
case "$out" in
  *"checksum mismatch"*) : ;;
  *) printf 'FAIL: expected "checksum mismatch", got: %s\n' "$out" >&2; exit 1 ;;
esac
[ ! -e "$bad/cynative" ] || { printf 'FAIL: tampered install wrote a binary\n' >&2; exit 1; }

printf 'install.e2e: OK (install + version %s + uninstall + checksum-failure)\n' "$want" >&2
