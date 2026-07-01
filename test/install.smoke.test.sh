#!/bin/sh
# End-to-end smoke: run the real install.sh against a loopback fixture server.
# Proves both issue #40 clauses - install from http://127.0.0.1, and reject a
# non-loopback http override. Hermetic (no network): CYNATIVE_VERSION is pinned,
# the server is loopback-only, and a gh stub keeps attestation offline.
set -eu

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
installer="$root/install.sh"

server_pid=''
workdir=''
cleanup() {
  [ -z "${server_pid:-}" ] || kill "$server_pid" 2>/dev/null || true
  [ -z "${workdir:-}" ] || rm -rf "$workdir"
}
trap cleanup EXIT INT TERM

command -v python3 >/dev/null 2>&1 || { printf 'FAIL: python3 not found (fixture server)\n' >&2; exit 1; }

workdir=$(mktemp -d)
srv="$workdir/srv"
bin="$workdir/bin"
stub="$workdir/stub"
mkdir -p "$srv" "$bin" "$stub"

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

marker='fake-cynative-ok'
cat > "$srv/cynative" <<EOF
#!/bin/sh
echo $marker
EOF
chmod +x "$srv/cynative"
( cd "$srv" && tar -czf "$archive" cynative && rm -f cynative )
( cd "$srv" && { sha256sum "$archive" 2>/dev/null || shasum -a 256 "$archive"; } > checksums.txt )

cat > "$stub/gh" <<'EOF'
#!/bin/sh
exit 1
EOF
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
port=$(cat "$portfile")

# Accept path: the real installer against a loopback http base.
CYNATIVE_BASE_URL="http://127.0.0.1:$port" \
CYNATIVE_VERSION="v0.0.0-test" \
CYNATIVE_REQUIRE_ATTESTATION=0 \
CYNATIVE_INSTALL_DIR="$bin" \
PATH="$stub:$PATH" \
  sh "$installer"

[ -x "$bin/cynative" ] || { printf 'FAIL: binary not installed\n' >&2; exit 1; }
out=$("$bin/cynative")
[ "$out" = "$marker" ] || { printf 'FAIL: installed binary marker mismatch: %s\n' "$out" >&2; exit 1; }

# Reject path: a non-loopback http override must fail closed before any download.
set +e
reject=$(CYNATIVE_BASE_URL="http://evil.example" CYNATIVE_VERSION="v0.0.0-test" sh "$installer" 2>&1)
rc=$?
set -e
[ "$rc" -ne 0 ] || { printf 'FAIL: non-loopback http override was not rejected\n' >&2; exit 1; }
case "$reject" in
  *cynative-install:*"must be https"*) : ;;
  *) printf 'FAIL: reject message shape: %s\n' "$reject" >&2; exit 1 ;;
esac

printf 'install.smoke: OK (accept http://127.0.0.1 + reject non-loopback http)\n' >&2
