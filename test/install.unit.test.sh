#!/bin/sh
# Unit tests for the install.sh URL-safety seam. Sources install.sh via the
# CYNATIVE_TEST_SOURCE guard (no install runs, no network) and checks the pure
# helpers. Mirrors the Pester Test-CynUrlAllowed / Resolve-CynBaseUrl blocks and
# adds the IPv6 / 127.0.0.0/8 / spoof cases the POSIX parser must prove itself.
set -u

CYNATIVE_TEST_SOURCE=1
export CYNATIVE_TEST_SOURCE
# shellcheck disable=SC1091  # install.sh is sourced at runtime via a $0-relative path.
. "$(dirname "$0")/../install.sh"

pass=0
fail=0
allow() { # label url : url_allowed should accept.
  if url_allowed "$2"; then pass=$((pass + 1))
  else fail=$((fail + 1)); printf 'FAIL expected-allow: %s (%s)\n' "$1" "$2" >&2; fi
}
reject() { # label url : url_allowed should refuse.
  if url_allowed "$2"; then fail=$((fail + 1)); printf 'FAIL expected-reject: %s (%s)\n' "$1" "$2" >&2
  else pass=$((pass + 1)); fi
}
eq() { # label want got.
  if [ "$2" = "$3" ]; then pass=$((pass + 1))
  else fail=$((fail + 1)); printf 'FAIL %s:\n  want: %s\n  got:  %s\n' "$1" "$2" "$3" >&2; fi
}

allow 'https public'          'https://example.com/x'
allow 'https bare host'       'https://mirror.example'
allow 'http 127.0.0.1:port'   'http://127.0.0.1:8000/x'
allow 'http localhost'        'http://localhost:8000/x'
allow 'http [::1]:port'       'http://[::1]:8000/x'
allow 'http [::1]'            'http://[::1]'
allow 'http 127.5.6.7'        'http://127.5.6.7'
allow 'http 127.255.255.255'  'http://127.255.255.255'

reject 'http public'          'http://evil.example/x'
reject 'http 127-spoof'       'http://127.0.0.1.evil.com'
reject 'http localhost-spoof' 'http://localhost.evil.com'
reject 'http octet over 255'  'http://127.256.0.1'
reject 'http leading zero'    'http://0127.0.0.1'
reject 'http [::1]evil'       'http://[::1]evil.com'
reject 'http [::1 unclosed'   'http://[::1'
reject 'ftp'                  'ftp://example.com/x'
reject 'file'                 'file:///tmp/x'
reject 'no scheme'            'not-a-url'

eq 'default base url' \
  'https://github.com/cynative/cynative/releases/download/v1.0.0' \
  "$(resolve_base_url '' 'cynative/cynative' 'v1.0.0')"
eq 'https override trims one slash' \
  'https://mirror.example/dl' "$(resolve_base_url 'https://mirror.example/dl/' 'r' 'v')"
eq 'https override trims all slashes' \
  'https://mirror.example/dl' "$(resolve_base_url 'https://mirror.example/dl///' 'r' 'v')"
eq 'loopback http override kept' \
  'http://127.0.0.1:8000' "$(resolve_base_url 'http://127.0.0.1:8000' 'r' 'v')"

# Reject override: err prints the cynative-install: message and exits; run in a
# subshell so its exit does not kill the harness, and capture stderr.
msg=$(resolve_base_url 'http://evil.example' 'r' 'v' 2>&1 >/dev/null)
rc=$?
if [ "$rc" -ne 0 ]; then pass=$((pass + 1))
else fail=$((fail + 1)); printf 'FAIL reject should exit non-zero\n' >&2; fi
case "$msg" in
  *cynative-install:*"must be https"*) pass=$((pass + 1)) ;;
  *) fail=$((fail + 1)); printf 'FAIL reject message shape: %s\n' "$msg" >&2 ;;
esac

printf 'install.unit: %d passed, %d failed\n' "$pass" "$fail" >&2
[ "$fail" -eq 0 ]
