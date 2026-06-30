#!/usr/bin/env bash
# GoReleaser post-build hook: sign a darwin Mach-O with Developer ID Application.
# Usage: sign-darwin-binary.sh <binary-path> <target e.g. darwin_arm64>
set -euo pipefail

binary="$1"; target="${2:-}"
case "${target}" in
  darwin_*) ;;
  *) exit 0 ;;   # non-darwin target: nothing to sign
esac

: "${MACOS_SIGN_P12_FILE:?MACOS_SIGN_P12_FILE unset}"
: "${MACOS_SIGN_PASSWORD_FILE:?MACOS_SIGN_PASSWORD_FILE unset}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
entitlements="$(cd "${here}/../.." && pwd)/.goreleaser/entitlements.plist"

# Guard: must be a Developer ID Application certificate.
# Capture output via substitution to insulate from rcodesign's non-zero exit on success.
cert_info="$(rcodesign analyze-certificate \
  --p12-file "${MACOS_SIGN_P12_FILE}" --p12-password-file "${MACOS_SIGN_PASSWORD_FILE}" 2>/dev/null || true)"
grep -qi "Developer ID Application" <<<"${cert_info}" \
  || { echo "::error::expected a Developer ID Application certificate" >&2; exit 1; }

tmp="${binary}.signed"
n=0
until rcodesign sign \
      --p12-file "${MACOS_SIGN_P12_FILE}" --p12-password-file "${MACOS_SIGN_PASSWORD_FILE}" \
      --entitlements-xml-file "${entitlements}" \
      --code-signature-flags runtime --for-notarization \
      "${binary}" "${tmp}"; do
  n=$((n+1)); [ "${n}" -ge 3 ] && { echo "::error::rcodesign sign failed after ${n} attempts" >&2; exit 1; }
  echo "rcodesign sign retry ${n}…" >&2; sleep 5
done

# Verify hardened runtime + both JIT entitlements BEFORE replacing the original.
info="$(rcodesign print-signature-info "${tmp}" 2>/dev/null || true)"
grep -qi 'runtime'                          <<<"${info}" || { echo "::error::hardened runtime flag missing" >&2; exit 1; }
grep -q  'allow-unsigned-executable-memory' <<<"${info}" || { echo "::error::allow-unsigned-executable-memory missing" >&2; exit 1; }
grep -q  'allow-jit'                        <<<"${info}" || { echo "::error::allow-jit missing" >&2; exit 1; }

mv -f "${tmp}" "${binary}"
echo "signed ${binary} (${target})"
