#!/usr/bin/env bash
# Sign (Developer ID Installer) + notarize + staple a flat .pkg. Linux-only, headless.
# Usage: sign-notarize-pkg.sh <pkg-path>
set -euo pipefail

pkg="$1"
: "${MACOS_INSTALLER_P12_FILE:?MACOS_INSTALLER_P12_FILE unset}"
: "${MACOS_INSTALLER_PASSWORD_FILE:?MACOS_INSTALLER_PASSWORD_FILE unset}"
: "${MACOS_NOTARY_API_KEY_JSON:?MACOS_NOTARY_API_KEY_JSON unset}"

# Guard: must be a Developer ID Installer certificate.
# Capture output via substitution to insulate from rcodesign's non-zero exit on success.
cert_info="$(rcodesign analyze-certificate \
  --p12-file "${MACOS_INSTALLER_P12_FILE}" --p12-password-file "${MACOS_INSTALLER_PASSWORD_FILE}" 2>/dev/null || true)"
grep -qi "Developer ID Installer" <<<"${cert_info}" \
  || { echo "::error::expected a Developer ID Installer certificate" >&2; exit 1; }

retry() { local n=0; until "$@"; do n=$((n+1)); [ "${n}" -ge 3 ] && return 1; echo "retry ${n}: $*" >&2; sleep 10; done; }

retry rcodesign sign \
  --p12-file "${MACOS_INSTALLER_P12_FILE}" --p12-password-file "${MACOS_INSTALLER_PASSWORD_FILE}" \
  "${pkg}" || { echo "::error::pkg installer-signing failed" >&2; exit 1; }

retry rcodesign notary-submit --api-key-file "${MACOS_NOTARY_API_KEY_JSON}" --staple "${pkg}" \
  || { echo "::error::pkg notarization/stapling failed" >&2; exit 1; }

echo "signed+notarized+stapled ${pkg}"
