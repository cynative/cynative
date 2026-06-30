#!/usr/bin/env bash
# Assert a built .pkg is well-formed, signed, stapled, root:wheel, and its payload
# binary matches the reference dist binary. Fail-closed.
# Usage: assert-pkg.sh <pkg-path> <reference-binary>
set -euo pipefail

pkg="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; ref="$2"
work="$(mktemp -d)"; trap 'rm -rf "${work}"' EXIT

# 1. Structure (grep -F: TOC entries contain regex metachars).
toc="$(xar -tf "${pkg}")"
for e in Distribution base.pkg/PackageInfo base.pkg/Payload base.pkg/Bom; do
  grep -Fqx -- "${e}" <<<"${toc}" || { echo "::error::pkg missing ${e}" >&2; exit 1; }
done

# 2. Signature + stapled ticket (fail-closed — Codex M4).
# NOTE: `rcodesign verify` only works on Mach-O binaries and errors on XAR/pkg files.
# Use `print-signature-info` instead and assert the three cryptographic verifies that confirm
# the Developer ID Installer signature is intact (TOC checksum, RSA sig, CMS sig+chain).
pkg_sig="$(rcodesign print-signature-info "${pkg}" 2>/dev/null || true)"
grep -q 'checksum_verifies: true'       <<<"${pkg_sig}" || { echo "::error::pkg TOC checksum verification failed" >&2; exit 1; }
grep -q 'rsa_signature_verifies: true'  <<<"${pkg_sig}" || { echo "::error::pkg RSA signature verification failed" >&2; exit 1; }
grep -q 'cms_signature_verifies: true'  <<<"${pkg_sig}" || { echo "::error::pkg CMS signature verification failed" >&2; exit 1; }
grep -q 'chains_to_apple_root_ca: true' <<<"${pkg_sig}" || { echo "::error::pkg cert does not chain to Apple root CA" >&2; exit 1; }
# NOTE: `print-signature-info` does NOT surface the staple — it only reads the XAR TOC signature.
# rcodesign staples by appending a `t8lr`-magic notarization-ticket trailer to the .pkg (verified
# against a real Apple-accepted+stapled pkg). Detect that trailer directly (fail-closed).
# rcodesign appends a fixed ~1706-byte notarization-ticket trailer starting with the `t8lr`
# magic at the very end of the .pkg (validated: magic at EOF-1706 across real stapled pkgs).
# Anchor to the tail so a coincidental `t8lr` elsewhere in the payload can't false-pass.
tail -c 4096 "${pkg}" | grep -Pqa '\x74\x38\x6c\x72' \
  || { echo "::error::pkg missing stapled notarization ticket (no t8lr trailer)" >&2; exit 1; }

# 3. Payload contents + ownership.
# NOTE: bomutils' `lsbom` SEGFAULTS on Linux (known port bug), so verify ownership from
# the Payload cpio itself (numeric). The Bom is built with `mkbom -u 0 -g 0`, so it matches
# the Payload by construction; macOS Installer reads the Bom natively at install time.
( cd "${work}" && xar -xf "${pkg}" base.pkg/Payload base.pkg/Bom )
own="$(gunzip -c "${work}/base.pkg/Payload" | cpio -itnv 2>/dev/null | awk '$NF ~ /(^|\/)usr\/local\/bin\/cynative$/{print $3" "$4}')"
[ "${own}" = "0 0" ] || { echo "::error::payload binary not root:wheel (got owner '${own}')" >&2; exit 1; }
( cd "${work}" && gunzip -c base.pkg/Payload | cpio -idm 2>/dev/null )
test -f "${work}/usr/local/bin/cynative" || { echo "::error::payload missing /usr/local/bin/cynative" >&2; exit 1; }

# 4. Payload binary == reference dist binary (proves cdhash coupling).
a="$(sha256sum "${ref}" | cut -d' ' -f1)"; b="$(sha256sum "${work}/usr/local/bin/cynative" | cut -d' ' -f1)"
[ "${a}" = "${b}" ] || { echo "::error::payload sha256 ${b} != reference ${a}" >&2; exit 1; }

# 5. Hardened runtime + BOTH JIT entitlements on the payload binary (Codex M5).
info="$(rcodesign print-signature-info "${work}/usr/local/bin/cynative" 2>/dev/null || true)"
grep -qE 'CodeSignatureFlags\([^)]*RUNTIME' <<<"${info}" || { echo "::error::payload binary missing hardened runtime" >&2; exit 1; }
grep -q  allow-unsigned-executable-memory <<<"${info}" || { echo "::error::payload binary missing allow-unsigned-executable-memory" >&2; exit 1; }
grep -q  allow-jit                        <<<"${info}" || { echo "::error::payload binary missing allow-jit" >&2; exit 1; }
echo "assert-pkg OK: ${pkg}"
