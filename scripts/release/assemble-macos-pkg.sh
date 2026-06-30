#!/usr/bin/env bash
# Assemble one unsigned macOS flat .pkg on Linux. No Apple credentials needed.
# Usage: assemble-macos-pkg.sh <goarch:amd64|arm64> <signed-binary> <version> <out.pkg>
set -euo pipefail

goarch="$1"; binary="$2"; version="$3"; out_arg="$4"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$(dirname "${out_arg}")"
out="$(cd "$(dirname "${out_arg}")" && pwd)/$(basename "${out_arg}")"   # absolutize before any cd

case "${goarch}" in
  amd64) host_arch="x86_64" ;;
  arm64) host_arch="arm64" ;;
  *) echo "unsupported goarch: ${goarch}" >&2; exit 1 ;;
esac

work="$(mktemp -d)"; trap 'rm -rf "${work}"' EXIT
root="${work}/root"; flat="${work}/flat"
mkdir -p "${root}/usr/local/bin" "${flat}/base.pkg"
install -m 0755 "${binary}" "${root}/usr/local/bin/cynative"

# Payload: deterministic cpio (odc), root:wheel ownership, gzip.
( cd "${root}" && find . | LC_ALL=C sort | cpio -o --format odc -R 0:0 | gzip -c ) \
  > "${flat}/base.pkg/Payload"

# Bom: matching root:wheel ownership.
mkbom -u 0 -g 0 "${root}" "${flat}/base.pkg/Bom"

# Metadata from templates.
sed -e "s/@VERSION@/${version}/g" -e "s/@IDENTIFIER@/com.cynative.cynative/g" \
  "${here}/templates/PackageInfo.tmpl" > "${flat}/base.pkg/PackageInfo"
sed -e "s/@VERSION@/${version}/g" -e "s/@IDENTIFIER@/com.cynative.cynative/g" -e "s/@HOST_ARCH@/${host_arch}/g" \
  "${here}/templates/Distribution.tmpl" > "${flat}/Distribution"

# Flat package: uncompressed XAR, Distribution first.
( cd "${flat}" && xar --compression none -cf "${out}" Distribution base.pkg )
echo "assembled ${out}"
