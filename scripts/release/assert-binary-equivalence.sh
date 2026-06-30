#!/usr/bin/env bash
# Assert the signed binary is byte-identical across dist, tarball, and pkg payload.
# Usage: assert-binary-equivalence.sh <dist-binary> <tarball.tar.gz> <pkg>
set -euo pipefail

dist="$1"; tarball="$2"; pkg="$(cd "$(dirname "$3")" && pwd)/$(basename "$3")"
work="$(mktemp -d)"; trap 'rm -rf "${work}"' EXIT

tar -xzf "${tarball}" -C "${work}" cynative
( cd "${work}" && xar -xf "${pkg}" base.pkg/Payload && gunzip -c base.pkg/Payload | cpio -idm 2>/dev/null )

d="$(sha256sum "${dist}" | cut -d' ' -f1)"
t="$(sha256sum "${work}/cynative" | cut -d' ' -f1)"
p="$(sha256sum "${work}/usr/local/bin/cynative" | cut -d' ' -f1)"
echo "dist=${d} tarball=${t} pkg=${p}"
if ! [ "${d}" = "${t}" ] || ! [ "${d}" = "${p}" ]; then
  echo "::error::binary bytes diverge across dist/tarball/pkg" >&2; exit 1
fi
echo "assert-binary-equivalence OK"
