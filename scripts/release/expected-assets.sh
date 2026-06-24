#!/usr/bin/env bash
# Print the expected release-asset manifest as sorted TSV
# "name<TAB>sha256<TAB>path", derived from goreleaser's dist/artifacts.json.
# Covers exactly what goreleaser uploads: archives, the source archive, and
# the checksums file. Columns 1-2 are the assertion key (assert-assets.sh);
# column 3 is the local path verify-published.sh feeds to verify-asset.
#
# Usage: expected-assets.sh <dist-dir>
set -euo pipefail

dist=$1

jq -r '.[]
  | select(.type == "Archive" or .type == "Source" or .type == "Checksum")
  | [.name, .path] | @tsv' "${dist}/artifacts.json" |
  while IFS=$'\t' read -r name path; do
    # Bare assignment so a sha256sum failure aborts the script (an argument
    # substitution would swallow the exit status and emit an empty digest).
    digest=$(sha256sum "${path}" | cut -d' ' -f1)
    printf '%s\t%s\t%s\n' "${name}" "${digest}" "${path}"
  done | LC_ALL=C sort
