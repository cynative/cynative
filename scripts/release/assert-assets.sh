#!/usr/bin/env bash
# Assert a release's asset set equals the expected manifest EXACTLY — names
# AND sha256 digests. Detects surplus, missing, and swapped assets. Used both
# pre-publish (gate) and post-publish (authoritative re-check: the published
# asset list is immutable, so the read cannot be raced).
#
# Usage:
#   assert-assets.sh generate <dist-dir>
#     Print the expected release-asset manifest as sorted TSV
#     "name<TAB>sha256<TAB>path", derived from goreleaser's dist/artifacts.json.
#     Covers exactly what goreleaser uploads: archives and the checksums file.
#     Columns 1-2 are the assertion key (assert mode below); column 3 is the
#     local path the release job stages into the release-artifacts hand-off
#     (downstream consumers never dereference it).
#
#   assert-assets.sh <owner/repo> <release-id> <manifest.tsv>
#     manifest: LC_ALL=C-sorted TSV "name<TAB>sha256<TAB>path"   (requires GH_TOKEN)
set -euo pipefail

if [ "${1:-}" = "generate" ]; then
  dist=$2

  jq -r '.[]
    | select(.type == "Archive" or .type == "Checksum")
    | [.name, .path] | @tsv' "${dist}/artifacts.json" |
    while IFS=$'\t' read -r name path; do
      # Bare assignment so a sha256sum failure aborts the script (an argument
      # substitution would swallow the exit status and emit an empty digest).
      digest=$(sha256sum "${path}" | cut -d' ' -f1)
      printf '%s\t%s\t%s\n' "${name}" "${digest}" "${path}"
    done | LC_ALL=C sort
  exit 0
fi

repo=$1
release_id=$2
manifest=$3

if [ ! -s "${manifest}" ]; then
  echo "::error::manifest ${manifest} missing or empty" >&2
  exit 1
fi

remote_file=$(mktemp)
trap 'rm -f "${remote_file}"' EXIT

assets=$(gh api --paginate "repos/${repo}/releases/${release_id}/assets?per_page=100" |
  jq -r '.[] | [.name, (.digest // "null")] | @tsv')

if [ -n "${assets}" ]; then
  while IFS=$'\t' read -r name digest; do
    if [ "${digest}" = "null" ] || [ -z "${digest}" ]; then
      # API returned no digest. Fail closed rather than downloading the asset
      # body (potentially several hundred MB) to hash it ourselves.
      echo "::error::release asset ${name} has no API digest; refusing to hash locally" >&2
      exit 1
    fi
    printf '%s\t%s\n' "${name}" "${digest#sha256:}" >> "${remote_file}"
  done <<<"${assets}"
fi

LC_ALL=C sort -o "${remote_file}" "${remote_file}"

if ! diff <(cut -f1,2 "${manifest}") "${remote_file}"; then
  echo "::error::release ${release_id} asset set does not match the expected manifest (< expected, > actual)" >&2
  exit 1
fi
echo "asset set matches expected manifest ($(wc -l < "${manifest}") assets)"
