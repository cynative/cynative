#!/usr/bin/env bash
# Assert a release's asset set equals the expected manifest EXACTLY — names
# AND sha256 digests. Detects surplus, missing, and swapped assets. Used both
# pre-publish (gate) and post-publish (authoritative re-check: the published
# asset list is immutable, so the read cannot be raced).
#
# Usage: assert-assets.sh <owner/repo> <release-id> <manifest.tsv>
#   manifest: LC_ALL=C-sorted TSV "name<TAB>sha256<TAB>path"   (requires GH_TOKEN)
set -euo pipefail

repo=$1
release_id=$2
manifest=$3

if [ ! -s "${manifest}" ]; then
  echo "::error::manifest ${manifest} missing or empty" >&2
  exit 1
fi

remote_file=$(mktemp)
tmp_asset=$(mktemp)
trap 'rm -f "${remote_file}" "${tmp_asset}"' EXIT

assets=$(gh api --paginate "repos/${repo}/releases/${release_id}/assets?per_page=100" |
  jq -r '.[] | [.id, .name, (.digest // "null")] | @tsv')

if [ -n "${assets}" ]; then
  while IFS=$'\t' read -r asset_id name digest; do
    if [ "${digest}" = "null" ] || [ -z "${digest}" ]; then
      # API returned no digest — download the asset and hash it ourselves.
      gh api "repos/${repo}/releases/assets/${asset_id}" \
        -H "Accept: application/octet-stream" > "${tmp_asset}"
      hashed=$(sha256sum "${tmp_asset}" | cut -d' ' -f1)
      digest="sha256:${hashed}"
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
