#!/usr/bin/env bash
# Assert exactly one DRAFT release titled exactly like the tag exists and
# print its release ID — the canonical release_id every later step consumes.
# Zero drafts means goreleaser failed to adopt; more than one means stale
# rerun debris that must be deleted before re-running.
#
# Usage: assert-draft.sh <owner/repo> <tag>   (requires GH_TOKEN)
set -euo pipefail

repo=$1
tag=$2

ids=$(gh api --paginate "repos/${repo}/releases?per_page=100" |
  jq -r --arg name "${tag}" \
    '.[] | select(.draft and .name == $name and .tag_name == $name
      and (.body // "" | length > 0)) | .id')
# Match on BOTH title (goreleaser's draft-adoption key) and tag_name (the
# ref GitHub binds at publish) — a draft matching only one of them means a
# misconfigured release that must not be published.
# A non-empty body distinguishes release-please's draft (changelog) from a
# draft goreleaser would have created itself (changelog disabled, empty).
count=0
if [ -n "${ids}" ]; then
  count=$(wc -l <<<"${ids}")
fi
if [ "${count}" -ne 1 ]; then
  echo "::error::expected exactly 1 draft release titled ${tag}, found ${count} — delete stale drafts before re-running" >&2
  exit 1
fi
echo "${ids}"
