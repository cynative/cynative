#!/usr/bin/env bash
# Publish the draft release — the instant of immutability. On any PATCH
# failure, never assume state: observe the release and branch on the actual
# draft field (the PATCH may have landed even if the response was lost).
#
# Usage: publish-release.sh <owner/repo> <release-id>   (requires GH_TOKEN)
set -euo pipefail

repo=$1
release_id=$2

# Refuse to publish unless immutable releases is enabled — publishing with
# the setting off would silently produce a mutable release. The draft stays
# intact, so the operator can enable the setting and re-run.
if ! enabled=$(gh api "repos/${repo}/immutable-releases" --jq '.enabled' 2>&1); then
  echo "::error::cannot read repos/${repo}/immutable-releases — the workflow's GitHub App token needs the repository Administration: read permission for this gate: ${enabled}" >&2
  exit 1
fi
if [ "${enabled}" != "true" ]; then
  echo "::error::immutable releases is not enabled on ${repo} — enable it (gh api -X PUT repos/${repo}/immutable-releases) and re-run; the draft is intact" >&2
  exit 1
fi

if gh api -X PATCH "repos/${repo}/releases/${release_id}" \
  -F draft=false -f make_latest=true >/dev/null; then
  echo "published release ${release_id}"
  exit 0
fi

echo "publish PATCH failed — observing actual release state" >&2
state=$(gh api "repos/${repo}/releases/${release_id}" --jq '.draft')
if [ "${state}" = "false" ]; then
  echo "release ${release_id} is published despite the PATCH error — continuing"
  exit 0
fi
echo "::error::release ${release_id} is still a draft; publish failed — pre-publish recovery applies (retry the workflow)" >&2
exit 1
