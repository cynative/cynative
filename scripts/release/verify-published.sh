#!/usr/bin/env bash
# Post-publish verification of everything that is readable IMMEDIATELY after
# publish (detection — publish cannot be rolled back):
# 1. exact asset-set re-check against the now-immutable asset list (catches
#    anything injected between the pre-publish assertion and the PATCH),
# 2. release→tag binding: the published release must still point at the
#    expected tag (a retagged draft would otherwise go live under a
#    different tag),
# 3. tag→SHA binding: the tag is frozen at publish, so this read is authoritative,
# 4. the release is marked latest.
# Attestation verification is deliberately NOT here: GitHub generates the
# release attestation asynchronously, 15–20+ minutes after publish on this
# repo (v0.3.3 exhausted a 10-minute in-run window), so it lives in the
# release-event-triggered attestation workflow instead. The bytes-chain
# still closes: the digest assertions here pin frozen assets == local dist,
# and the deferred `gh release verify` pins attestation == frozen assets.
#
# Usage: verify-published.sh <owner/repo> <tag> <release-id> <manifest.tsv> <sha>
#   (requires GH_TOKEN; manifest as in assert-assets.sh)
set -euo pipefail

repo=$1
tag=$2
release_id=$3
manifest=$4
sha=$5
here=$(dirname "$0")

"${here}/assert-assets.sh" "${repo}" "${release_id}" "${manifest}"

# The published release must still be bound to the expected tag — a
# retagged draft would otherwise go live under a different tag while the
# tag-scoped checks below pass against an impostor release.
published_tag=$(gh api "repos/${repo}/releases/${release_id}" --jq '.tag_name')
if [ "${published_tag}" != "${tag}" ]; then
  echo "::error::release ${release_id} is bound to tag ${published_tag}, expected ${tag}" >&2
  exit 1
fi

# The tag is frozen at publish; verify it is bound to the expected commit.
tag_sha=$(gh api "repos/${repo}/git/ref/tags/${tag}" --jq '.object.sha')
if [ "${tag_sha}" != "${sha}" ]; then
  echo "::error::published tag ${tag} points at ${tag_sha}, expected ${sha}" >&2
  exit 1
fi

# gh release view has no isLatest JSON field; compare against the REST
# "latest release" endpoint instead.
latest_id=$(gh api "repos/${repo}/releases/latest" --jq '.id')
if [ "${latest_id}" != "${release_id}" ]; then
  echo "::error::release ${tag} is not the latest release (latest id ${latest_id}, expected ${release_id})" >&2
  exit 1
fi
echo "post-publish verification passed for ${tag}"
