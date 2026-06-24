#!/usr/bin/env bash
# Create the release tag ref at the expected SHA, or verify a pre-existing one
# points exactly there. A pre-existing tag at a different SHA aborts the run:
# building it would immutably publish the wrong code. Idempotent — also used
# as the pre-publish tag re-verify.
#
# Usage: ensure-tag.sh <owner/repo> <tag> <sha>   (requires GH_TOKEN)
set -euo pipefail

repo=$1
tag=$2
sha=$3

if out=$(gh api "repos/${repo}/git/refs" -f ref="refs/tags/${tag}" -f sha="${sha}" 2>&1); then
  echo "created tag ${tag} at ${sha}"
  exit 0
fi
if ! grep -q "Reference already exists" <<<"${out}"; then
  echo "::error::creating tag ${tag} failed: ${out}"
  exit 1
fi
existing=$(gh api "repos/${repo}/git/ref/tags/${tag}" --jq '.object.sha')
if [ "${existing}" != "${sha}" ]; then
  # Note: an annotated tag's object.sha is the tag object, not the commit —
  # it will mismatch and fail closed here, which is the safe direction.
  echo "::error::tag ${tag} exists at ${existing}, expected ${sha} — refusing to build; investigate before rerunning (do NOT delete a tag this pipeline did not create)"
  exit 1
fi
echo "tag ${tag} already exists at expected ${sha}"
