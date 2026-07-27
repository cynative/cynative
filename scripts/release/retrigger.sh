#!/usr/bin/env bash
# Start a FRESH Release Pipeline run without pushing to main.
#
# Why this exists: a failed pre-publish gate leaves the draft intact and recoverable,
# but re-running the failed run does not help when the fix was a secret. GitHub
# snapshots secret values at workflow-run-create time, not at re-run time
# (cli/cli#13522), so a re-run reuses the stale values and fails the same way.
#
# repository_dispatch, not workflow_dispatch: a repository_dispatch run always executes
# the workflow definition from the default branch, never a caller-selected ref, so there
# is no path for a doctored branch copy to reach the release App key or the macOS
# signing secrets.
#
# release-please phase 1 acts only on a pending release PR, so a dispatch with nothing
# pending is a no-op rather than a spurious release.
#
# Usage: retrigger.sh <owner/repo>   (requires GH_TOKEN with contents: write)
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: retrigger.sh <owner/repo>   (requires GH_TOKEN)" >&2
  exit 1
fi
repo=$1

# Require owner/name. A bare name would make gh resolve the path against the current
# directory's git remote, which is not necessarily the repo the operator meant.
case "${repo}" in
*/*) ;;
*)
  echo "::error::repo must be owner/name, got '${repo}'" >&2
  exit 1
  ;;
esac

if [ -z "${GH_TOKEN:-}" ]; then
  echo "::error::GH_TOKEN is not set; a dispatch needs a token with contents: write" >&2
  exit 1
fi

if ! gh api -X POST "repos/${repo}/dispatches" -f event_type=release-retry; then
  echo "::error::dispatch to ${repo} failed; no run was started" >&2
  exit 1
fi

echo "dispatched release-retry to ${repo}: a fresh Release Pipeline run is starting"
echo "watch it with: gh run list --workflow=release.yaml --repo ${repo} --limit 3"
