#!/usr/bin/env bash
# End-to-end GitHub dry-run of the immutable-release pipeline on a throwaway
# PUBLIC repo (public because the real repo is public and release
# attestations are plan-gated on private repos). Drives the REAL
# release-please CLI, the SAME scripts/release/*.sh the workflow runs, and
# the pinned goreleaser.
#
# Prereqs: gh (authenticated, repo scope), jq, go, node/npx, run from the
# cynative repo root. Teardown needs the delete_repo scope
# (gh auth refresh -h github.com -s delete_repo) or delete the repo manually.
#
# Usage: scripts/release/smoke-test.sh [owner/name-of-throwaway-repo]
#   Env: SMOKE_ATTESTATION_ATTEMPTS — attestation retry budget (default 120).
set -euo pipefail

# Unique name per run: a failed teardown must not poison the next run
# (timestamp + PID so same-second runs cannot collide).
smoke_repo=${1:-$(gh api user --jq .login)/cynative-immutable-smoke-$(date +%s)-$$}
cyn_root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT
goreleaser_bin="${work}/goreleaser"
fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }
expect_fail() { if out=$("$@" 2>&1); then fail "expected failure: $* — output: ${out}"; fi; }
# Like expect_fail, but also require the failure output to contain $1 — so a
# wrong-reason failure (environmental flake) cannot pass as the proven one.
expect_fail_match() {
  local pattern=$1
  shift
  if out=$("$@" 2>&1); then
    fail "expected failure: $* — output: ${out}"
  fi
  grep -q "${pattern}" <<<"${out}" ||
    fail "failure did not match '${pattern}': $* — output: ${out}"
}

# Fail in seconds, not minutes, if this gh cannot verify releases.
gh release --help 2>/dev/null | grep -qE '^[[:space:]]+verify:' ||
  fail "local gh lacks 'release verify' — upgrade gh first"

echo "== build pinned goreleaser from the cynative module =="
(cd "${cyn_root}" && go build -o "${goreleaser_bin}" github.com/goreleaser/goreleaser/v2)

echo "== create throwaway repo ${smoke_repo} =="
gh repo create "${smoke_repo}" --public
gh repo clone "${smoke_repo}" "${work}/repo"
cd "${work}/repo"
git switch -c main 2>/dev/null || git switch main
# Fresh clone on a box that pushes over SSH elsewhere: wire gh as the https
# credential helper and give the throwaway clone a local identity.
git config credential.helper '!gh auth git-credential'
git config user.name "cynative-smoke"
git config user.email "cynative-smoke@example.invalid"

echo "== seed minimal Go project + release config =="
cat > go.mod <<EOF
module github.com/${smoke_repo}

go 1.24
EOF
cat > main.go <<'EOF'
// Package main is a smoke-test fixture.
package main

import "fmt"

func main() { fmt.Println("smoke") }
EOF
cat > .goreleaser.yaml <<'EOF'
version: 2
builds:
  - main: .
    env: [CGO_ENABLED=0]
    goos: [linux]
    goarch: [amd64]
archives:
  - formats: [tar.gz]
source:
  enabled: true
release:
  # Same handoff contract as the real pipeline (the part under test).
  draft: true
  use_existing_draft: true
  mode: keep-existing
changelog:
  disable: true
EOF
cat > release-please-config.json <<'EOF'
{
  "release-type": "go",
  "bump-minor-pre-major": true,
  "bump-patch-for-minor-pre-major": true,
  "draft": true,
  "packages": { ".": {} }
}
EOF
echo '{ ".": "0.0.1" }' > .release-please-manifest.json
# dist/ must be ignored or goreleaser's dirty-state check fails on the
# second release cycle.
echo "dist/" > .gitignore
git add -A && git commit -m "chore: seed smoke fixture" && git push -u origin main

echo "== enable immutable releases =="
gh api -X PUT "repos/${smoke_repo}/immutable-releases" >/dev/null
[ "$(gh api "repos/${smoke_repo}/immutable-releases" --jq .enabled)" = "true" ] ||
  fail "immutable releases not enabled"

echo "== real release-please: release-pr -> merge -> github-release (draft) =="
git commit --allow-empty -m "feat: trigger a release" && git push
token=$(gh auth token)
npx --yes release-please@17 release-pr --repo-url="${smoke_repo}" --token="${token}"
pr=$(gh pr list --repo "${smoke_repo}" --state open --json number --jq '.[0].number')
[ -n "${pr}" ] || fail "release-please opened no PR"
gh pr merge "${pr}" --repo "${smoke_repo}" --squash --admin
# Pin to the exact merge commit, not whatever main has advanced to — the
# SHA/tag handoff is the thing under test. mergeCommit can be null for a
# brief window after a squash merge, so retry until it is available.
sha=""
for _ in 1 2 3 4 5; do
  sha=$(gh pr view "${pr}" --repo "${smoke_repo}" --json mergeCommit --jq '.mergeCommit.oid // empty')
  [ -n "${sha}" ] && break
  sleep 2
done
[ -n "${sha}" ] || fail "mergeCommit not available for PR ${pr}"
git fetch origin && git reset --hard "${sha}"
npx --yes release-please@17 github-release --repo-url="${smoke_repo}" --token="${token}"

# Deterministic given the seeded config: bump-patch-for-minor-pre-major
# turns a feat into a patch bump, so 0.0.1 + feat -> v0.0.2.
tag=v0.0.2

echo "== assert: draft titled exactly like the tag; tag is lazy (absent) =="
# The releases list endpoint can lag a just-created draft (read-after-write
# consistency), so poll briefly before declaring it missing.
found=""
for _ in 1 2 3 4 5; do
  if [ "$(gh api "repos/${smoke_repo}/releases?per_page=10" \
    --jq "[.[] | select(.draft and .name == \"${tag}\")] | length")" = "1" ]; then
    found=1
    break
  fi
  sleep 3
done
[ -n "${found}" ] || fail "expected one draft named ${tag}"
expect_fail gh api "repos/${smoke_repo}/git/ref/tags/${tag}"

echo "== pipeline steps, same scripts as the workflow =="
export GH_TOKEN="${token}"
"${cyn_root}/scripts/release/ensure-tag.sh" "${smoke_repo}" "${tag}" "${sha}"
git fetch origin "refs/tags/${tag}:refs/tags/${tag}"
GITHUB_TOKEN="${token}" "${goreleaser_bin}" release --clean
release_id=$("${cyn_root}/scripts/release/assert-draft.sh" "${smoke_repo}" "${tag}")
"${cyn_root}/scripts/release/expected-assets.sh" dist > "${work}/expected.tsv"
"${cyn_root}/scripts/release/assert-assets.sh" "${smoke_repo}" "${release_id}" "${work}/expected.tsv"
"${cyn_root}/scripts/release/ensure-tag.sh" "${smoke_repo}" "${tag}" "${sha}"
"${cyn_root}/scripts/release/publish-release.sh" "${smoke_repo}" "${release_id}"
# Short retry against API flakes; these checks are instant reads of frozen
# state (attestation verification is separate and async, below).
verified=""
for attempt in 1 2 3; do
  if "${cyn_root}/scripts/release/verify-published.sh" \
    "${smoke_repo}" "${tag}" "${release_id}" "${work}/expected.tsv" "${sha}"; then
    verified=1
    break
  fi
  echo "verify-published attempt ${attempt} failed; retrying in 5s"
  sleep 5
done
[ -n "${verified}" ] || fail "verify-published did not pass after 3 attempts"

echo "== attestation (async — the Release Attestation workflow covers prod) =="
# Same ~30-minute default budget as the production workflow (observed lag
# 15–20+ minutes on the real repo; throwaway repos are usually instant, and
# the loop exits early on success). Override via SMOKE_ATTESTATION_ATTEMPTS.
att=""
for _ in $(seq 1 "${SMOKE_ATTESTATION_ATTEMPTS:-120}"); do
  if gh release verify "${tag}" --repo "${smoke_repo}" >/dev/null 2>&1; then
    att=1
    break
  fi
  sleep 15
done
[ -n "${att}" ] || fail "no attestation for ${tag} within the retry budget"
# Per-asset coverage: every built file must be a subject in the attestation.
while IFS=$'\t' read -r _name _sha path; do
  gh release verify-asset "${tag}" "${path}" --repo "${smoke_repo}"
done < "${work}/expected.tsv"

echo "== assert immutability: mutations must fail =="
asset_id=$(gh api "repos/${smoke_repo}/releases/${release_id}/assets?per_page=1" --jq '.[0].id')
expect_fail gh api -X DELETE "repos/${smoke_repo}/releases/assets/${asset_id}"
expect_fail gh api -X DELETE "repos/${smoke_repo}/git/refs/tags/${tag}"

echo "== negative 1: pre-existing tag at wrong SHA must abort ensure-tag =="
first_sha=$(git rev-list --max-parents=0 HEAD)
gh api "repos/${smoke_repo}/git/refs" -f ref="refs/tags/v9.9.9" -f sha="${first_sha}" >/dev/null
expect_fail "${cyn_root}/scripts/release/ensure-tag.sh" "${smoke_repo}" "v9.9.9" "${sha}"

echo "== negative 2: surplus draft asset must fail the pre-publish assertion =="
surplus_id=$(gh api "repos/${smoke_repo}/releases" -f tag_name=v9.9.8 -f name=v9.9.8 -F draft=true --jq .id)
echo "malicious" > "${work}/evil.txt"
# Drafts cannot be addressed by tag (the very lesson this design encodes), so
# upload via the uploads API by release ID.
gh api -X POST -H "Content-Type: text/plain" \
  "https://uploads.github.com/repos/${smoke_repo}/releases/${surplus_id}/assets?name=evil.txt" \
  --input "${work}/evil.txt" >/dev/null
expect_fail_match "asset set does not match" "${cyn_root}/scripts/release/assert-assets.sh" "${smoke_repo}" "${surplus_id}" "${work}/expected.tsv"

echo "== negative 3: surplus injected AFTER assertion is caught post-publish =="
# Second real release cycle (v0.2.0): run everything up to and including the
# pre-publish assertions, then inject, then publish — verify-published's
# exact re-check must fail.
git commit --allow-empty -m "feat: trigger second release" && git push
npx --yes release-please@17 release-pr --repo-url="${smoke_repo}" --token="${token}"
pr=$(gh pr list --repo "${smoke_repo}" --state open --json number --jq '.[0].number')
[ -n "${pr}" ] || fail "release-please opened no PR for the second cycle"
gh pr merge "${pr}" --repo "${smoke_repo}" --squash --admin
sha2=""
for _ in 1 2 3 4 5; do
  sha2=$(gh pr view "${pr}" --repo "${smoke_repo}" --json mergeCommit --jq '.mergeCommit.oid // empty')
  [ -n "${sha2}" ] && break
  sleep 2
done
[ -n "${sha2}" ] || fail "mergeCommit not available for PR ${pr}"
git fetch origin && git reset --hard "${sha2}"
npx --yes release-please@17 github-release --repo-url="${smoke_repo}" --token="${token}"
tag2=v0.0.3
"${cyn_root}/scripts/release/ensure-tag.sh" "${smoke_repo}" "${tag2}" "${sha2}"
git fetch origin "refs/tags/${tag2}:refs/tags/${tag2}"
GITHUB_TOKEN="${token}" "${goreleaser_bin}" release --clean
release_id2=$("${cyn_root}/scripts/release/assert-draft.sh" "${smoke_repo}" "${tag2}")
"${cyn_root}/scripts/release/expected-assets.sh" dist > "${work}/expected2.tsv"
"${cyn_root}/scripts/release/assert-assets.sh" "${smoke_repo}" "${release_id2}" "${work}/expected2.tsv"
gh api -X POST -H "Content-Type: text/plain" \
  "https://uploads.github.com/repos/${smoke_repo}/releases/${release_id2}/assets?name=evil.txt" \
  --input "${work}/evil.txt" >/dev/null
"${cyn_root}/scripts/release/publish-release.sh" "${smoke_repo}" "${release_id2}"
expect_fail_match "asset set does not match" "${cyn_root}/scripts/release/verify-published.sh" \
  "${smoke_repo}" "${tag2}" "${release_id2}" "${work}/expected2.tsv" "${sha2}"

echo "== teardown =="
gh repo delete "${smoke_repo}" --yes ||
  echo "WARN: could not delete ${smoke_repo} (needs delete_repo scope) — delete it manually"
echo "SMOKE TEST PASSED"
