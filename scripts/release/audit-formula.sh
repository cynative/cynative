#!/usr/bin/env bash
# Render the Homebrew Formula from the release assets manifest and run
# `brew audit --strict` against it in a throwaway local tap, BEFORE publish:
# a failure stops the release with the draft intact and the tap untouched, so
# a broken formula can never strand a published release behind a stale tap.
# Offline by necessity: draft assets are not publicly downloadable, so
# --online checks are impossible pre-publish.
# Usage: audit-formula.sh <version-without-v> <assets-tsv>
#   assets-tsv: "name<TAB>sha256<TAB>path" rows (the workflow's expected-assets.tsv).
set -euo pipefail
version="$1"; assets="$2"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=scripts/release/assets-lib.sh
# shellcheck disable=SC1091 # gated standalone; the shellcheck gate runs without -x.
. "${here}/assets-lib.sh"

sha_darwin_arm="$(sha_for "${assets}" cynative_Darwin_arm64.tar.gz)"
sha_darwin_intel="$(sha_for "${assets}" cynative_Darwin_x86_64.tar.gz)"
sha_linux_arm="$(sha_for "${assets}" cynative_Linux_arm64.tar.gz)"
sha_linux_intel="$(sha_for "${assets}" cynative_Linux_x86_64.tar.gz)"

# No auto-update inside the release gate: avoidable latency and flake surface.
export HOMEBREW_NO_AUTO_UPDATE=1
# The release job runs on ubuntu-latest, where brew is preinstalled off PATH.
if ! command -v brew >/dev/null 2>&1 && [ -x /home/linuxbrew/.linuxbrew/bin/brew ]; then
  eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"
fi
command -v brew >/dev/null 2>&1 || { echo "::error::brew not found" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "::error::jq not found" >&2; exit 1; }

# Throwaway local tap. --no-git because tap-new otherwise makes a git commit,
# which fails wherever no git identity is configured (CI runners, dev hosts).
# Untap first so local re-runs are idempotent; untap again on exit to clean up.
brew untap cynative/audit >/dev/null 2>&1 || true
brew tap-new --no-git cynative/audit >/dev/null
trap 'brew untap cynative/audit >/dev/null 2>&1 || true' EXIT

formula="$(brew --repository cynative/audit)/Formula/cynative.rb"
"${here}/render-formula.sh" "${version}" \
  "${sha_darwin_arm}" "${sha_darwin_intel}" "${sha_linux_arm}" "${sha_linux_intel}" \
  > "${formula}"

# --except=version, and the formula KEEPS its `version` stanza. `brew audit
# --strict` calls a version that matches the one it scans out of the download
# url redundant, and fails the release over it; the obvious answer, dropping the
# stanza, is wrong. Homebrew's url parsing is not a dependable version source
# for our asset names, and it is the USER's brew that resolves the formula, not
# CI's:
#   * before Homebrew/brew#23336, `cynative_Linux_x86_64.tar.gz` scanned as
#     version "86.64" (which is why this audit passed silently until v1.9.0)
#   * the ubuntu-latest brew that carries that fix still scans
#     `cynative_Darwin_arm64.tar.gz` as version "64" (observed live on the
#     v1.9.1 release run)
# so a stanza-less formula installs under a version nobody chose on whichever
# arch the user's brew happens to misparse, and `brew upgrade` compares exactly
# that label. An explicit version is the only spelling that means the same thing
# on every brew. --except takes audit METHOD names, so this turns off exactly
# one, ResourceAuditor#audit_version, and nothing else.
brew audit --strict --except=version cynative/audit/cynative

# That method's only other service here is catching a missing or empty version
# (its remaining arm is core/bottle-only), so assert the version directly rather
# than lose the check: this is what the formula will report to `brew install`.
resolved="$(brew info --json=v2 cynative/audit/cynative | jq -r '.formulae[0].versions.stable')"
if [ "${resolved}" != "${version}" ]; then
  echo "::error::formula reports version '${resolved}', expected '${version}'" >&2
  exit 1
fi
echo "formula audit OK (${version})"
