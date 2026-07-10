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

# Throwaway local tap. --no-git because tap-new otherwise makes a git commit,
# which fails wherever no git identity is configured (CI runners, dev hosts).
# Untap first so local re-runs are idempotent; untap again on exit to clean up.
brew untap cynative/audit >/dev/null 2>&1 || true
brew tap-new --no-git cynative/audit >/dev/null
trap 'brew untap cynative/audit >/dev/null 2>&1 || true' EXIT

"${here}/render-formula.sh" "${version}" \
  "${sha_darwin_arm}" "${sha_darwin_intel}" "${sha_linux_arm}" "${sha_linux_intel}" \
  > "$(brew --repository cynative/audit)/Formula/cynative.rb"

brew audit --strict cynative/audit/cynative
echo "formula audit OK (${version})"
