#!/usr/bin/env bash
# Render + commit the cask to cynative/homebrew-tap. Requires GH_TOKEN with push access.
# Usage: publish-cask.sh <version-without-v> <arm64-pkg-sha256> <x86_64-pkg-sha256>
set -euo pipefail
version="$1"; sha_arm="$2"; sha_intel="$3"
: "${GH_TOKEN:?}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"; trap 'rm -rf "${work}"' EXIT

git clone --depth 1 "https://x-access-token:${GH_TOKEN}@github.com/cynative/homebrew-tap.git" "${work}/tap"
mkdir -p "${work}/tap/Casks"
"${here}/render-cask.sh" "${version}" "${sha_arm}" "${sha_intel}" > "${work}/tap/Casks/cynative.rb"
git -C "${work}/tap" add Casks/cynative.rb
if git -C "${work}/tap" diff --cached --quiet; then echo "cask unchanged"; exit 0; fi
git -C "${work}/tap" -c user.name="cynative-release[bot]" -c user.email="release@cynative.com" \
  commit -m "cynative ${version}"
git -C "${work}/tap" push origin HEAD
echo "pushed cask ${version}"
