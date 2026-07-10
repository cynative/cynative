#!/usr/bin/env bash
# Render + commit the Homebrew Formula to cynative/homebrew-tap, retiring the
# legacy Cask. Requires GH_TOKEN with push access.
# Usage: publish-tap.sh <version-without-v> <assets-tsv>
#   assets-tsv: "name<TAB>sha256<TAB>path" rows (the workflow's expected-assets.tsv).
set -euo pipefail
version="$1"; assets="$2"
: "${GH_TOKEN:?}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=scripts/release/assets-lib.sh
# shellcheck disable=SC1091 # gated standalone; the shellcheck gate runs without -x.
. "${here}/assets-lib.sh"

sha_darwin_arm="$(sha_for "${assets}" cynative_Darwin_arm64.tar.gz)"
sha_darwin_intel="$(sha_for "${assets}" cynative_Darwin_x86_64.tar.gz)"
sha_linux_arm="$(sha_for "${assets}" cynative_Linux_arm64.tar.gz)"
sha_linux_intel="$(sha_for "${assets}" cynative_Linux_x86_64.tar.gz)"

work="$(mktemp -d)"; trap 'rm -rf "${work}"' EXIT
git clone --depth 1 \
  "https://x-access-token:${GH_TOKEN}@github.com/cynative/homebrew-tap.git" "${work}/tap"

mkdir -p "${work}/tap/Formula"
"${here}/render-formula.sh" "${version}" \
  "${sha_darwin_arm}" "${sha_darwin_intel}" "${sha_linux_arm}" "${sha_linux_intel}" \
  > "${work}/tap/Formula/cynative.rb"
git -C "${work}/tap" add Formula/cynative.rb

# Retire the legacy Cask (idempotent: present only on the first release after the split).
if [ -f "${work}/tap/Casks/cynative.rb" ]; then
  git -C "${work}/tap" rm -f Casks/cynative.rb
fi

if git -C "${work}/tap" diff --cached --quiet; then echo "tap unchanged"; exit 0; fi
git -C "${work}/tap" -c user.name="cynative-release[bot]" -c user.email="release@cynative.com" \
  commit -m "cynative ${version}"
git -C "${work}/tap" push origin HEAD
echo "pushed formula ${version}"
