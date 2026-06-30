#!/usr/bin/env bash
# Render + commit the Homebrew Formula to cynative/homebrew-tap, retiring the
# legacy Cask. Requires GH_TOKEN with push access.
# Usage: publish-tap.sh <version-without-v> <assets-tsv>
#   assets-tsv: "name<TAB>sha256<TAB>path" rows (the workflow's expected-assets.tsv).
set -euo pipefail
version="$1"; assets="$2"
: "${GH_TOKEN:?}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pull a tarball's sha256 out of the assets manifest, failing closed on a missing
# row or a non-64-hex digest (never publish a Formula with a bad sha256).
sha_for() {
  local name="$1" sha
  sha="$(awk -F'\t' -v n="${name}" '$1==n{print $2; exit}' "${assets}")"
  [[ "${sha}" =~ ^[0-9a-f]{64}$ ]] || {
    echo "::error::missing or invalid sha256 for ${name}" >&2
    exit 1
  }
  printf '%s' "${sha}"
}

sha_darwin_arm="$(sha_for cynative_Darwin_arm64.tar.gz)"
sha_darwin_intel="$(sha_for cynative_Darwin_x86_64.tar.gz)"
sha_linux_arm="$(sha_for cynative_Linux_arm64.tar.gz)"
sha_linux_intel="$(sha_for cynative_Linux_x86_64.tar.gz)"

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
