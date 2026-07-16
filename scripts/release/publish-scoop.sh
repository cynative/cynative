#!/usr/bin/env bash
# Render + push the Scoop manifest to cynative/scoop-bucket, AFTER the release is
# published and verified. The Scoop analog of publish-tap.sh. Requires GH_TOKEN
# with push access to scoop-bucket.
# Usage: publish-scoop.sh <version-without-v> <checksums-file>
#   checksums-file: the published release's checksums.txt ("<sha256>  <name>" rows).
set -euo pipefail
version="$1"; checksums="$2"
: "${GH_TOKEN:?}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=scripts/release/assets-lib.sh
# shellcheck disable=SC1091 # gated standalone; the shellcheck gate runs without -x.
. "${here}/assets-lib.sh"

# Strict, duplicate-detecting lookups: the manifest hash is Scoop's install-time
# integrity check, so a wrong or ambiguous digest must fail the push, not ship.
sha_windows_intel="$(sha_for_checksums "${checksums}" cynative_Windows_x86_64.zip)"
sha_windows_arm="$(sha_for_checksums "${checksums}" cynative_Windows_arm64.zip)"

work="$(mktemp -d)"; trap 'rm -rf "${work}"' EXIT
git clone --depth 1 \
  "https://x-access-token:${GH_TOKEN}@github.com/cynative/scoop-bucket.git" "${work}/bucket"

mkdir -p "${work}/bucket/bucket"
"${here}/render-scoop.sh" "${version}" "${sha_windows_intel}" "${sha_windows_arm}" \
  > "${work}/bucket/bucket/cynative.json"
git -C "${work}/bucket" add bucket/cynative.json

# Idempotent: the bucket already serves identical content.
if git -C "${work}/bucket" diff --cached --quiet; then echo "bucket unchanged"; exit 0; fi
git -C "${work}/bucket" -c user.name="cynative-release[bot]" -c user.email="release@cynative.com" \
  commit -m "cynative ${version}"
# Fast-forward only: a plain push rejects a non-ff update, never --force.
git -C "${work}/bucket" push origin HEAD
echo "pushed scoop manifest ${version}"
