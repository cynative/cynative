#!/usr/bin/env bash
# Render the Scoop manifest (bucket/cynative.json) to stdout. The Scoop analog of
# render-formula.sh: pure and arg-driven, so it is unit-testable offline.
# Usage: render-scoop.sh <version-without-v> <sha_windows_x86_64> <sha_windows_arm64>
set -euo pipefail
version="$1"; sha_intel="$2"; sha_arm="$3"

[ -n "${version}" ] || { echo "::error::empty version" >&2; exit 1; }
for sha in "${sha_intel}" "${sha_arm}"; do
  [[ "${sha}" =~ ^[0-9a-f]{64}$ ]] || { echo "::error::malformed sha256: ${sha}" >&2; exit 1; }
done

base="https://github.com/cynative/cynative/releases/download/v${version}"
jq -n --indent 4 \
  --arg version "${version}" \
  --arg url64 "${base}/cynative_Windows_x86_64.zip" \
  --arg hash64 "${sha_intel}" \
  --arg urlarm "${base}/cynative_Windows_arm64.zip" \
  --arg hasharm "${sha_arm}" \
  --arg homepage "https://github.com/cynative/cynative" \
  --arg license "Apache-2.0" \
  --arg description "Agentic security research across your code, cloud, and runtime (read-only)" \
  '{
     version: $version,
     architecture: {
       "64bit": { url: $url64, bin: ["cynative.exe"], hash: $hash64 },
       "arm64": { url: $urlarm, bin: ["cynative.exe"], hash: $hasharm }
     },
     homepage: $homepage,
     license: $license,
     description: $description
   }'
