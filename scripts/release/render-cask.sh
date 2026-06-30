#!/usr/bin/env bash
# Render the Homebrew Cask for the pkg release to stdout.
# Usage: render-cask.sh <version-without-v> <arm64-pkg-sha256> <x86_64-pkg-sha256>
set -euo pipefail
version="$1"; sha_arm="$2"; sha_intel="$3"
# Note: ${...} are bash (filled now); #{...} are Ruby (evaluated by brew at install).
cat <<EOF
cask "cynative" do
  arch arm: "arm64", intel: "x86_64"

  version "${version}"
  sha256 arm:   "${sha_arm}",
         intel: "${sha_intel}"

  url "https://github.com/cynative/cynative/releases/download/v#{version}/cynative_Darwin_#{arch}.pkg",
      verified: "github.com/cynative/cynative/"
  name "Cynative"
  desc "Agentic security research across your code, cloud and runtime — read-only by construction"
  homepage "https://github.com/cynative/cynative"

  depends_on macos: ">= :big_sur"

  pkg "cynative_Darwin_#{arch}.pkg"

  uninstall pkgutil: "com.cynative.cynative",
            delete:  "/usr/local/bin/cynative"

  caveats <<~CAVEATS
    cynative installs to /usr/local/bin (the macOS Installer may prompt for your password).
    Set your LLM provider, model and an API key before first run, e.g.:
      export CYNATIVE_LLM_PROVIDER=anthropic
      export CYNATIVE_LLM_MODEL=claude-opus-4-8
      export ANTHROPIC_API_KEY=...
  CAVEATS
end
EOF
