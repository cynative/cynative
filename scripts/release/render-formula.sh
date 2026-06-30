#!/usr/bin/env bash
# Render the Homebrew Formula (binary install over the release tarballs) to stdout.
# Usage: render-formula.sh <version-without-v> <sha_darwin_arm64> <sha_darwin_x86_64> <sha_linux_arm64> <sha_linux_x86_64>
# Note: ${...} are bash (filled now); #{...} are Ruby (evaluated by brew at install).
set -euo pipefail
version="$1"
sha_darwin_arm="$2"; sha_darwin_intel="$3"
sha_linux_arm="$4"; sha_linux_intel="$5"
cat <<EOF
class Cynative < Formula
  desc "Agentic security research across your code, cloud and runtime — read-only by construction"
  homepage "https://github.com/cynative/cynative"
  version "${version}"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/cynative/cynative/releases/download/v#{version}/cynative_Darwin_arm64.tar.gz"
      sha256 "${sha_darwin_arm}"
    end

    on_intel do
      url "https://github.com/cynative/cynative/releases/download/v#{version}/cynative_Darwin_x86_64.tar.gz"
      sha256 "${sha_darwin_intel}"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/cynative/cynative/releases/download/v#{version}/cynative_Linux_arm64.tar.gz"
      sha256 "${sha_linux_arm}"
    end

    on_intel do
      url "https://github.com/cynative/cynative/releases/download/v#{version}/cynative_Linux_x86_64.tar.gz"
      sha256 "${sha_linux_intel}"
    end
  end

  def install
    bin.install "cynative"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/cynative --version")
  end
end
EOF
