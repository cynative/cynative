#!/usr/bin/env bash
# Render the Homebrew Formula (binary install over the release tarballs) to stdout.
# Pure and arg-driven (the Homebrew twin of render-scoop.sh), so it is unit-testable offline.
# Usage: render-formula.sh <version-without-v> <sha_darwin_arm64> <sha_darwin_x86_64> <sha_linux_arm64> <sha_linux_x86_64>
# Note: ${...} are bash (filled now); #{...} are Ruby (evaluated by brew at install).
set -euo pipefail
version="$1"
sha_darwin_arm="$2"; sha_darwin_intel="$3"
sha_linux_arm="$4"; sha_linux_intel="$5"

[ -n "${version}" ] || { echo "::error::empty version" >&2; exit 1; }
[[ "${version}" =~ ^[0-9a-zA-Z.-]+$ ]] || { echo "::error::malformed version: ${version}" >&2; exit 1; }
for sha in "${sha_darwin_arm}" "${sha_darwin_intel}" "${sha_linux_arm}" "${sha_linux_intel}"; do
  [[ "${sha}" =~ ^[0-9a-f]{64}$ ]] || { echo "::error::malformed sha256: ${sha}" >&2; exit 1; }
done

cat <<EOF
class Cynative < Formula
  desc "Agentic security research across your code, cloud, and runtime (read-only)"
  homepage "https://github.com/cynative/cynative"
  version "${version}"
  license "Apache-2.0"

  on_macos do
    # cynative is built with Go 1.27, whose macOS floor is 13 (Ventura), so gate
    # installs there — unsupported hosts fail before downloading an unrunnable binary.
    # A bare symbol means ">= that release"; the ">= :ventura" string form is
    # deprecated and errors on current brew ("unknown or unsupported macOS version").
    depends_on macos: :ventura

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
