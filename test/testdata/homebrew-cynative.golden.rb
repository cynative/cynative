class Cynative < Formula
  desc "Agentic security research across your code, cloud, and runtime (read-only)"
  homepage "https://github.com/cynative/cynative"
  license "Apache-2.0"

  on_macos do
    # cynative is built with Go 1.26, whose macOS floor is 12 (Monterey), so gate
    # installs there — unsupported hosts fail before downloading an unrunnable binary.
    # A bare symbol means ">= that release"; the ">= :monterey" string form is
    # deprecated and errors on current brew ("unknown or unsupported macOS version").
    depends_on macos: :monterey

    on_arm do
      url "https://github.com/cynative/cynative/releases/download/v1.5.1/cynative_Darwin_arm64.tar.gz"
      sha256 "5c712baad9179d576da1f8cff632b840b4b03495fd565a79fea8fe1a2b8b6be1"
    end

    on_intel do
      url "https://github.com/cynative/cynative/releases/download/v1.5.1/cynative_Darwin_x86_64.tar.gz"
      sha256 "1321513cd9c9a8bd117c0ec1986845daf9face1ccdc35441b2b1910e50ce7be8"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/cynative/cynative/releases/download/v1.5.1/cynative_Linux_arm64.tar.gz"
      sha256 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    end

    on_intel do
      url "https://github.com/cynative/cynative/releases/download/v1.5.1/cynative_Linux_x86_64.tar.gz"
      sha256 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    end
  end

  def install
    bin.install "cynative"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/cynative --version")
  end
end
