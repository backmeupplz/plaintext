#!/usr/bin/env bash
# Prints the Homebrew formula for a release from its SHA256SUMS; the release workflow writes it to
# Formula/plaintext.rb in backmeupplz/homebrew-tap:
#   packaging/homebrew/formula.sh 0.1.0 SHA256SUMS > Formula/plaintext.rb
set -euo pipefail
version=$1
sums=$2
url=https://github.com/backmeupplz/plaintext/releases/download/v$version
sha() { awk -v f="plaintext-$1.tar.gz" '$2 == f || $2 == "*" f { print $1 }' "$sums" | grep .; }
mac_arm=$(sha aarch64-apple-darwin)
mac_intel=$(sha x86_64-apple-darwin)
linux_arm=$(sha aarch64-unknown-linux-musl)
linux_intel=$(sha x86_64-unknown-linux-musl)

cat <<RB
class Plaintext < Formula
  desc "End-to-end encrypted, self-hosted password manager: command line and MCP server"
  homepage "https://getplaintext.org"
  version "$version"
  license "MIT"

  livecheck do
    url :stable
    strategy :github_latest
  end

  on_macos do
    on_arm do
      url "$url/plaintext-aarch64-apple-darwin.tar.gz"
      sha256 "$mac_arm"
    end
    on_intel do
      url "$url/plaintext-x86_64-apple-darwin.tar.gz"
      sha256 "$mac_intel"
    end
  end

  on_linux do
    on_arm do
      url "$url/plaintext-aarch64-unknown-linux-musl.tar.gz"
      sha256 "$linux_arm"
    end
    on_intel do
      url "$url/plaintext-x86_64-unknown-linux-musl.tar.gz"
      sha256 "$linux_intel"
    end
  end

  def install
    bin.install "plaintext"
  end

  test do
    assert_equal "plaintext #{version}", shell_output("#{bin}/plaintext --version").strip
  end
end
RB
