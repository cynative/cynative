#!/usr/bin/env bash
# Install the dependabot-tracked macOS-packaging toolchain on Linux.
#   rcodesign  — version pinned in tools/rcodesign/Cargo.toml (dependabot: cargo)
#   bomutils   — third_party/bomutils submodule              (dependabot: gitsubmodule)
#   xar        — third_party/xar submodule                   (dependabot: gitsubmodule)
# Idempotent per tool (skips any tool already on PATH); the apt build-deps step always runs. Installs to ${PKGTOOLS_PREFIX:-/usr/local}/bin.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
bindir="${PKGTOOLS_PREFIX:-/usr/local}/bin"
work="$(mktemp -d)"; trap 'rm -rf "${work}"' EXIT

rcodesign_version() {
  sed -n 's/.*apple-codesign[[:space:]]*=[[:space:]]*"=\{0,1\}\([0-9][0-9.]*\)".*/\1/p' \
    "${repo}/tools/rcodesign/Cargo.toml" | head -1
}

install_build_deps() {
  sudo apt-get update
  sudo apt-get install -y build-essential autoconf automake libtool pkg-config \
    libxml2-dev libssl-dev zlib1g-dev git curl
}

install_rcodesign() {
  local v; v="$(rcodesign_version)"
  [ -n "${v}" ] || { echo "::error::could not read apple-codesign version from Cargo.toml" >&2; exit 1; }
  if command -v rcodesign >/dev/null 2>&1 && rcodesign --version 2>/dev/null | grep -q "${v}"; then
    echo "rcodesign ${v} already present"; return
  fi
  local asset="apple-codesign-${v}-x86_64-unknown-linux-musl"
  local base="https://github.com/indygreg/apple-platform-rs/releases/download/apple-codesign/${v}"
  curl -fsSL "${base}/${asset}.tar.gz" -o "${work}/rc.tar.gz"
  # Integrity: verify against the upstream-published per-asset checksum (fail closed).
  if curl -fsSL "${base}/${asset}.tar.gz.sha256" -o "${work}/rc.sha256"; then
    echo "$(cut -d' ' -f1 "${work}/rc.sha256")  ${work}/rc.tar.gz" | sha256sum -c -
  else
    curl -fsSL "${base}/SHA256SUMS" -o "${work}/SHA256SUMS"
    ( cd "${work}" && grep "  ${asset}.tar.gz\$" SHA256SUMS | sha256sum -c - )
  fi
  tar -xzf "${work}/rc.tar.gz" -C "${work}"
  sudo install -m 0755 "${work}/${asset}/rcodesign" "${bindir}/rcodesign"
  rcodesign --version
}

install_bomutils() {
  command -v mkbom >/dev/null 2>&1 && { echo "mkbom already present"; return; }
  [ -e "${repo}/third_party/bomutils/Makefile" ] \
    || { echo "::error::third_party/bomutils submodule not checked out (git submodule update --init)" >&2; exit 1; }
  cp -a "${repo}/third_party/bomutils" "${work}/bomutils"   # build a copy; leave the submodule pristine
  make -C "${work}/bomutils"
  sudo make -C "${work}/bomutils" install
  command -v mkbom
}

install_xar() {
  command -v xar >/dev/null 2>&1 && { echo "xar already present"; return; }
  [ -d "${repo}/third_party/xar/xar" ] \
    || { echo "::error::third_party/xar submodule not checked out (git submodule update --init)" >&2; exit 1; }
  cp -a "${repo}/third_party/xar/xar" "${work}/xar"
  # OpenSSL 3 removed OpenSSL_add_all_ciphers; repoint the libcrypto probe (no-op if already fixed upstream).
  sed -i 's/OpenSSL_add_all_ciphers/CRYPTO_free/' "${work}/xar/configure.ac"
  ( cd "${work}/xar" && autoconf && ./configure && make && sudo make install )
  sudo ldconfig 2>/dev/null || true
  command -v xar
}

install_build_deps
install_rcodesign
install_bomutils
install_xar
echo "OK: $(rcodesign --version); mkbom=$(command -v mkbom); xar=$(xar --version 2>&1 | head -1)"
