#!/bin/sh
# cynative installer.
#   curl -fsSL https://raw.githubusercontent.com/cynative/cynative/main/install.sh | sh
# Env: CYNATIVE_VERSION (default: latest), CYNATIVE_INSTALL_DIR (default: ~/.local/bin),
#      CYNATIVE_REQUIRE_ATTESTATION=1 (make a failed `gh attestation verify` fatal).
# For high-integrity installs, fetch this script from an immutable ref instead of `main`:
#   curl -fsSL https://raw.githubusercontent.com/cynative/cynative/<tag-or-sha>/install.sh | sh
set -eu

REPO="cynative/cynative"
BINARY="cynative"
INSTALL_DIR="${CYNATIVE_INSTALL_DIR:-${HOME}/.local/bin}"

err() { printf 'cynative-install: %s\n' "$*" >&2; exit 1; }

# Paired uninstall: `curl -fsSL .../install.sh | sh -s -- --uninstall`
if [ "${1:-}" = "--uninstall" ]; then
  target="$INSTALL_DIR/$BINARY"
  if [ -e "$target" ]; then rm -f "$target" && printf 'removed %s\n' "$target" >&2
  else printf '%s not found (nothing to remove)\n' "$target" >&2; fi
  exit 0
fi

download() { # url -> stdout
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1"
  elif command -v wget >/dev/null 2>&1; then wget -qO- "$1"
  else err "need curl or wget"; fi
}
download_to() { # url file
  if command -v curl >/dev/null 2>&1; then curl -fsSL -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else err "need curl or wget"; fi
}
sha256() { # file -> "<hex>  <file>"
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1"
  else err "need sha256sum or shasum"; fi
}

command -v uname >/dev/null 2>&1 || err "uname not found"
command -v tar >/dev/null 2>&1 || err "tar not found"
command -v mktemp >/dev/null 2>&1 || err "mktemp not found"

case "$(uname -s)" in
  Linux) OS=Linux ;;
  Darwin) OS=Darwin ;;
  *) err "unsupported OS '$(uname -s)' — see https://github.com/${REPO}/releases" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=x86_64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) err "unsupported arch '$(uname -m)' — see https://github.com/${REPO}/releases" ;;
esac

VERSION="${CYNATIVE_VERSION:-}"
if [ -z "$VERSION" ]; then
  VERSION=$(download "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
  [ -n "$VERSION" ] || err "could not resolve latest release tag"
fi

ARCHIVE="${BINARY}_${OS}_${ARCH}.tar.gz"
BASE="https://github.com/${REPO}/releases/download/${VERSION}"

tmp=$(mktemp -d) || err "mktemp failed"
trap 'rm -rf "$tmp"' EXIT INT TERM

printf 'downloading %s @ %s\n' "$ARCHIVE" "$VERSION" >&2
download_to "${BASE}/${ARCHIVE}" "$tmp/$ARCHIVE" || err "download failed: ${BASE}/${ARCHIVE}"
download_to "${BASE}/checksums.txt" "$tmp/checksums.txt" || err "download failed: ${BASE}/checksums.txt"

matches=$(awk -v f="$ARCHIVE" '$2==f {print $1}' "$tmp/checksums.txt")
count=$(printf '%s' "$matches" | grep -c . || true)
[ "$count" = "1" ] || err "expected exactly one checksum entry for ${ARCHIVE}, found ${count}"
got=$(cd "$tmp" && sha256 "$ARCHIVE" | awk '{print $1}')
[ "$matches" = "$got" ] || err "checksum mismatch: want ${matches} got ${got}"

if command -v gh >/dev/null 2>&1; then
  if gh attestation verify "$tmp/$ARCHIVE" -R "$REPO" >/dev/null 2>&1; then
    printf 'attestation verified\n' >&2
  elif [ "${CYNATIVE_REQUIRE_ATTESTATION:-0}" = "1" ]; then
    err "attestation verification failed (CYNATIVE_REQUIRE_ATTESTATION=1)"
  else
    printf 'warning: attestation not verified (continuing)\n' >&2
  fi
fi

tar -xzf "$tmp/$ARCHIVE" -C "$tmp" "$BINARY" || err "failed to extract ${BINARY}"
[ -f "$tmp/$BINARY" ] || err "${BINARY} not found in archive"
chmod +x "$tmp/$BINARY"

mkdir -p "$INSTALL_DIR" || err "cannot create ${INSTALL_DIR}"
mv "$tmp/$BINARY" "$INSTALL_DIR/.${BINARY}.tmp.$$" || err "install write failed"
mv "$INSTALL_DIR/.${BINARY}.tmp.$$" "$INSTALL_DIR/$BINARY" || err "install move failed"

printf 'installed %s %s to %s/%s\n' "$BINARY" "$VERSION" "$INSTALL_DIR" "$BINARY" >&2
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *) printf 'note: %s is not on PATH — add: export PATH="%s:$PATH"\n' "$INSTALL_DIR" "$INSTALL_DIR" >&2 ;;
esac
