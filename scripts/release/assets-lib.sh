# shellcheck shell=bash
# Shared helpers for the release scripts. Sourced, not executed (no shebang;
# the dialect is declared via the shellcheck directive above).

# sha_for <assets-tsv> <asset-name>: pull an asset's sha256 out of the assets
# manifest ("name<TAB>sha256<TAB>path" rows), failing closed on a missing row
# or a non-64-hex digest (never publish or audit a Formula with a bad sha256).
sha_for() {
  local assets="$1" name="$2" sha
  sha="$(awk -F'\t' -v n="${name}" '$1==n{print $2; exit}' "${assets}")"
  [[ "${sha}" =~ ^[0-9a-f]{64}$ ]] || {
    echo "::error::missing or invalid sha256 for ${name}" >&2
    return 1
  }
  printf '%s' "${sha}"
}

# sha_for_checksums <checksums-file> <asset-name>: pull an asset's sha256 out of
# a goreleaser checksums.txt ("<sha256>  <name>" rows), failing closed unless
# EXACTLY one row names the asset and its digest is 64-hex. Stricter than
# sha_for, which takes the first match: the Scoop path must reject a duplicate
# row, because Scoop verifies the manifest SHA-256 and a wrong hash bricks every
# install.
sha_for_checksums() {
  local file="$1" name="$2" sha count
  count="$(awk -v n="${name}" '$2==n{c++} END{print c+0}' "${file}")"
  if [ "${count}" -ne 1 ]; then
    echo "::error::expected exactly 1 checksum row for ${name}, found ${count}" >&2
    return 1
  fi
  sha="$(awk -v n="${name}" '$2==n{print $1; exit}' "${file}")"
  [[ "${sha}" =~ ^[0-9a-f]{64}$ ]] || {
    echo "::error::missing or invalid sha256 for ${name}" >&2
    return 1
  }
  printf '%s' "${sha}"
}
