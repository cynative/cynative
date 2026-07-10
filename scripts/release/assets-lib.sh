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
