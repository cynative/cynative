# macOS `.pkg` — pipeline overview and maintainer manual-test checklist

Every release ships a signed, notarized and **stapled** flat `.pkg` installer for
each Darwin architecture (`arm64`, `x86_64`). This document explains how the
pipeline produces those packages and how a maintainer verifies them on a real Mac
before a release is considered good.

---

## Pipeline overview

### 1. Binary signing (goreleaser post-build hook)

The goreleaser build runs the post-build hook
`scripts/release/sign-darwin-binary.sh` once per Darwin target. The hook:

- Uses **rcodesign** to sign the Mach-O with the **Developer ID Application**
  certificate from `MACOS_SIGN_P12_FILE`/`MACOS_SIGN_PASSWORD_FILE`.
- Applies the entitlements at `.goreleaser/entitlements.plist` (hardened runtime
  + `allow-jit` + `allow-unsigned-executable-memory`).
- Verifies the `RUNTIME` flag and both JIT entitlements before replacing the
  original binary.
- The signed bytes go into **both** the `cynative_Darwin_*.tar.gz` archive and
  the `.pkg` — the tarball binary is byte-for-byte identical to what is packaged.

### 2. Post-goreleaser: assemble, sign, notarize and staple

After goreleaser finishes, the "Build, sign, notarize & staple macOS pkgs" CI
step runs `scripts/release/assemble-macos-pkg.sh` + `scripts/release/sign-notarize-pkg.sh`
for each architecture pair (`arm64` → `cynative_Darwin_arm64.pkg`,
`amd64`/`x86_64` → `cynative_Darwin_x86_64.pkg`):

1. **Assemble** (`assemble-macos-pkg.sh`): builds a flat `.pkg` on Linux using
   the `third_party/` toolchain (bomutils `mkbom` + `xar`). The payload is a
   deterministic `cpio` (odc format, root:wheel ownership, gzip). PackageInfo
   and Distribution are rendered from `scripts/release/templates/` with
   `@IDENTIFIER@` = `com.cynative.cynative` and `@VERSION@` set to the release
   version.

2. **Sign** (`sign-notarize-pkg.sh`): signs the assembled `.pkg` with the
   **Developer ID Installer** certificate from
   `MACOS_INSTALLER_P12_FILE`/`MACOS_INSTALLER_PASSWORD_FILE` via rcodesign.

3. **Notarize + staple**: submits the signed `.pkg` to Apple's notary service
   via `rcodesign notary-submit --staple`, using the App Store Connect API key
   (`MACOS_NOTARY_API_KEY_JSON`, assembled from `MACOS_NOTARY_ISSUER_ID`/`MACOS_NOTARY_KEY_ID`/`MACOS_NOTARY_KEY` via `rcodesign encode-app-store-connect-api-key`).
   Only the `.pkg` is submitted to the notary — the byte-identical tarball
   binary passes Gatekeeper's online check via the registered cdhash.

4. **Assertion**: `scripts/release/assert-pkg.sh` and
   `scripts/release/assert-binary-equivalence.sh` verify the notarized `.pkg`
   and confirm the binary inside it is identical to the tarball binary.

Both `.pkg` files are then uploaded to the GitHub release draft.

### Binary-equivalence invariant

`assert-binary-equivalence.sh` confirms that the signed binary in the tarball,
the raw goreleaser dist binary, and the binary extracted from the `.pkg` are all
byte-identical. This means the notarized cdhash registered with Apple also covers
the tarball binary — a quarantined tarball binary's first terminal use is
Gatekeeper-clean via the online cdhash check. Only a quarantined tarball's first
**GUI** launch (e.g. double-clicking in Finder on a downloaded archive) needs
internet for that online check; terminal use, `install.sh`, and Homebrew are
unaffected.

---

## Pinned tools and how to bump them

### rcodesign

**Pin location:** `tools/rcodesign/Cargo.toml`

```toml
[dependencies]
apple-codesign = "=0.29.0"
```

**Dependabot ecosystem:** `cargo` — dependabot opens a PR bumping the version
string when a new release appears.

`scripts/release/install-pkg-tools.sh` reads the version from that file and
downloads the matching prebuilt Linux musl binary from
[`indygreg/apple-platform-rs`](https://github.com/indygreg/apple-platform-rs/releases).
The crate is not compiled in CI.

### bomutils and xar

**Pin location:** `third_party/bomutils` and `third_party/xar` (git submodules,
`.gitmodules`).

**Dependabot ecosystem:** `gitsubmodule` — dependabot opens a PR bumping the
submodule SHA when the upstream moves.

### Smoke-testing bumps before auto-merge

The `pkg-tools.yaml` CI job (`Packaging toolchain` workflow) fires on any PR that
touches `tools/rcodesign/**`, `third_party/**`, `.gitmodules`, or the packaging
scripts. It installs the full toolchain and runs a smoke assembly (unsigned pkg
from a test binary) to confirm the bump doesn't break the build.

NOTE: this job is advisory unless it is added to the branch ruleset's *required
status checks*. GitHub auto-merge only waits on the repo's configured required
checks — currently `Lint & Test` and `Validate PR title` — so a dependabot bump
could auto-merge once those pass, even if `pkg-tools.yaml` has not yet run or has
failed. To make it a hard gate on auto-merge, add the `Build & smoke-test macOS
packaging toolchain` check to the `default` ruleset's required status checks.

---

## Frozen package identifier

```
com.cynative.cynative
```

This value is baked into every `.pkg`'s `PackageInfo` (installer identifier) and
`Distribution` files via `scripts/release/templates/`. It is also the pkgutil
receipt left on the user's system after installation, and the value the Homebrew
cask uses in its `uninstall pkgutil:` stanza.

**This identifier must never change after the first public `.pkg` release.**
Changing it would leave stale receipts on existing users' machines that `brew
uninstall --cask cynative` (and `pkgutil --forget`) can no longer clean up.

---

## CI secret inventory

| Secret | Certificate type | Used by |
|---|---|---|
| `MACOS_SIGN_P12` | Developer ID Application (base64-encoded p12) | goreleaser hook — signs the darwin binary |
| `MACOS_SIGN_PASSWORD` | p12 password | goreleaser hook |
| `MACOS_INSTALLER_P12` | Developer ID Installer (base64-encoded p12) | post-goreleaser step — signs the `.pkg` |
| `MACOS_INSTALLER_PASSWORD` | p12 password | post-goreleaser step |
| `MACOS_NOTARY_ISSUER_ID` | App Store Connect notary key — issuer UUID | notarization |
| `MACOS_NOTARY_KEY_ID` | App Store Connect notary key — key ID | notarization |
| `MACOS_NOTARY_KEY` | App Store Connect notary key — private key (base64-encoded `.p8`) | notarization |

### Critical operational note: p12 format

The two p12 secrets (`MACOS_SIGN_P12`, `MACOS_INSTALLER_P12`) **must** be
**leaf-only p12s** — one certificate, no CA chain — exported with OpenSSL's
`-legacy` flag:

```bash
openssl pkcs12 -legacy -export \
  -inkey <private-key.pem> \
  -in <leaf-certificate.pem> \
  -out <out.p12>
```

Two requirements here are non-negotiable:

1. **`-legacy`**: rcodesign cannot decrypt p12s produced with OpenSSL's default
   (non-legacy) cipher suite (AES-256-CBC / SHA-256 MAC). The `-legacy` flag
   produces the RC2/SHA-1 cipher that rcodesign supports.

2. **Leaf-only (no CA chain)**: including the intermediate CA certificate in the
   p12 causes rcodesign to select the wrong certificate when signing. Export only
   the leaf Developer ID cert, not the full chain.

Both secrets are stored base64-encoded in GitHub Actions secrets. The pipeline
decodes them securely into a private temporary directory with restricted permissions:

```bash
umask 077
d="$(mktemp -d)"; trap 'rm -rf "${d}"' EXIT
printf '%s' "${SECRET}" | base64 -d > "${d}/cert.p12"
chmod 600 "${d}/cert.p12"
```

This ensures credentials are never written to a predictable global path.

---

## Maintainer manual test (Intel macOS) — per release of the `.pkg`

Run this checklist on an Intel Mac (x86\_64) for each release that ships a
`.pkg`. This confirms the full Gatekeeper chain works on the notarized installer
and validates the Homebrew cask end-to-end.

1. Download `cynative_Darwin_x86_64.pkg` from the GitHub release page.

2. Verify the installer signature and notarization ticket:
   ```bash
   pkgutil --check-signature cynative_Darwin_x86_64.pkg
   # Expected: "Status: signed by a developer certificate...
   #            Notarization: trusted"
   ```

3. Confirm Gatekeeper acceptance:
   ```bash
   spctl -a -vv -t install cynative_Darwin_x86_64.pkg
   # Expected: "accepted" and "source=Notarized Developer ID"
   ```

4. Install the package:
   ```bash
   sudo installer -pkg cynative_Darwin_x86_64.pkg -target /
   ```

5. Confirm the binary runs without a Gatekeeper prompt:
   ```bash
   which cynative && cynative --version
   # No Gatekeeper dialog; prints version, commit, date, Go version, platform.
   ```

6. Verify hardened runtime is present in the installed binary:
   ```bash
   codesign -dv --verbose=4 /usr/local/bin/cynative 2>&1 | grep -i 'runtime\|flags'
   # Expected output includes: CodeDirectory v=... flags=0x10000(runtime) ...
   ```

7. Test the Homebrew cask end-to-end (fresh install):
   ```bash
   brew install cynative/tap/cynative
   cynative --version
   brew uninstall --cask cynative
   pkgutil --pkgs | grep cynative
   # Expected: no output (receipt forgotten by the cask's pkgutil uninstall stanza).
   ```
