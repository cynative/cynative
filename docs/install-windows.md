# Installing cynative on Windows

`cynative` ships a single static `cynative.exe` (amd64 + arm64). Two install channels.

## Scoop (recommended)

```powershell
scoop bucket add cynative https://github.com/cynative/scoop-bucket
scoop install cynative
scoop update cynative      # upgrade
scoop uninstall cynative   # remove
```

The Scoop manifest pins the release archive's SHA-256, so Scoop aborts on a hash mismatch.

## Install script (irm | iex)

```powershell
irm https://raw.githubusercontent.com/cynative/cynative/main/install.ps1 | iex
```

- Installs to `%LOCALAPPDATA%\cynative\bin` (override with `$env:CYNATIVE_INSTALL_DIR`) and adds
  it to your **user** PATH — **no admin** required. Open a new terminal after first install.
- Verifies the archive SHA-256 against the release `checksums.txt`, failing closed on a
  mismatch; with `gh` installed it also checks the release attestation (set
  `$env:CYNATIVE_REQUIRE_ATTESTATION=1` to make a failed/absent attestation fatal).
- Pin a version: `$env:CYNATIVE_VERSION='v1.0.0'`.
- **High-integrity install:** fetch the script from an immutable tag, not `main`:
  `irm https://raw.githubusercontent.com/cynative/cynative/v1.0.0/install.ps1 | iex`.
- **Upgrade:** re-run the one-liner. Close any running `cynative` first — Windows locks the
  running `.exe` and the installer will tell you to close it.
- **Uninstall:**
  `& ([scriptblock]::Create((irm https://raw.githubusercontent.com/cynative/cynative/main/install.ps1))) -Uninstall`.

## Manual verification

```powershell
$v = 'v1.0.0'
irm "https://github.com/cynative/cynative/releases/download/$v/cynative_Windows_x86_64.zip" -OutFile c.zip
irm "https://github.com/cynative/cynative/releases/download/$v/checksums.txt" -OutFile checksums.txt
(Get-FileHash -Algorithm SHA256 c.zip).Hash.ToLower()   # compare to the checksums.txt line
Expand-Archive c.zip -DestinationPath .
```

## Notes

- **ExecutionPolicy / locked-down environments:** `irm | iex` runs an in-memory string, so it
  is not blocked by *file* ExecutionPolicy. It is still subject to Constrained Language Mode,
  WDAC/AppLocker, and enterprise proxy interception — in those environments, download the zip,
  verify the checksum manually (above), and place `cynative.exe` on your PATH yourself.
- **SmartScreen / antivirus:** the binary is unsigned (code signing is not yet offered), so
  SmartScreen or AV may warn on first run. Verify integrity via the checksum (and attestation)
  above before allowing it.
- **Corporate proxy:** the installer honors your system proxy settings.
- **Terminal experience:** on Windows the interactive prompt uses a basic line reader (no
  raw-mode editing or history); Ctrl-C works as expected.
