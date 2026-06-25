# cynative installer (Windows PowerShell 5.1+).
#   irm https://raw.githubusercontent.com/cynative/cynative/main/install.ps1 | iex
# For a high-integrity install, fetch from an immutable tag instead of main:
#   irm https://raw.githubusercontent.com/cynative/cynative/v1.0.0/install.ps1 | iex
# Env: CYNATIVE_VERSION (default latest), CYNATIVE_INSTALL_DIR (default %LOCALAPPDATA%\cynative\bin),
#      CYNATIVE_REQUIRE_ATTESTATION=1 (fail closed on a failed/absent attestation check),
#      CYNATIVE_BASE_URL (download base override; https required unless loopback — for testing).
param([switch]$Uninstall)

function Resolve-CynArch {
    param(
        [string]$Wow64 = $env:PROCESSOR_ARCHITEW6432,
        [string]$Native = $env:PROCESSOR_ARCHITECTURE
    )
    $arch = if ($Wow64) { $Wow64 } else { $Native }
    switch (([string]$arch).ToUpperInvariant()) {
        'AMD64' { 'x86_64' }
        'ARM64' { 'arm64' }
        default { throw "cynative-install: unsupported architecture '$arch'" }
    }
}

function Get-CynArchiveName {
    param([Parameter(Mandatory)][string]$Arch)
    "cynative_Windows_$Arch.zip"
}

function Test-CynUrlAllowed {
    param([Parameter(Mandatory)][string]$Url)
    $uri = [uri]$Url
    if ($uri.Scheme -eq 'https') { return $true }
    # Uri.IsLoopback is true for localhost, 127.0.0.1, and ::1.
    if ($uri.Scheme -eq 'http' -and $uri.IsLoopback) { return $true }
    return $false
}

function Resolve-CynBaseUrl {
    param(
        [string]$Override = $env:CYNATIVE_BASE_URL,
        [Parameter(Mandatory)][string]$Repo,
        [Parameter(Mandatory)][string]$Version
    )
    if ($Override) {
        if (-not (Test-CynUrlAllowed -Url $Override)) {
            throw "cynative-install: CYNATIVE_BASE_URL must be https:// (or http:// on loopback for tests): '$Override'"
        }
        return $Override.TrimEnd('/')
    }
    "https://github.com/$Repo/releases/download/$Version"
}

# Run main only when executed directly (not when dot-sourced by Pester).
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-CynMain -Uninstall:$Uninstall
}
