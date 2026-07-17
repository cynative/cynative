# cynative installer (Windows PowerShell 5.1+).
#   irm https://raw.githubusercontent.com/cynative/cynative/main/install.ps1 | iex
# For a high-integrity install, fetch from an immutable tag instead of main:
#   irm https://raw.githubusercontent.com/cynative/cynative/v1.0.0/install.ps1 | iex
# Env: CYNATIVE_VERSION (default latest), CYNATIVE_INSTALL_DIR (default %LOCALAPPDATA%\cynative\bin),
#      CYNATIVE_REQUIRE_ATTESTATION=1 (fail closed on a failed/absent attestation check),
#      CYNATIVE_BASE_URL (download base override; https required unless loopback - for testing).
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

function Get-CynExpectedHash {
    param(
        [Parameter(Mandatory)][string]$ChecksumsText,
        [Parameter(Mandatory)][string]$ArchiveName
    )
    $found = @()
    foreach ($line in ($ChecksumsText -split "`n")) {
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        $parts = $trimmed -split '\s+', 2          # "<hash><whitespace><filename>"
        if ($parts.Count -eq 2 -and $parts[1].Trim() -eq $ArchiveName) {
            $found += $parts[0].Trim()
        }
    }
    if ($found.Count -ne 1) {
        throw "cynative-install: expected exactly one checksum entry for $ArchiveName, found $($found.Count)"
    }
    $found[0]
}

function Test-CynHashMatch {
    param(
        [Parameter(Mandatory)][string]$Expected,
        [Parameter(Mandatory)][string]$Actual
    )
    $Expected.Trim() -ieq $Actual.Trim()
}

function Get-CynNormalizedDir {
    param([Parameter(Mandatory)][string]$Dir)
    $Dir.Trim().TrimEnd('\', '/')
}

function Test-CynPathContains {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$PathValue,
        [Parameter(Mandatory)][string]$Dir
    )
    $target = Get-CynNormalizedDir -Dir $Dir
    foreach ($entry in ($PathValue -split ';')) {
        if (-not $entry) { continue }
        if ((Get-CynNormalizedDir -Dir $entry) -ieq $target) { return $true }
    }
    return $false
}

function Add-CynPathEntry {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$PathValue,
        [Parameter(Mandatory)][string]$Dir
    )
    if (Test-CynPathContains -PathValue $PathValue -Dir $Dir) { return $PathValue }
    if ([string]::IsNullOrEmpty($PathValue)) { return $Dir }
    ($PathValue.TrimEnd(';') + ';' + $Dir)
}

function Remove-CynPathEntry {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$PathValue,
        [Parameter(Mandatory)][string]$Dir
    )
    $target = Get-CynNormalizedDir -Dir $Dir
    $kept = foreach ($entry in ($PathValue -split ';')) {
        if (-not $entry) { continue }
        if ((Get-CynNormalizedDir -Dir $entry) -ieq $target) { continue }
        $entry
    }
    ($kept -join ';')
}

function Resolve-CynAttestationAction {
    param(
        [Parameter(Mandatory)][bool]$GhAvailable,
        [Parameter(Mandatory)][bool]$Required
    )
    if ($GhAvailable) { return 'verify' }
    if ($Required) { return 'fail' }
    return 'skip'
}

function Get-CynString {
    param([Parameter(Mandatory)][string]$Url)
    $content = (Invoke-WebRequest -UseBasicParsing -Uri $Url -Headers @{ 'User-Agent' = 'cynative-install' }).Content
    # Windows PowerShell 5.1 returns .Content as a byte[] when the response Content-Type is not
    # text. GitHub serves every release asset - checksums.txt included - as
    # application/octet-stream, so decode a byte[] body here to hand callers a string always.
    if ($content -is [byte[]]) { return [System.Text.Encoding]::UTF8.GetString($content) }
    [string]$content
}

function Save-CynFile {
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$Path)
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Path -Headers @{ 'User-Agent' = 'cynative-install' }
}

function New-CynTempDir {
    $p = Join-Path ([IO.Path]::GetTempPath()) ('cynative-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $p | Out-Null
    $p
}

function Get-CynLatestVersion {
    param([Parameter(Mandatory)][string]$Repo)
    $tag = (Get-CynString -Url "https://api.github.com/repos/$Repo/releases/latest" | ConvertFrom-Json).tag_name
    if (-not $tag) { throw 'cynative-install: could not resolve latest release tag' }
    $tag
}

function Invoke-CynAttestation {
    param([string]$Repo, [string]$Version, [string]$ArchivePath)
    $gh = [bool](Get-Command gh -ErrorAction SilentlyContinue)
    $required = ($env:CYNATIVE_REQUIRE_ATTESTATION -eq '1')
    switch (Resolve-CynAttestationAction -GhAvailable $gh -Required $required) {
        'fail' { throw 'cynative-install: CYNATIVE_REQUIRE_ATTESTATION=1 but gh is not installed' }
        'skip' { return }
        'verify' {
            # gh may be installed but unusable (not authenticated, or no GH_TOKEN in CI).
            # Under $ErrorActionPreference='Stop', a native command's stderr becomes a
            # terminating error on Windows PowerShell 5.1, so soften it here: a gh failure
            # must degrade to a warning (or a fail when required), never abort the install
            # on its own. Read the exit code to decide.
            $prevEA = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try { & gh release verify-asset $Version $ArchivePath --repo $Repo 2>&1 | Out-Null }
            finally { $ErrorActionPreference = $prevEA }
            if ($LASTEXITCODE -eq 0) { Write-Host 'attestation verified' }
            elseif ($required) { throw 'cynative-install: attestation verification failed (CYNATIVE_REQUIRE_ATTESTATION=1)' }
            else { Write-Host 'warning: attestation not verified (continuing)' }
        }
    }
}

function Install-CynBinary {
    param([string]$Src, [string]$InstallDir, [string]$Binary)
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $dest = Join-Path $InstallDir $Binary
    $stage = Join-Path $InstallDir ('.' + $Binary + '.tmp.' + $PID)
    Copy-Item -LiteralPath $Src -Destination $stage -Force
    try {
        Move-Item -LiteralPath $stage -Destination $dest -Force
    } catch {
        # A locked target (running cynative.exe) surfaces as IOException OR
        # UnauthorizedAccessException OR a PS-wrapped error depending on the share mode,
        # so catch broadly and keep the underlying message for diagnostics.
        Remove-Item -LiteralPath $stage -Force -ErrorAction SilentlyContinue
        throw "cynative-install: could not replace $dest - close any running cynative and re-run ($($_.Exception.Message))"
    }
}

function Add-CynToUserPath {
    param([string]$Dir)
    $current = [string][Environment]::GetEnvironmentVariable('Path', 'User')
    if (Test-CynPathContains -PathValue $current -Dir $Dir) { return }
    [Environment]::SetEnvironmentVariable('Path', (Add-CynPathEntry -PathValue $current -Dir $Dir), 'User')
    Write-Host "added $Dir to your user PATH - open a new terminal for it to take effect"
}

function Remove-CynFromUserPath {
    param([string]$Dir)
    $current = [string][Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not (Test-CynPathContains -PathValue $current -Dir $Dir)) { return }
    [Environment]::SetEnvironmentVariable('Path', (Remove-CynPathEntry -PathValue $current -Dir $Dir), 'User')
    Write-Host "removed $Dir from your user PATH"
}

function Invoke-CynInstall {
    param([string]$Repo, [string]$Binary, [string]$InstallDir)
    $arch = Resolve-CynArch
    $archive = Get-CynArchiveName -Arch $arch
    $version = if ($env:CYNATIVE_VERSION) { $env:CYNATIVE_VERSION } else { Get-CynLatestVersion -Repo $Repo }
    $base = Resolve-CynBaseUrl -Repo $Repo -Version $version
    Write-Host "downloading $archive @ $version"
    $tmp = New-CynTempDir
    try {
        $archivePath = Join-Path $tmp $archive
        Save-CynFile -Url "$base/$archive" -Path $archivePath
        $expected = Get-CynExpectedHash -ChecksumsText (Get-CynString -Url "$base/checksums.txt") -ArchiveName $archive
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash
        if (-not (Test-CynHashMatch -Expected $expected -Actual $actual)) {
            throw "cynative-install: checksum mismatch for $archive (want $expected got $actual)"
        }
        Invoke-CynAttestation -Repo $Repo -Version $version -ArchivePath $archivePath
        Expand-Archive -LiteralPath $archivePath -DestinationPath $tmp -Force
        Install-CynBinary -Src (Join-Path $tmp $Binary) -InstallDir $InstallDir -Binary $Binary
        Add-CynToUserPath -Dir $InstallDir
        Write-Host "installed cynative $version to $InstallDir\$Binary"
    } finally {
        Remove-Item -Recurse -Force -LiteralPath $tmp -ErrorAction SilentlyContinue
    }
}

function Invoke-CynUninstall {
    param([string]$InstallDir, [string]$Binary)
    $dest = Join-Path $InstallDir $Binary
    if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force; Write-Host "removed $dest" }
    else { Write-Host "$dest not found (nothing to remove)" }
    Remove-CynFromUserPath -Dir $InstallDir
}

function Invoke-CynMain {
    param([switch]$Uninstall)
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue'
    $ErrorActionPreference = 'Stop'

    $repo = 'cynative/cynative'
    $binary = 'cynative.exe'
    $installDir = if ($env:CYNATIVE_INSTALL_DIR) { $env:CYNATIVE_INSTALL_DIR } `
                  else { Join-Path $env:LOCALAPPDATA 'cynative\bin' }

    if ($Uninstall) { Invoke-CynUninstall -InstallDir $installDir -Binary $binary }
    else { Invoke-CynInstall -Repo $repo -Binary $binary -InstallDir $installDir }
}

# Run main only when executed directly (not when dot-sourced by Pester).
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-CynMain -Uninstall:$Uninstall
}
