# archive.smoke.test.ps1 - pre-publish release-archive install smoke (cynative#43).
#
# Windows sibling of archive.smoke.test.sh: proves a built
# cynative_Windows_<arch>.zip release archive is installable under Windows
# PowerShell 5.1 (the floor install.ps1 targets): the zip bytes match the
# manifest digest the release job asserted against the draft release,
# checksums.txt describes those same bytes, Expand-Archive (the exact code
# path install.ps1 runs) can extract it, cynative.exe sits at the archive
# root, its PE machine field matches the expected architecture (Windows 11
# ARM transparently emulates x64, so execution alone cannot catch an x64 exe
# misplaced in the arm64 zip), and the binary runs and reports exactly the
# expected version. No LLM or connector coverage by design.
#
# Usage: powershell -File test\archive.smoke.test.ps1
#
# Env (all required, no fallbacks):
#   ARCHIVE_PATH     path to the .zip to smoke
#   SMOKE_VERSION    expected version, bare, no leading v (e.g. 1.5.1)
#   EXPECTED_SHA256  sha256 the zip bytes must match (as asserted against the
#                    draft release by the release job)
#   CHECKSUMS_PATH   path to the checksums.txt release asset
#   EXPECTED_ARCH    the leg's native architecture, amd64 or arm64

$ErrorActionPreference = 'Stop'

# Read the PE COFF machine field: 'MZ' magic, e_lfanew at 0x3C, 'PE\0\0'
# signature, then the UInt16 machine immediately after. Fail-closed: any
# short read or bad magic throws.
function Get-CynSmokePeMachine {
    param([Parameter(Mandatory)][string]$Path)
    $stream = [IO.File]::OpenRead($Path)
    try {
        $reader = New-Object IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw "$Path is not an executable (no MZ magic)" }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw "$Path has no PE signature at e_lfanew" }
        return $reader.ReadUInt16()
    } finally {
        $stream.Dispose()
    }
}

$status = 1
$tmp = $null
try {
    # The intended floor is explicit: Desktop edition 5.1+ (this smoke proves
    # the zip against the same Expand-Archive implementation install.ps1's
    # floor uses, so a pwsh run would prove the wrong thing).
    if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion -lt [Version]'5.1') {
        throw "this smoke must run under Windows PowerShell 5.1 (Desktop), got $($PSVersionTable.PSVersion) $($PSVersionTable.PSEdition)"
    }

    # Env contract: all required, fail closed on anything missing or malformed.
    $archivePath = $env:ARCHIVE_PATH
    if ([string]::IsNullOrWhiteSpace($archivePath)) { throw 'ARCHIVE_PATH is required' }
    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
        throw "ARCHIVE_PATH does not name a file: $archivePath"
    }
    $version = $env:SMOKE_VERSION
    if ([string]::IsNullOrWhiteSpace($version)) { throw 'SMOKE_VERSION is required' }
    if ($version -clike 'v*') { throw "SMOKE_VERSION must be bare, without a leading v: $version" }
    $expectedSha = $env:EXPECTED_SHA256
    if ($expectedSha -cnotmatch '^[0-9a-f]{64}$') {
        throw 'EXPECTED_SHA256 must be exactly 64 lowercase hex chars'
    }
    $checksumsPath = $env:CHECKSUMS_PATH
    if ([string]::IsNullOrWhiteSpace($checksumsPath)) { throw 'CHECKSUMS_PATH is required' }
    if (-not (Test-Path -LiteralPath $checksumsPath -PathType Leaf)) {
        throw "CHECKSUMS_PATH does not name a file: $checksumsPath"
    }
    # Fail-closed arch map: IMAGE_FILE_MACHINE_AMD64 / IMAGE_FILE_MACHINE_ARM64.
    $machineByArch = @{ 'amd64' = 0x8664; 'arm64' = 0xAA64 }
    $arch = $env:EXPECTED_ARCH
    if (-not $arch -or -not $machineByArch.ContainsKey($arch)) {
        throw "EXPECTED_ARCH must be amd64 or arm64, got '$arch'"
    }
    $expectedMachine = $machineByArch[$arch]

    $archiveName = Split-Path -Path $archivePath -Leaf
    Write-Host "== SMOKE == $archiveName (expecting cynative $version)"

    # Integrity: the artifact hand-off delivered the exact bytes the release
    # job asserted against the draft release.
    $actualSha = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSha -cne $expectedSha) { throw "zip sha256 $actualSha != expected $expectedSha" }

    # checksums.txt must describe these same bytes: both installers trust it,
    # and nothing else in the pipeline compares its rows to the archives.
    # Same "<hash><whitespace><filename>", exactly-one-row contract as
    # install.ps1's verifier.
    $found = @()
    foreach ($line in (Get-Content -LiteralPath $checksumsPath)) {
        $trimmed = "$line".Trim()
        if (-not $trimmed) { continue }
        $parts = $trimmed -split '\s+', 2
        if ($parts.Count -eq 2 -and $parts[1].Trim() -ceq $archiveName) { $found += $parts[0].Trim() }
    }
    if ($found.Count -ne 1) {
        throw "expected exactly one checksums.txt row for $archiveName, found $($found.Count)"
    }
    if ($found[0].ToLowerInvariant() -cne $expectedSha) {
        throw "checksums.txt digest $($found[0]) != archive digest $expectedSha"
    }

    # Fresh extraction dir; Expand-Archive (with -Force, as install.ps1 calls
    # it) is the same 5.1 implementation install.ps1 relies on, so a zip it
    # cannot read fails here first.
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('cynative-archive-smoke-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    Expand-Archive -LiteralPath $archivePath -DestinationPath $tmp -Force

    # The binary sits at the archive root under the exact name install.ps1
    # resolves.
    $exePath = Join-Path $tmp 'cynative.exe'
    if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
        throw "cynative.exe not at the archive root of $archiveName"
    }

    # Native-arch proof: Windows 11 ARM runs x64 binaries transparently, so
    # --version alone cannot catch a wrong-arch exe in the zip.
    $machine = Get-CynSmokePeMachine -Path $exePath
    if ($machine -ne $expectedMachine) {
        throw ('cynative.exe PE machine 0x{0:X4} != expected 0x{1:X4} for {2}' `
            -f $machine, $expectedMachine, $env:EXPECTED_ARCH)
    }

    # The extracted binary actually runs: absolute path, exit status first,
    # then the exact first line (a prefix match would accept 1.2.30 for
    # 1.2.3).
    $out = & $exePath --version
    $rc = $LASTEXITCODE
    if ($rc -ne 0) { throw "cynative.exe --version exited $rc" }
    $firstLine = [string](@($out)[0])
    if ($firstLine -cne "cynative $version") {
        throw "--version reported '$firstLine', expected 'cynative $version'"
    }

    Write-Host "archive.smoke: OK ($archiveName extracts, cynative $version runs)"
    $status = 0
} catch {
    Write-Host "FAIL: $($_.Exception.Message)"
} finally {
    if ($tmp -and (Test-Path -LiteralPath $tmp)) {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

exit $status
