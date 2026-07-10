# install-script.smoke.test.ps1 - post-release public install-script smoke (cynative#47).
#
# Windows sibling of install-script.smoke.test.sh: runs the documented public
# install path end to end under Windows PowerShell 5.1 (the floor install.ps1
# targets). Fetches install.ps1 from raw.githubusercontent.com at main (never
# the local checkout), installs the expected release from the public GitHub
# release assets, asserts the installed binary reports exactly the expected
# version and that exactly one user-PATH entry was added, uninstalls via the
# documented scriptblock path, and asserts binary and PATH entry are gone.
# NOT hermetic; deliberately no skip path. No TLS pre-configuration: the first
# irm runs before the downloaded installer sets TLS 1.2, and proving that works
# on a stock 5.1 host is part of the test.
#
# Usage: powershell -File test\install-script.smoke.test.ps1
#
# Env:
#   SMOKE_VERSION  expected version, bare, no leading v (e.g. 0.4.0). When
#                  unset, resolved from the latest published GitHub release.
#
# The suppressions are this file's point, not a smell: the documented install
# command is literally "irm ... | iex", so the alias and Invoke-Expression
# rules must stay enabled globally but not fire on this script.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '',
    Justification = 'The documented public install command is irm | iex; executing it verbatim is the test.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingCmdletAliases', '',
    Justification = 'irm and iex are the documented command text; spelling them out would test a different command.')]
param()

$ErrorActionPreference = 'Stop'

$installerUrl = 'https://raw.githubusercontent.com/cynative/cynative/main/install.ps1'
$installDir = Join-Path $env:LOCALAPPDATA 'cynative\bin'
$exe = Join-Path $installDir 'cynative.exe'

# Existence that does not follow the target: Test-Path is false for a dangling
# symlink or reparse point, which the pollution guard, the post-uninstall
# assert, and cleanup must all still see. Enumerate the parent's directory
# entries instead (the leaf contains no wildcards, so the pattern is literal).
function Test-CynSmokeEntryExists {
    param([Parameter(Mandatory)][string]$Path)
    $parent = Split-Path -Path $Path -Parent
    $leaf = Split-Path -Path $Path -Leaf
    if (-not (Test-Path -LiteralPath $parent)) { return $false }
    (@([IO.Directory]::GetFileSystemEntries($parent, $leaf)).Count -gt 0)
}

# One normalization for every PATH check, mirroring install.ps1's own rules:
# split on ';', ignore empties, trim whitespace and trailing slashes, compare
# case-insensitively.
function Get-CynSmokeNormalizedDir {
    param([Parameter(Mandatory)][string]$Dir)
    $Dir.Trim().TrimEnd('\', '/')
}
function Get-CynSmokeUserPathMatches {
    param([Parameter(Mandatory)][string]$Dir)
    $target = Get-CynSmokeNormalizedDir -Dir $Dir
    # Not named $matches: that is an automatic variable, and assigning it
    # trips PSAvoidAssignmentToAutomaticVariable.
    $found = @()
    $current = [string][Environment]::GetEnvironmentVariable('Path', 'User')
    foreach ($entry in ($current -split ';')) {
        if (-not $entry) { continue }
        if ((Get-CynSmokeNormalizedDir -Dir $entry) -ieq $target) { $found += $entry }
    }
    , $found
}

# Mutation state for the finally block: $armed flips true only once the guards
# have passed and the snapshots below are real, so a guard failure can never
# trigger a restore of never-taken snapshots (restoring a null PATH would
# delete the user PATH outright).
$armed = $false
$status = 1
$originalUserPath = $null
$originalEnv = @{}

try {
    # The intended floor is explicit: Desktop edition 5.1+ (plain 5.0 lacks
    # PSEdition and is not admitted).
    if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion -lt [Version]'5.1') {
        throw "this smoke must run under Windows PowerShell 5.1 (Desktop), got $($PSVersionTable.PSVersion) $($PSVersionTable.PSEdition)"
    }

    # Resolve the expected version: SMOKE_VERSION wins; unset resolves the
    # latest published release (fatal on fetch error or missing tag; no skip
    # path). Fail closed on an empty result: it would un-pin the install.
    $version = [string]$env:SMOKE_VERSION
    if (-not $version) {
        $release = Invoke-RestMethod -UseBasicParsing `
            -Uri 'https://api.github.com/repos/cynative/cynative/releases/latest' `
            -Headers @{ 'User-Agent' = 'cynative-smoke' }
        $version = ([string]$release.tag_name) -replace '^v', ''
    }
    if (-not $version) { throw 'could not resolve a nonempty expected version' }

    Write-Host "== SMOKE == cynative $version via the public install.ps1"

    # Pollution guard: binary and user-PATH entry must both be absent, so the
    # PATH snapshot below is known-clean and the finally restore can never
    # re-pollute.
    if (Test-CynSmokeEntryExists -Path $exe) {
        throw "$exe already exists; refusing to smoke a polluted environment (a previous failed run may have left it behind)"
    }
    if ((Get-CynSmokeUserPathMatches -Dir $installDir).Count -ne 0) {
        throw "user PATH already contains $installDir; refusing to smoke a polluted environment"
    }

    # Snapshots for the finally block: the known-clean user PATH (no [string]
    # cast: an absent value must snapshot as $null so restore removes rather
    # than writes an empty value) and the original installer env knobs, so an
    # interactive local run does not keep mutated state.
    $originalUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    foreach ($name in 'CYNATIVE_BASE_URL', 'CYNATIVE_INSTALL_DIR', 'CYNATIVE_VERSION', 'CYNATIVE_REQUIRE_ATTESTATION') {
        $originalEnv[$name] = [Environment]::GetEnvironmentVariable($name)
    }
    $armed = $true

    # Env hygiene: a run must not silently dodge the public channel or the
    # default install dir. Then pin the release (documented knob; the
    # installer's own anonymous releases/latest call risks rate-limit flakes
    # on shared runner IPs) and keep attestation advisory (GitHub produces
    # attestations asynchronously, 15-20+ minutes after publish).
    $env:CYNATIVE_BASE_URL = $null
    $env:CYNATIVE_INSTALL_DIR = $null
    $env:CYNATIVE_VERSION = "v$version"
    $env:CYNATIVE_REQUIRE_ATTESTATION = '0'

    # Install: the real documented one-liner.
    irm $installerUrl | iex

    if (-not (Test-CynSmokeEntryExists -Path $exe)) {
        throw "$exe not installed (did the installer download fail?)"
    }

    # Verify by absolute path: exit status first, then the exact first line -
    # a stale asset serving the previous release must fail loudly.
    $out = & $exe --version
    $rc = $LASTEXITCODE
    if ($rc -ne 0) { throw "$exe --version exited $rc" }
    $firstLine = [string](@($out)[0])
    if ($firstLine -ne "cynative $version") {
        throw "--version reported '$firstLine', expected 'cynative $version' (stale release asset?)"
    }

    # The installer must have added exactly one user-PATH entry (registry
    # scope: the current process PATH does not refresh).
    if ((Get-CynSmokeUserPathMatches -Dir $installDir).Count -ne 1) {
        throw "expected exactly one user-PATH entry for $installDir after install"
    }

    # Uninstall: the documented scriptblock path, then assert binary and PATH
    # entry are gone (the directory itself legitimately remains).
    & ([scriptblock]::Create((irm $installerUrl))) -Uninstall
    if (Test-CynSmokeEntryExists -Path $exe) { throw "$exe still present after uninstall" }
    if ((Get-CynSmokeUserPathMatches -Dir $installDir).Count -ne 0) {
        throw "user PATH still contains $installDir after uninstall"
    }

    $status = 0
    Write-Host "install-script.smoke: OK (cynative $version installed, verified, uninstalled)"
} catch {
    Write-Host "FAIL: $($_.Exception.Message)"
} finally {
    # Best-effort, nonfatal cleanup that preserves the primary outcome. Each
    # piece has independent error handling so one failure cannot skip the
    # rest. On a green run these are no-ops or restore-to-identical; the env
    # restore also keeps an interactive session unmutated.
    if ($armed) {
        try {
            if (Test-CynSmokeEntryExists -Path $exe) {
                Remove-Item -LiteralPath $exe -Force -ErrorAction SilentlyContinue
            }
        } catch { Write-Host "warning: cleanup could not remove ${exe}: $($_.Exception.Message)" }
        try {
            [Environment]::SetEnvironmentVariable('Path', $originalUserPath, 'User')
        } catch { Write-Host "warning: cleanup could not restore the user PATH: $($_.Exception.Message)" }
        foreach ($name in $originalEnv.Keys) {
            try {
                [Environment]::SetEnvironmentVariable($name, $originalEnv[$name])
            } catch { Write-Host "warning: cleanup could not restore ${name}: $($_.Exception.Message)" }
        }
    }
}

exit $status
