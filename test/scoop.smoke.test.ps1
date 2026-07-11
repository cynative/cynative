# scoop.smoke.test.ps1 - post-release Scoop install smoke (cynative#46).
#
# Scoop sibling of homebrew.smoke.test.sh: proves the public Scoop channel end
# to end under Windows PowerShell 5.1 (scoop's documented floor). Adds the
# public bucket via the documented `scoop bucket add cynative
# https://github.com/cynative/scoop-bucket` (a preexisting local clone is
# validated and refreshed instead), rechecks the manifest serves the expected
# version, installs via the documented `scoop install cynative` (scoop's own
# fail-closed SHA-256 check runs inside), asserts the install came from the
# cynative bucket and that `cynative --version` reports exactly the expected
# version, uninstalls via `scoop uninstall cynative`, and asserts shims, app
# dir, and command resolution are all gone. Catches public-channel drift: a
# stale or inconsistent bucket, a manifest/asset hash mismatch, an
# uninstallable zip. NOT hermetic: talks to the public scoop-bucket repo and
# the public GitHub release assets. Deliberately no skip path (no legitimate
# "not configured" state). Scoop itself is a prerequisite, never installed or
# removed here (in CI the workflow's bootstrap step provides it). A local run
# leaves the cynative bucket added; `scoop bucket rm cynative` removes it.
#
# Usage: powershell -File test\scoop.smoke.test.ps1
#
# Env:
#   SMOKE_VERSION  expected version, bare, no leading v (e.g. 0.4.0). When
#                  unset (or whitespace), resolved from the latest published
#                  GitHub release.
#   SCOOP          scoop root override, honored for every path this script
#                  derives (shims, apps, buckets); default %USERPROFILE%\scoop.

$ErrorActionPreference = 'Stop'

$bucketUrl = 'https://github.com/cynative/scoop-bucket'

# Existence that does not follow the target: Test-Path is false for a dangling
# symlink or reparse point, which the pollution guards, the post-uninstall
# asserts, and cleanup must all still see. Enumerate the parent's directory
# entries instead (the leaf contains no wildcards, so the pattern is literal).
function Test-CynSmokeEntryExists {
    param([Parameter(Mandatory)][string]$Path)
    $parent = Split-Path -Path $Path -Parent
    $leaf = Split-Path -Path $Path -Leaf
    if (-not (Test-Path -LiteralPath $parent)) { return $false }
    (@([IO.Directory]::GetFileSystemEntries($parent, $leaf)).Count -gt 0)
}

# Run scoop out of process in an explicit Windows PowerShell (Desktop) child:
# in-process, `scoop` resolves to the scoop.ps1 shim, where a code path that
# never calls `exit` leaves $LASTEXITCODE stale and this script's Stop
# preference could alter scoop's internal error handling; scoop's .cmd shim
# prefers pwsh when available, which would silently lift the 5.1 floor this
# smoke exists to prove. A fresh powershell.exe -File run always yields the
# real process exit code under Desktop 5.1 ($PSHOME is the 5.1 home here, the
# floor gate below guarantees it). The command text stays the documented one.
function Invoke-CynSmokeScoop {
    param([Parameter(Mandatory)][string[]]$Arguments)
    & (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass `
        -File $script:scoopPs1 @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "scoop $($Arguments -join ' ') exited $LASTEXITCODE"
    }
}

# Mutation state for the finally block: $armed flips true only once the
# pollution guards have passed, so a guard failure can never trigger cleanup
# of artifacts this run does not own; $installSucceeded gates whether a
# bucket added by this run counts as the documented leave-in-place state or
# as failed-run residue.
$armed = $false
$status = 1
$bucketPreexisted = $false
$installSucceeded = $false

try {
    # The intended floor is explicit: Desktop edition 5.1+ (plain 5.0 lacks
    # PSEdition and is not admitted).
    if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion -lt [Version]'5.1') {
        throw "this smoke must run under Windows PowerShell 5.1 (Desktop), got $($PSVersionTable.PSVersion) $($PSVersionTable.PSEdition)"
    }

    # Prereqs, hard FAILs (no skip path): installing scoop is out of scope
    # here, and scoop buckets hard-require git.
    if (-not (Get-Command scoop -ErrorAction SilentlyContinue)) {
        throw 'scoop not found (https://scoop.sh; in CI the workflow bootstrap step installs it)'
    }
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        throw 'git not found (scoop buckets require git: https://git-scm.com)'
    }

    # Resolve the expected version: SMOKE_VERSION wins when nonempty after a
    # trim; unset, empty, or whitespace-only resolves the latest published
    # release (the siblings' contract; fatal on fetch error or missing tag;
    # no skip path). Fail closed on an empty result: it would un-pin the
    # release under test. tag_name is probed strictly, never cast: 5.1's
    # JSON handling can coerce wrong-shaped values into plausible strings.
    $version = ([string]$env:SMOKE_VERSION).Trim()
    if (-not $version) {
        $release = Invoke-RestMethod -UseBasicParsing `
            -Uri 'https://api.github.com/repos/cynative/cynative/releases/latest' `
            -Headers @{ 'User-Agent' = 'cynative-smoke' }
        $tagName = $null
        if ($null -ne $release -and $release.PSObject.Properties['tag_name']) {
            $tagName = $release.PSObject.Properties['tag_name'].Value
        }
        if ($tagName -isnot [string] -or [string]::IsNullOrWhiteSpace($tagName)) {
            throw 'releases/latest returned no usable tag_name'
        }
        $version = ($tagName -replace '^v', '').Trim()
    }
    if (-not $version) { throw 'could not resolve a nonempty expected version' }

    Write-Host "== SMOKE == cynative $version via scoop"

    # Effective paths: the CI bootstrap exports the resolved root as SCOOP;
    # locally scoop's own default applies. Everything below derives from the
    # root, so a custom root is honored consistently.
    $scoopRoot = [string]$env:SCOOP
    if (-not $scoopRoot) { $scoopRoot = Join-Path $env:USERPROFILE 'scoop' }
    $shimsDir = Join-Path $scoopRoot 'shims'
    $script:scoopPs1 = Join-Path $shimsDir 'scoop.ps1'
    if (-not (Test-Path -LiteralPath $script:scoopPs1)) {
        throw "$($script:scoopPs1) not found (scoop root mismatch? set SCOOP to the real root)"
    }
    $appDir = Join-Path $scoopRoot 'apps\cynative'
    $bucketDir = Join-Path $scoopRoot 'buckets\cynative'
    $shims = @('cynative.exe', 'cynative.shim', 'cynative.cmd', 'cynative.ps1') |
        ForEach-Object { Join-Path $shimsDir $_ }

    # Pollution guards: any preexisting cynative artifact would make every
    # later assertion lie; refuse to run rather than clean up state this run
    # does not own.
    foreach ($shim in $shims) {
        if (Test-CynSmokeEntryExists -Path $shim) {
            throw "$shim already exists; refusing to smoke a polluted environment (a previous failed run may have left it behind: scoop uninstall cynative)"
        }
    }
    if (Test-CynSmokeEntryExists -Path $appDir) {
        throw "$appDir already exists; refusing to smoke a polluted environment (scoop uninstall cynative removes it)"
    }
    $preexisting = Get-Command cynative -ErrorAction SilentlyContinue
    if ($preexisting) {
        throw "cynative already resolvable at $($preexisting.Source); refusing to smoke a polluted environment"
    }
    $bucketPreexisted = Test-Path -LiteralPath $bucketDir
    $armed = $true

    if ($bucketPreexisted) {
        # A local re-run: refresh the existing clone instead of failing the
        # non-idempotent `scoop bucket add`, but only if it provably IS the
        # public bucket in a clean state - a dirty edit or a local branch
        # ahead of origin must not masquerade as public channel state.
        $origin = ([string](git -C $bucketDir remote get-url origin)).Trim()
        if ($LASTEXITCODE -ne 0) { throw "git remote get-url origin exited $LASTEXITCODE for $bucketDir" }
        if ($origin -ne $bucketUrl -and $origin -ne "$bucketUrl.git") {
            throw "existing bucket at $bucketDir has origin '$origin', expected $bucketUrl; refusing to touch an unrelated clone"
        }
        $dirty = git -C $bucketDir status --porcelain
        if ($LASTEXITCODE -ne 0) { throw "git status --porcelain exited $LASTEXITCODE for $bucketDir" }
        if ($dirty) {
            throw "existing bucket at $bucketDir has local modifications; refusing to smoke a polluted bucket"
        }
        git -C $bucketDir pull --ff-only --quiet
        if ($LASTEXITCODE -ne 0) {
            throw "could not refresh the existing bucket at $bucketDir (git pull --ff-only exited $LASTEXITCODE)"
        }
        $head = ([string](git -C $bucketDir rev-parse HEAD)).Trim()
        if ($LASTEXITCODE -ne 0) { throw "git rev-parse HEAD exited $LASTEXITCODE for $bucketDir" }
        $remoteTip = ([string](git -C $bucketDir rev-parse origin/main)).Trim()
        if ($LASTEXITCODE -ne 0) { throw "git rev-parse origin/main exited $LASTEXITCODE for $bucketDir" }
        if ($head -ne $remoteTip) {
            throw "existing bucket HEAD $head != origin/main $remoteTip after refresh; refusing to smoke non-public bucket state"
        }
    } else {
        # The documented command, verbatim.
        Invoke-CynSmokeScoop -Arguments @('bucket', 'add', 'cynative', $bucketUrl)
    }

    # Recheck the local manifest immediately before install (the bucket can
    # move between the workflow's resolve-job wait and this step): distinct
    # diagnostics per failure shape, and the version must be a nonempty JSON
    # string - a wrong-typed value is invalid, never stringified into the
    # mismatch report.
    $manifestPath = Join-Path $bucketDir 'bucket\cynative.json'
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        throw "bucket manifest missing: $manifestPath"
    }
    $manifestRaw = Get-Content -LiteralPath $manifestPath -Raw
    # Top-level type gate on the raw text: 5.1's ConvertFrom-Json pipeline
    # unrolls a singleton array, so [{"version":...}] would otherwise pass
    # the property probe below.
    if ($manifestRaw -notmatch '^\s*\{') {
        throw "bucket manifest ${manifestPath}: top-level JSON value is not an object"
    }
    try {
        $manifest = $manifestRaw | ConvertFrom-Json
    } catch {
        throw "bucket manifest ${manifestPath} is unparseable: $($_.Exception.Message)"
    }
    $bucketVersion = $null
    if ($null -ne $manifest -and $manifest.PSObject.Properties['version']) {
        $bucketVersion = $manifest.PSObject.Properties['version'].Value
    }
    if ($bucketVersion -isnot [string] -or -not $bucketVersion) {
        throw "bucket manifest ${manifestPath}: version is not a nonempty string"
    }
    if ($bucketVersion -cne $version) {
        throw "bucket serves $bucketVersion, expected $version (bucket lagging or racing a release?)"
    }

    # Install: the documented command, verbatim (unqualified). Scoop's
    # fail-closed hash verification runs inside.
    Invoke-CynSmokeScoop -Arguments @('install', 'cynative')
    $installSucceeded = $true

    # Provenance: the unqualified name must have resolved from the cynative
    # bucket. Only a polluted local machine with a same-named app in another
    # bucket could violate this (the fresh runner has just main + cynative),
    # but green-lighting the wrong channel would defeat the smoke.
    $installJsonPath = Join-Path $appDir 'current\install.json'
    if (-not (Test-Path -LiteralPath $installJsonPath)) {
        throw "install metadata missing: $installJsonPath"
    }
    $installRaw = Get-Content -LiteralPath $installJsonPath -Raw
    if ($installRaw -notmatch '^\s*\{') {
        throw "install metadata ${installJsonPath}: top-level JSON value is not an object"
    }
    $installMeta = $installRaw | ConvertFrom-Json
    $installBucket = $null
    if ($null -ne $installMeta -and $installMeta.PSObject.Properties['bucket']) {
        $installBucket = $installMeta.PSObject.Properties['bucket'].Value
    }
    if ($installBucket -isnot [string] -or $installBucket -cne 'cynative') {
        throw "installed app came from bucket '$installBucket', expected 'cynative'"
    }

    # Verify by absolute shim path: exit status first, then the exact first
    # line - a stale bucket or asset serving the previous release must fail
    # loudly (prefix/substring false positives are a known trap).
    $exe = Join-Path $shimsDir 'cynative.exe'
    if (-not (Test-CynSmokeEntryExists -Path $exe)) {
        throw "$exe not created by scoop install"
    }
    $out = & $exe --version
    $rc = $LASTEXITCODE
    if ($rc -ne 0) { throw "$exe --version exited $rc" }
    $firstLine = [string](@($out)[0])
    if ($firstLine -cne "cynative $version") {
        throw "--version reported '$firstLine', expected 'cynative $version' (stale bucket or release asset?)"
    }

    # Uninstall: a nonzero exit is a real failure, but zero proves nothing
    # (scoop uninstall exits 0 even for an app that is not installed), so the
    # gone-asserts carry the weight: every shim, the app dir, and command
    # resolution must all be gone.
    Invoke-CynSmokeScoop -Arguments @('uninstall', 'cynative')
    foreach ($shim in $shims) {
        if (Test-CynSmokeEntryExists -Path $shim) { throw "$shim still present after uninstall" }
    }
    if (Test-CynSmokeEntryExists -Path $appDir) { throw "$appDir still present after uninstall" }
    if (Get-Command cynative -ErrorAction SilentlyContinue) {
        throw 'cynative still resolvable after uninstall'
    }

    Write-Host "scoop.smoke: OK (cynative $version installed, verified, uninstalled)"
    $status = 0
} catch {
    Write-Host "FAIL: $($_.Exception.Message)"
} finally {
    # Best-effort, nonfatal cleanup that preserves the primary outcome. Each
    # piece has independent error handling so one failure cannot skip the
    # rest. On a green run these are no-ops.
    if ($armed) {
        try {
            $leftover = @($shims | Where-Object { Test-CynSmokeEntryExists -Path $_ })
            if (Test-CynSmokeEntryExists -Path $appDir) { $leftover += $appDir }
            if ($leftover.Count -gt 0) {
                & (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass `
                    -File $script:scoopPs1 uninstall cynative
                if ($LASTEXITCODE -ne 0) { Write-Host "warning: cleanup scoop uninstall exited $LASTEXITCODE" }
            }
        } catch { Write-Host "warning: cleanup uninstall failed: $($_.Exception.Message)" }
        try {
            foreach ($p in ($shims + $appDir)) {
                if (Test-CynSmokeEntryExists -Path $p) { Write-Host "warning: residual left behind: $p (remove manually)" }
            }
        } catch { Write-Host "warning: cleanup re-enumeration failed: $($_.Exception.Message)" }
        try {
            # A bucket this run added but never successfully installed from
            # is failed-run residue, not the documented leave-in-place state;
            # remove it. Any run that reached a successful install leaves the
            # bucket, mirroring brew leaving the tap.
            if (-not $bucketPreexisted -and -not $installSucceeded -and (Test-Path -LiteralPath $bucketDir)) {
                & (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass `
                    -File $script:scoopPs1 bucket rm cynative
                if ($LASTEXITCODE -ne 0) { Write-Host "warning: cleanup scoop bucket rm exited $LASTEXITCODE" }
            }
        } catch { Write-Host "warning: cleanup bucket rm failed: $($_.Exception.Message)" }
    }
}

exit $status
