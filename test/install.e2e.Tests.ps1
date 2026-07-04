# Windows installer end-to-end test (issue #42), run under Windows PowerShell 5.1 (the
# supported floor for install.ps1). It installs the real goreleaser release zip served from
# a loopback fixture, verifies cynative.exe --version, uninstalls, and proves the
# checksum-mismatch path fails closed. Driven by env from the CI job:
#   CYN_E2E_INSTALL_DIR   where the installer puts cynative.exe (== CYNATIVE_INSTALL_DIR)
#   CYN_E2E_STAGE         the served fixture dir (the checksum test corrupts the zip here)
#   CYN_E2E_WANT_VERSION  the version goreleaser stamped (asserted by --version)
#   CYNATIVE_BASE_URL     the loopback fixture base (set by the job from the server port)
# ASCII-only: Windows PowerShell 5.1 handles UTF-8-without-BOM poorly.
BeforeAll {
    $script:InstallDir = $env:CYN_E2E_INSTALL_DIR
    $script:Exe        = Join-Path $script:InstallDir 'cynative.exe'
    $script:ScriptPath = (Resolve-Path "$PSScriptRoot/../install.ps1").Path
    # Double any single quote so the path is safe inside a single-quoted -Command literal.
    $script:ScriptPathQ = $script:ScriptPath.Replace("'", "''")

    # Dot-source install.ps1 for its arch/name helpers only. The dot-source guard
    # (InvocationName -ne '.') keeps this from running the installer, so this just imports
    # the functions - the real installs below run it in fresh child processes. Deriving the
    # archive name (instead of hardcoding) keeps the test correct if the runner arch changes.
    . $script:ScriptPath
    $script:Archive = Get-CynArchiveName -Arch (Resolve-CynArch)

    # The expected first line of --version. Strip a leading 'v' (goreleaser stamps the
    # snapshot version without one, but normalize defensively) so the assertion is exact.
    $raw = [string]$env:CYN_E2E_WANT_VERSION
    $script:WantVersion = if ($raw.StartsWith('v')) { $raw.Substring(1) } else { $raw }

    function Read-UserPath { [Environment]::GetEnvironmentVariable('Path', 'User') }

    # Snapshot the user PATH so AfterAll can restore it: the installer mutates the user PATH
    # on install/uninstall, and a mid-suite failure must not leak that change to the runner.
    $script:OrigUserPath = Read-UserPath

    # Run a child powershell.exe and capture its exit code + combined output. Force
    # 'Continue' around the call: under the caller's Stop preference, a child stderr line
    # (an installer throw, or gh noise on the runner) would otherwise be raised as a
    # terminating NativeCommandError on Windows PowerShell 5.1 before we could capture it.
    # With Continue it lands in $out as text, so assertions can inspect it.
    function Invoke-Child {
        param([Parameter(Mandatory)][string[]]$PsArgs)
        $prevEA = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass @PsArgs 2>&1 | Out-String
        } finally {
            $ErrorActionPreference = $prevEA
        }
        [pscustomobject]@{ Code = $LASTEXITCODE; Output = $out }
    }

    # The -File invocation (the supported scripted path + the arg-bound uninstall).
    function Invoke-InstallerFile {
        param([string[]]$ExtraArgs = @())
        Invoke-Child -PsArgs (@('-File', $script:ScriptPath) + $ExtraArgs)
    }

    # The documented `irm <url>/install.ps1 | iex` install. Reading the local file stands in
    # for irm; the iex/stream invocation mode and the $MyInvocation.InvocationName the
    # dot-source guard depends on are identical whether the text came from irm or disk.
    function Invoke-InstallerIex {
        Invoke-Child -PsArgs @('-Command', "Get-Content -Raw -LiteralPath '$script:ScriptPathQ' | iex")
    }

    # The documented uninstall: & ([scriptblock]::Create((irm <url>/install.ps1))) -Uninstall
    function Invoke-UninstallScriptblock {
        Invoke-Child -PsArgs @('-Command', "& ([scriptblock]::Create((Get-Content -Raw -LiteralPath '$script:ScriptPathQ'))) -Uninstall")
    }

    # Assert cynative.exe runs and reports the version goreleaser stamped (the first line of
    # --version, `cynative <version>`). Proves both "the binary runs" and "it is the right
    # build", superseding the old --help-only check.
    function Test-CynInstalledVersion {
        $out = & $script:Exe --version 2>&1
        $LASTEXITCODE | Should -Be 0
        (@($out)[0]) | Should -Be "cynative $script:WantVersion"
    }
}

AfterAll {
    # Restore the user PATH captured before the suite mutated it (a null value removes the
    # var, matching a runner that started without a user PATH).
    [Environment]::SetEnvironmentVariable('Path', $script:OrigUserPath, 'User')
}

Describe 'install.ps1 end-to-end (Windows)' {
    It 'installs (-File), updates the user PATH, and reports the stamped version' {
        (Invoke-InstallerFile).Code | Should -Be 0
        Test-Path -LiteralPath $script:Exe | Should -BeTrue
        # Read the registry value, not $env:Path (the process env is not refreshed mid-job).
        (Read-UserPath) | Should -Match ([regex]::Escape($script:InstallDir))
        Test-CynInstalledVersion
    }

    It 'uninstalls (-File) and prunes the PATH entry' {
        (Invoke-InstallerFile -ExtraArgs @('-Uninstall')).Code | Should -Be 0
        Test-Path -LiteralPath $script:Exe | Should -BeFalse
        ([string](Read-UserPath)) | Should -Not -Match ([regex]::Escape($script:InstallDir))
    }

    # Exercise the documented copy-paste install/uninstall commands, whose iex/scriptblock
    # invocation modes drive the dot-source guard differently than -File - the likeliest
    # place a Windows PowerShell 5.1 installer regression hides.
    It 'installs via the documented irm | iex path' {
        $r = Invoke-InstallerIex
        $r.Code | Should -Be 0
        Test-Path -LiteralPath $script:Exe | Should -BeTrue
        (Read-UserPath) | Should -Match ([regex]::Escape($script:InstallDir))
        Test-CynInstalledVersion
    }

    It 'uninstalls via the documented scriptblock invocation' {
        (Invoke-UninstallScriptblock).Code | Should -Be 0
        Test-Path -LiteralPath $script:Exe | Should -BeFalse
        ([string](Read-UserPath)) | Should -Not -Match ([regex]::Escape($script:InstallDir))
    }

    # Prove the guard FIRES (its specific error), not merely that some later
    # download/checksum step failed. Runs on a still-valid staged archive (before the
    # corruption block), so a generic failure cannot masquerade as a guard rejection.
    It 'rejects a non-loopback http base URL with the guard error, before downloading' {
        $prev = $env:CYNATIVE_BASE_URL
        try {
            $env:CYNATIVE_BASE_URL = 'http://example.com/dl'
            $r = Invoke-InstallerFile
            $r.Code | Should -Not -Be 0
            $r.Output | Should -Match 'CYNATIVE_BASE_URL must be https'
            Test-Path -LiteralPath $script:Exe | Should -BeFalse
        } finally { $env:CYNATIVE_BASE_URL = $prev }
    }

    # LAST: this mutates the shared staged archive (invalidating its SHA-256). No block
    # after it may depend on a valid archive.
    It 'aborts on a checksum mismatch (corrupted archive)' {
        $bad = Join-Path $env:CYN_E2E_STAGE $script:Archive
        Add-Content -LiteralPath $bad -Value 'corruption'
        $r = Invoke-InstallerFile
        $r.Code | Should -Not -Be 0
        $r.Output | Should -Match 'checksum mismatch'
        Test-Path -LiteralPath $script:Exe | Should -BeFalse
    }
}
