BeforeAll {
    $script:InstallDir = $env:CYN_E2E_INSTALL_DIR
    $script:Exe        = Join-Path $script:InstallDir 'cynative.exe'
    $script:ScriptPath = (Resolve-Path "$PSScriptRoot/../install.ps1").Path

    function Read-UserPath { [Environment]::GetEnvironmentVariable('Path', 'User') }

    # The `-File` invocation (the supported scripted path + the arg-bound uninstall).
    function Invoke-InstallerFile {
        param([string[]]$ExtraArgs = @())
        $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:ScriptPath @ExtraArgs 2>&1 | Out-String
        [pscustomobject]@{ Code = $LASTEXITCODE; Output = $out }
    }

    # The documented `irm <url>/install.ps1 | iex` install. Reading the local file stands
    # in for `irm`; the iex/stream invocation mode and the $MyInvocation.InvocationName the
    # dot-source guard depends on are identical whether the text came from irm or disk.
    function Invoke-InstallerIex {
        $cmd = "Get-Content -Raw -LiteralPath '$script:ScriptPath' | iex"
        $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $cmd 2>&1 | Out-String
        [pscustomobject]@{ Code = $LASTEXITCODE; Output = $out }
    }

    # The documented uninstall: & ([scriptblock]::Create((irm <url>/install.ps1))) -Uninstall
    function Invoke-UninstallScriptblock {
        $cmd = "& ([scriptblock]::Create((Get-Content -Raw -LiteralPath '$script:ScriptPath'))) -Uninstall"
        $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $cmd 2>&1 | Out-String
        [pscustomobject]@{ Code = $LASTEXITCODE; Output = $out }
    }
}

Describe 'install.ps1 end-to-end (Windows)' {
    It 'installs (-File), updates the user PATH, and the binary runs' {
        (Invoke-InstallerFile).Code | Should -Be 0
        Test-Path -LiteralPath $script:Exe | Should -BeTrue
        # Read the registry value, not $env:Path (the process env is not refreshed mid-job).
        (Read-UserPath) | Should -Match ([regex]::Escape($script:InstallDir))
        # Invoke by full path - the registry PATH write is not visible in this process.
        & $script:Exe --help | Out-Null
        $LASTEXITCODE | Should -Be 0
    }

    It 'uninstalls (-File) and prunes the PATH entry' {
        (Invoke-InstallerFile -ExtraArgs @('-Uninstall')).Code | Should -Be 0
        Test-Path -LiteralPath $script:Exe | Should -BeFalse
        ([string](Read-UserPath)) | Should -Not -Match ([regex]::Escape($script:InstallDir))
    }

    # Finding 2: exercise the documented copy-paste install/uninstall commands, whose
    # iex/scriptblock invocation modes drive the dot-source guard differently than -File.
    It 'installs via the documented irm | iex path' {
        $r = Invoke-InstallerIex
        $r.Code | Should -Be 0
        Test-Path -LiteralPath $script:Exe | Should -BeTrue
        & $script:Exe --help | Out-Null
        $LASTEXITCODE | Should -Be 0
    }

    It 'uninstalls via the documented scriptblock invocation' {
        (Invoke-UninstallScriptblock).Code | Should -Be 0
        Test-Path -LiteralPath $script:Exe | Should -BeFalse
        ([string](Read-UserPath)) | Should -Not -Match ([regex]::Escape($script:InstallDir))
    }

    # Finding 3: prove the guard FIRES (its specific error), not merely that some later
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
        $bad = Join-Path $env:CYN_E2E_STAGE 'cynative_Windows_x86_64.zip'
        Add-Content -LiteralPath $bad -Value 'corruption'
        $r = Invoke-InstallerFile
        $r.Code | Should -Not -Be 0
        $r.Output | Should -Match 'checksum mismatch'
        Test-Path -LiteralPath $script:Exe | Should -BeFalse
    }
}
