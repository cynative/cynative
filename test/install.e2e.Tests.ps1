BeforeAll {
    $script:InstallDir = $env:CYN_E2E_INSTALL_DIR
    $script:Exe        = Join-Path $script:InstallDir 'cynative.exe'
    $script:ScriptPath = "$PSScriptRoot/../install.ps1"
    function Read-UserPath { [Environment]::GetEnvironmentVariable('Path', 'User') }
    function Run-Installer {
        param([string[]]$ExtraArgs = @())
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:ScriptPath @ExtraArgs
        return $LASTEXITCODE
    }
}

Describe 'install.ps1 end-to-end (Windows)' {
    It 'installs the binary, updates the user PATH, and the binary runs' {
        (Run-Installer) | Should -Be 0
        Test-Path -LiteralPath $script:Exe | Should -BeTrue
        (Read-UserPath) | Should -Match ([regex]::Escape($script:InstallDir))
        # Invoke by full path - the registry PATH write is not visible in this process.
        & $script:Exe --help | Out-Null
        $LASTEXITCODE | Should -Be 0
    }

    It 'uninstalls the binary and prunes the PATH entry' {
        (Run-Installer -ExtraArgs @('-Uninstall')) | Should -Be 0
        Test-Path -LiteralPath $script:Exe | Should -BeFalse
        ([string](Read-UserPath)) | Should -Not -Match ([regex]::Escape($script:InstallDir))
    }

    # NOTE: Pester 5 runs It blocks in file order. This block mutates the shared staged
    # archive, so it must stay AFTER the install/uninstall blocks (which need a valid zip)
    # and BEFORE only the base-URL block (which aborts before any download).
    It 'aborts on a checksum mismatch (corrupted archive)' {
        $bad = Join-Path $env:CYN_E2E_STAGE 'cynative_Windows_x86_64.zip'
        Add-Content -LiteralPath $bad -Value 'corruption'   # invalidate the SHA-256
        (Run-Installer) | Should -Not -Be 0
        Test-Path -LiteralPath $script:Exe | Should -BeFalse
    }

    It 'rejects a non-loopback http base URL before downloading' {
        $prev = $env:CYNATIVE_BASE_URL
        try {
            $env:CYNATIVE_BASE_URL = 'http://example.com/dl'
            (Run-Installer) | Should -Not -Be 0
        } finally { $env:CYNATIVE_BASE_URL = $prev }
    }
}
