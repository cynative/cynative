# Hermetic coverage of the scoop smoke's install-record lookup. Scoop 0.6.0
# renamed install.json to scoop-install.json (ScoopInstaller/Scoop#6732), so the
# smoke reads the new name first and the old one second. Runs under pwsh 7 via
# `make pwsh-test`; the smoke itself needs a real Scoop and runs post-release.
BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    . (Join-Path $script:repoRoot 'test/lib/scoop-install-record.ps1')
}

Describe 'Get-CynSmokeScoopInstallRecord' {
    BeforeEach {
        $script:dir = Join-Path ([System.IO.Path]::GetTempPath()) ("cyn-scoop-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $script:dir | Out-Null
    }
    AfterEach {
        Remove-Item -LiteralPath $script:dir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'returns scoop-install.json when only the new name exists' {
        Set-Content -LiteralPath (Join-Path $script:dir 'scoop-install.json') -Value '{}'
        Get-CynSmokeScoopInstallRecord -Dir $script:dir | Should -Be (Join-Path $script:dir 'scoop-install.json')
    }

    It 'falls back to install.json for an older Scoop' {
        Set-Content -LiteralPath (Join-Path $script:dir 'install.json') -Value '{}'
        Get-CynSmokeScoopInstallRecord -Dir $script:dir | Should -Be (Join-Path $script:dir 'install.json')
    }

    It 'prefers scoop-install.json when both exist' {
        Set-Content -LiteralPath (Join-Path $script:dir 'scoop-install.json') -Value '{}'
        Set-Content -LiteralPath (Join-Path $script:dir 'install.json') -Value '{}'
        Get-CynSmokeScoopInstallRecord -Dir $script:dir | Should -Be (Join-Path $script:dir 'scoop-install.json')
    }

    It 'returns nothing when neither exists' {
        Get-CynSmokeScoopInstallRecord -Dir $script:dir | Should -BeNullOrEmpty
    }
}
