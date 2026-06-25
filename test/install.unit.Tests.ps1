BeforeAll {
    . "$PSScriptRoot/../install.ps1"
}

Describe 'Resolve-CynArch' {
    It 'maps AMD64 to x86_64' {
        Resolve-CynArch -Wow64 '' -Native 'AMD64' | Should -Be 'x86_64'
    }
    It 'maps ARM64 to arm64' {
        Resolve-CynArch -Wow64 '' -Native 'ARM64' | Should -Be 'arm64'
    }
    It 'prefers the WOW64 var (32-bit shell on 64-bit OS)' {
        Resolve-CynArch -Wow64 'AMD64' -Native 'x86' | Should -Be 'x86_64'
    }
    It 'throws on an unsupported arch' {
        { Resolve-CynArch -Wow64 '' -Native 'x86' } | Should -Throw
    }
}

Describe 'Get-CynArchiveName' {
    It 'builds the GoReleaser archive name' {
        Get-CynArchiveName -Arch 'x86_64' | Should -Be 'cynative_Windows_x86_64.zip'
    }
}

Describe 'Test-CynUrlAllowed' {
    It 'allows https' { Test-CynUrlAllowed -Url 'https://example.com/x' | Should -BeTrue }
    It 'allows http on loopback' { Test-CynUrlAllowed -Url 'http://127.0.0.1:8000/x' | Should -BeTrue }
    It 'allows http on localhost' { Test-CynUrlAllowed -Url 'http://localhost:8000/x' | Should -BeTrue }
    It 'rejects http on a public host' { Test-CynUrlAllowed -Url 'http://evil.example/x' | Should -BeFalse }
}

Describe 'Resolve-CynBaseUrl' {
    It 'defaults to the GitHub releases download URL' {
        Resolve-CynBaseUrl -Override '' -Repo 'cynative/cynative' -Version 'v1.0.0' |
            Should -Be 'https://github.com/cynative/cynative/releases/download/v1.0.0'
    }
    It 'accepts an https override and strips the trailing slash' {
        Resolve-CynBaseUrl -Override 'https://mirror.example/dl/' -Repo 'r' -Version 'v' |
            Should -Be 'https://mirror.example/dl'
    }
    It 'accepts a loopback http override (test seam)' {
        Resolve-CynBaseUrl -Override 'http://127.0.0.1:8000' -Repo 'r' -Version 'v' |
            Should -Be 'http://127.0.0.1:8000'
    }
    It 'rejects a non-loopback http override' {
        { Resolve-CynBaseUrl -Override 'http://evil.example' -Repo 'r' -Version 'v' } | Should -Throw
    }
}

Describe 'Get-CynExpectedHash' {
    # Pester 5 separates discovery from run: fixtures must be set in BeforeAll, not the
    # Describe body, or they are undefined inside It during the run phase.
    BeforeAll {
        $checksums = @"
aaaa1111  cynative_Windows_arm64.zip
bbbb2222  cynative_Windows_x86_64.zip
cccc3333  cynative_Linux_x86_64.tar.gz
"@
    }
    It 'returns the single matching hash' {
        Get-CynExpectedHash -ChecksumsText $checksums -ArchiveName 'cynative_Windows_x86_64.zip' |
            Should -Be 'bbbb2222'
    }
    It 'throws when there is no entry' {
        { Get-CynExpectedHash -ChecksumsText $checksums -ArchiveName 'nope.zip' } | Should -Throw
    }
    It 'throws when there is more than one entry' {
        $dup = "h1  a.zip`nh2  a.zip"
        { Get-CynExpectedHash -ChecksumsText $dup -ArchiveName 'a.zip' } | Should -Throw
    }
}

Describe 'Test-CynHashMatch' {
    It 'is case-insensitive' { Test-CynHashMatch -Expected 'ABCD' -Actual 'abcd' | Should -BeTrue }
    It 'rejects a mismatch' { Test-CynHashMatch -Expected 'abcd' -Actual 'ef01' | Should -BeFalse }
}
