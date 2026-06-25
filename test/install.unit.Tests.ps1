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
