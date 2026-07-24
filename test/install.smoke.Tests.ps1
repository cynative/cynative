# Hermetic wired coverage of install.ps1 fail-closed paths (checksum mismatch,
# non-loopback URL reject) driven under pwsh 7 against a loopback fixture.
# Runs on the Ubuntu CI runner via `make pwsh-test`, so it sets Windows-installer
# prerequisites explicitly and pins CYNATIVE_VERSION to avoid a live API call.
BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    . (Join-Path $script:repoRoot 'install.ps1')   # dot-source (guard skips main)

    $script:saved = @{}
    foreach ($k in 'PROCESSOR_ARCHITECTURE', 'PROCESSOR_ARCHITEW6432', 'CYNATIVE_VERSION',
        'CYNATIVE_REQUIRE_ATTESTATION', 'CYNATIVE_BASE_URL', 'CYNATIVE_INSTALL_DIR') {
        $script:saved[$k] = [Environment]::GetEnvironmentVariable($k)
    }
    $env:PROCESSOR_ARCHITECTURE = 'AMD64'
    $env:PROCESSOR_ARCHITEW6432 = ''
    $env:CYNATIVE_VERSION = 'v9.9.9'
    $env:CYNATIVE_REQUIRE_ATTESTATION = '0'

    $script:tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("cyn-smoke-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $script:tmp | Out-Null
    $script:srv = Join-Path $script:tmp 'srv'
    $script:bin = Join-Path $script:tmp 'bin'
    New-Item -ItemType Directory -Path $script:srv, $script:bin | Out-Null
    $env:CYNATIVE_INSTALL_DIR = $script:bin

    # Stage a fake archive + matching checksums.txt (arch resolved above).
    $arch = Resolve-CynArch
    $script:archive = Get-CynArchiveName -Arch $arch
    [IO.File]::WriteAllText((Join-Path $script:srv $script:archive), 'fake-archive-bytes')
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $script:srv $script:archive)).Hash.ToLower()
    [IO.File]::WriteAllText((Join-Path $script:srv 'checksums.txt'), "$hash  $script:archive`n")

    # Launch the loopback fixture and read its portfile with a bounded poll.
    $portFile = Join-Path $script:tmp 'port'
    $script:server = Start-Process -FilePath 'python3' `
        -ArgumentList @((Join-Path $script:repoRoot 'test/serve-fixture.py'), $script:srv, $portFile) `
        -PassThru -NoNewWindow
    $deadline = (Get-Date).AddSeconds(30)
    while (-not (Test-Path $portFile) -and (Get-Date) -lt $deadline) {
        if ($script:server.HasExited) { throw "fixture server exited early (code $($script:server.ExitCode))" }
        Start-Sleep -Milliseconds 200
    }
    if (-not (Test-Path $portFile)) { throw 'fixture server did not write a portfile in time' }
    $port = (Get-Content -Raw $portFile).Trim()
    $script:baseUrl = "http://127.0.0.1:$port"
}

Describe 'install.ps1 fail-closed wiring' {
    It 'rejects a non-loopback http base URL before downloading' {
        $env:CYNATIVE_BASE_URL = 'http://example.com/dl'
        { Invoke-CynInstall -Repo 'cynative/cynative' -Binary 'cynative.exe' -InstallDir $script:bin } |
            Should -Throw -ExpectedMessage '*must be https*'
        (Test-Path (Join-Path $script:bin 'cynative.exe')) | Should -BeFalse
    }

    It 'aborts on a checksum mismatch and writes no binary' {
        $env:CYNATIVE_BASE_URL = $script:baseUrl
        Add-Content -LiteralPath (Join-Path $script:srv $script:archive) -Value 'tamper'  # sha now diverges
        { Invoke-CynInstall -Repo 'cynative/cynative' -Binary 'cynative.exe' -InstallDir $script:bin } |
            Should -Throw -ExpectedMessage '*checksum mismatch*'
        (Test-Path (Join-Path $script:bin 'cynative.exe')) | Should -BeFalse
    }
}

AfterAll {
    if ($script:server -and -not $script:server.HasExited) {
        $script:server | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    foreach ($k in $script:saved.Keys) { [Environment]::SetEnvironmentVariable($k, $script:saved[$k]) }
    if ($script:tmp -and (Test-Path $script:tmp)) {
        Remove-Item -Recurse -Force $script:tmp -ErrorAction SilentlyContinue
    }
}
