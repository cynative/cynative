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

    # Snapshot the user PATH so the leak guard below can prove it is byte-identical
    # at teardown: both fail-closed tests throw before Add-CynToUserPath runs.
    $script:userPathBefore = [Environment]::GetEnvironmentVariable('Path', 'User')

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

    # Capture the fixture server's stdout/stderr so a startup failure is diagnosable
    # in CI instead of an opaque throw.
    $script:srvOut = Join-Path $script:tmp 'fixture.out'
    $script:srvErr = Join-Path $script:tmp 'fixture.err'
    function Show-CynFixtureOutput {
        foreach ($f in $script:srvOut, $script:srvErr) {
            if ((Test-Path $f) -and (Get-Item $f).Length -gt 0) {
                Write-Host "---- $(Split-Path -Leaf $f) ----"
                Write-Host (Get-Content -Raw -LiteralPath $f)
            }
        }
    }

    # Launch the loopback fixture and read its portfile with a bounded poll.
    # serve-fixture.py opens the portfile before it writes the port, so a bare
    # Test-Path can read an empty file: wait until the trimmed content is a
    # nonempty integer port, still aborting early if the server exits.
    $portFile = Join-Path $script:tmp 'port'
    $script:server = Start-Process -FilePath 'python3' `
        -ArgumentList @((Join-Path $script:repoRoot 'test/serve-fixture.py'), $script:srv, $portFile) `
        -PassThru -NoNewWindow `
        -RedirectStandardOutput $script:srvOut -RedirectStandardError $script:srvErr
    $deadline = (Get-Date).AddSeconds(30)
    $port = $null
    while ((Get-Date) -lt $deadline) {
        if ($script:server.HasExited) {
            Show-CynFixtureOutput
            throw "fixture server exited early (code $($script:server.ExitCode))"
        }
        if (Test-Path $portFile) {
            $raw = (Get-Content -Raw -LiteralPath $portFile -ErrorAction SilentlyContinue)
            if ($raw) {
                $trimmed = $raw.Trim()
                if ($trimmed -match '^\d+$') { $port = $trimmed; break }
            }
        }
        Start-Sleep -Milliseconds 200
    }
    if (-not $port) {
        Show-CynFixtureOutput
        throw 'fixture server did not write a valid port in time'
    }
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

    It 'leaves the user PATH unchanged (no user-PATH leak)' {
        # Both tests above fail closed before Add-CynToUserPath, so the user PATH
        # must be byte-identical to the BeforeAll snapshot; guards a future regression.
        [Environment]::GetEnvironmentVariable('Path', 'User') | Should -BeExactly $script:userPathBefore
    }
}

AfterAll {
    if ($script:server -and -not $script:server.HasExited) {
        $script:server | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    foreach ($f in $script:srvOut, $script:srvErr) {
        if ($f -and (Test-Path $f)) { Remove-Item -Force $f -ErrorAction SilentlyContinue }
    }
    foreach ($k in $script:saved.Keys) { [Environment]::SetEnvironmentVariable($k, $script:saved[$k]) }
    if ($script:tmp -and (Test-Path $script:tmp)) {
        Remove-Item -Recurse -Force $script:tmp -ErrorAction SilentlyContinue
    }
}
