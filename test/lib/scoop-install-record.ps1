# Dot-sourced by test/scoop.smoke.test.ps1 and test/scoop.smoke.Tests.ps1.
# Kept to Windows PowerShell 5.1 syntax.

# The path of the install record Scoop wrote into an app's version directory, or
# $null when there is none. Scoop 0.6.0 renamed install.json to
# scoop-install.json (ScoopInstaller/Scoop#6732) so it no longer overwrites a
# file an app ships, and its readers fall back to the old name for older
# installs. The new name wins when both exist, matching Scoop's own readers.
function Get-CynSmokeScoopInstallRecord {
    param([Parameter(Mandatory)][string]$Dir)
    foreach ($name in @('scoop-install.json', 'install.json')) {
        $candidate = Join-Path $Dir $name
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return $null
}
