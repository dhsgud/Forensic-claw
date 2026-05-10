$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
$LocalHelix = Join-Path $Root "bin\helix.exe"
$Helix = if (Test-Path $LocalHelix) { $LocalHelix } else { "helix" }

if (-not (Test-Path $LocalHelix) -and -not (Get-Command helix -ErrorAction SilentlyContinue)) {
    Write-Error "Helix CLI was not found."
}

& $Helix stop dev
exit $LASTEXITCODE
