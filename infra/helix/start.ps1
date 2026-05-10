$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
$LocalHelix = Join-Path $Root "bin\helix.exe"
$Helix = if (Test-Path $LocalHelix) { $LocalHelix } else { "helix" }

if (-not (Test-Path $LocalHelix) -and -not (Get-Command helix -ErrorAction SilentlyContinue)) {
    Write-Error "Helix CLI was not found. Install it first: curl -sSL https://install.helix-db.com | bash"
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Docker CLI was not found. Start Docker Desktop or install Docker first."
}

& $Helix check dev
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

& $Helix build dev
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

docker compose -f docker-compose.yml up -d
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

docker compose -f docker-compose.yml ps
exit $LASTEXITCODE
