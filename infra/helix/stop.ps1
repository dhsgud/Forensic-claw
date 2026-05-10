param(
    [switch] $DeleteData
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

docker compose -f docker-compose.yml down
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

if ($DeleteData) {
    $Volume = Join-Path $Root ".helix\.volumes\dev"
    if (Test-Path $Volume) {
        Remove-Item -LiteralPath $Volume -Recurse -Force
    }
}
