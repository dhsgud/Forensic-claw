$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

docker compose -f docker-compose.yml ps
exit $LASTEXITCODE
