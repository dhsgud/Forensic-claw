param(
    [switch] $DeleteData
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot

Push-Location $repoRoot
try {
    if ($DeleteData) {
        docker compose down -v
    }
    else {
        docker compose down
    }
}
finally {
    Pop-Location
}
