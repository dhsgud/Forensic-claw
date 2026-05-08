param(
    [switch] $InstallDeps,
    [switch] $Clean,
    [string] $Python
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$specPath = Join-Path $repoRoot "packaging\windows\forensic-claw.spec"
$distDir = Join-Path $repoRoot "dist\windows\Forensic-Claw"

function Resolve-PythonCommand {
    param([string] $RequestedPython)

    if ($RequestedPython) {
        return $RequestedPython
    }

    $venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
    if (Test-Path $venvPython) {
        return $venvPython
    }

    return "python"
}

$pythonCommand = Resolve-PythonCommand $Python

function Install-PythonBuildDependencies {
    param([string] $PythonCommand)

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $PythonCommand -m pip --version *> $null
    $pipExitCode = $LASTEXITCODE
    $ErrorActionPreference = $previousErrorActionPreference

    if ($pipExitCode -eq 0) {
        & $PythonCommand -m pip install -e ".[build]"
        return $LASTEXITCODE
    }

    $ErrorActionPreference = "Continue"
    & $PythonCommand -m ensurepip --upgrade *> $null
    $ensurePipExitCode = $LASTEXITCODE
    & $PythonCommand -m pip --version *> $null
    $pipExitCode = $LASTEXITCODE
    $ErrorActionPreference = $previousErrorActionPreference
    if ($ensurePipExitCode -eq 0 -and $pipExitCode -eq 0) {
        & $PythonCommand -m pip install -e ".[build]"
        return $LASTEXITCODE
    }

    $uvCommand = Get-Command "uv" -ErrorAction SilentlyContinue
    if ($uvCommand) {
        & $uvCommand.Source pip install --python $PythonCommand -e ".[build]"
        return $LASTEXITCODE
    }

    Write-Error "pip is not available for $PythonCommand, and uv was not found."
    return 1
}

Push-Location $repoRoot
try {
    if ($Clean -and (Test-Path $distDir)) {
        Remove-Item -LiteralPath $distDir -Recurse -Force
    }

    if ($InstallDeps) {
        Install-PythonBuildDependencies $pythonCommand
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to install build dependencies."
        }
    }

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $pythonCommand -c "import PyInstaller" *> $null
    $pyInstallerImportExitCode = $LASTEXITCODE
    $ErrorActionPreference = $previousErrorActionPreference
    if ($pyInstallerImportExitCode -ne 0) {
        throw "PyInstaller is not installed. Run: .\scripts\build-windows-exe.ps1 -InstallDeps"
    }

    $args = @(
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--distpath",
        (Join-Path $repoRoot "dist\windows"),
        "--workpath",
        (Join-Path $repoRoot "build\pyinstaller")
    )
    if ($Clean) {
        $args += "--clean"
    }
    $args += $specPath

    & $pythonCommand @args
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller build failed."
    }

    if (-not (Test-Path (Join-Path $distDir "Forensic-Claw.exe"))) {
        throw "Expected executable was not created: $distDir"
    }

    Write-Host "EXE build ready: $distDir"
}
finally {
    Pop-Location
}
