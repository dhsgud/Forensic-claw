param(
    [string] $Version,
    [switch] $SkipExeBuild,
    [switch] $InstallPythonBuildDeps,
    [string] $Python
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$sourceRoot = Join-Path $repoRoot "dist\windows\Forensic-Claw"
$installerDir = Join-Path $repoRoot "dist\installer"
$generatedDir = Join-Path $repoRoot "build\windows-installer"
$generatedWxs = Join-Path $generatedDir "Forensic-Claw.generated.wxs"
$upgradeCode = "C9865E2E-1BD1-4B1A-A1C8-6FE4C940EBC7"

function Get-ProjectVersion {
    $pyproject = Get-Content -Raw (Join-Path $repoRoot "pyproject.toml")
    if ($pyproject -match '(?m)^version\s*=\s*"([^"]+)"') {
        return $Matches[1]
    }
    return "0.0.0"
}

function Convert-ToMsiVersion {
    param([string] $RawVersion)

    $base = ($RawVersion -split "[+-]")[0]
    $base = ($base -replace "[^0-9.]", ".").Trim(".")
    $parts = @($base.Split(".", [System.StringSplitOptions]::RemoveEmptyEntries))
    while ($parts.Count -lt 3) {
        $parts += "0"
    }
    return "$($parts[0]).$($parts[1]).$($parts[2])"
}

function ConvertTo-WixId {
    param([string] $Text)

    $safe = $Text -replace "[^A-Za-z0-9_]", "_"
    if ($safe -notmatch "^[A-Za-z_]") {
        $safe = "id_$safe"
    }
    if ($safe.Length -gt 60) {
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        try {
            $hash = [System.BitConverter]::ToString(
                $sha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
            ).Replace("-", "").Substring(0, 12)
        }
        finally {
            $sha1.Dispose()
        }
        $safe = $safe.Substring(0, 47) + "_" + $hash
    }
    return $safe
}

function Escape-Xml {
    param([string] $Text)

    return [System.Security.SecurityElement]::Escape($Text)
}

function Write-DirectoryXml {
    param(
        [System.IO.DirectoryInfo] $Directory,
        [string] $DirectoryId,
        [System.Text.StringBuilder] $Builder,
        [System.Collections.Generic.List[string]] $ComponentRefs,
        [ref] $FileIndex,
        [int] $Depth
    )

    $indent = " " * $Depth
    foreach ($file in Get-ChildItem -LiteralPath $Directory.FullName -File | Sort-Object Name) {
        $currentIndex = $FileIndex.Value
        $FileIndex.Value = $currentIndex + 1
        $componentId = ConvertTo-WixId "cmp_$currentIndex`_$($file.FullName)"
        $fileId = ConvertTo-WixId "fil_$currentIndex`_$($file.Name)"
        $source = Escape-Xml $file.FullName
        [void] $Builder.AppendLine("$indent<Component Id=""$componentId"" Guid=""*"">")
        [void] $Builder.AppendLine("$indent  <File Id=""$fileId"" Source=""$source"" KeyPath=""yes"" />")
        [void] $Builder.AppendLine("$indent</Component>")
        $ComponentRefs.Add($componentId)
    }

    foreach ($child in Get-ChildItem -LiteralPath $Directory.FullName -Directory | Sort-Object Name) {
        $childId = ConvertTo-WixId "dir_$($child.FullName)"
        $childName = Escape-Xml $child.Name
        [void] $Builder.AppendLine("$indent<Directory Id=""$childId"" Name=""$childName"">")
        Write-DirectoryXml `
            -Directory $child `
            -DirectoryId $childId `
            -Builder $Builder `
            -ComponentRefs $ComponentRefs `
            -FileIndex $FileIndex `
            -Depth ($Depth + 2)
        [void] $Builder.AppendLine("$indent</Directory>")
    }
}

Push-Location $repoRoot
try {
    if (-not $SkipExeBuild) {
        $exeArgs = @()
        if ($InstallPythonBuildDeps) {
            $exeArgs += "-InstallDeps"
        }
        if ($Python) {
            $exeArgs += @("-Python", $Python)
        }
        & (Join-Path $repoRoot "scripts\build-windows-exe.ps1") @exeArgs
        if ($LASTEXITCODE -ne 0) {
            throw "EXE build failed."
        }
    }

    $exePath = Join-Path $sourceRoot "Forensic-Claw.exe"
    if (-not (Test-Path $exePath)) {
        throw "EXE output not found. Run scripts\build-windows-exe.ps1 first."
    }

    New-Item -ItemType Directory -Force -Path $installerDir, $generatedDir | Out-Null

    $rawVersion = if ($Version) { $Version } else { Get-ProjectVersion }
    $msiVersion = Convert-ToMsiVersion $rawVersion
    $msiPath = Join-Path $installerDir "Forensic-Claw-$msiVersion.msi"

    $builder = [System.Text.StringBuilder]::new()
    $componentRefs = [System.Collections.Generic.List[string]]::new()
    $fileIndex = 1
    $sourceDirectory = Get-Item $sourceRoot

    [void] $builder.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
    [void] $builder.AppendLine('<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">')
    [void] $builder.AppendLine("  <Package Name=""Forensic-Claw"" Manufacturer=""Forensic-Claw contributors"" Version=""$msiVersion"" UpgradeCode=""$upgradeCode"" Scope=""perMachine"">")
    [void] $builder.AppendLine('    <MajorUpgrade DowngradeErrorMessage="A newer version of Forensic-Claw is already installed." />')
    [void] $builder.AppendLine('    <MediaTemplate EmbedCab="yes" />')
    [void] $builder.AppendLine('    <Feature Id="MainFeature" Title="Forensic-Claw" Level="1">')
    [void] $builder.AppendLine('      <ComponentGroupRef Id="ApplicationComponents" />')
    [void] $builder.AppendLine('      <ComponentRef Id="StartMenuShortcutComponent" />')
    [void] $builder.AppendLine('    </Feature>')
    [void] $builder.AppendLine('  </Package>')
    [void] $builder.AppendLine('  <Fragment>')
    [void] $builder.AppendLine('    <StandardDirectory Id="ProgramFiles6432Folder">')
    [void] $builder.AppendLine('      <Directory Id="INSTALLFOLDER" Name="Forensic-Claw">')
    Write-DirectoryXml `
        -Directory $sourceDirectory `
        -DirectoryId "INSTALLFOLDER" `
        -Builder $builder `
        -ComponentRefs $componentRefs `
        -FileIndex ([ref] $fileIndex) `
        -Depth 8
    [void] $builder.AppendLine('      </Directory>')
    [void] $builder.AppendLine('    </StandardDirectory>')
    [void] $builder.AppendLine('    <StandardDirectory Id="ProgramMenuFolder">')
    [void] $builder.AppendLine('      <Directory Id="ApplicationProgramsFolder" Name="Forensic-Claw" />')
    [void] $builder.AppendLine('    </StandardDirectory>')
    [void] $builder.AppendLine('  </Fragment>')
    [void] $builder.AppendLine('  <Fragment>')
    [void] $builder.AppendLine('    <ComponentGroup Id="ApplicationComponents">')
    foreach ($componentId in $componentRefs) {
        [void] $builder.AppendLine("      <ComponentRef Id=""$componentId"" />")
    }
    [void] $builder.AppendLine('    </ComponentGroup>')
    [void] $builder.AppendLine('  </Fragment>')
    [void] $builder.AppendLine('  <Fragment>')
    [void] $builder.AppendLine('    <DirectoryRef Id="ApplicationProgramsFolder">')
    [void] $builder.AppendLine('      <Component Id="StartMenuShortcutComponent" Guid="*">')
    [void] $builder.AppendLine('        <Shortcut Id="StartWebUIShortcut" Name="Forensic-Claw WebUI" Description="Open Forensic-Claw Local WebUI" Target="[INSTALLFOLDER]Forensic-Claw.exe" Arguments="gateway --open-browser" WorkingDirectory="INSTALLFOLDER" />')
    [void] $builder.AppendLine('        <Shortcut Id="InfraManagerShortcut" Name="Forensic-Claw Infra Manager" Description="Prepare HelixDB graph-vector storage infrastructure" Target="[INSTALLFOLDER]Forensic-Claw.exe" Arguments="infra init" WorkingDirectory="INSTALLFOLDER" />')
    [void] $builder.AppendLine('        <RemoveFolder Id="ApplicationProgramsFolder" On="uninstall" />')
    [void] $builder.AppendLine('        <RegistryValue Root="HKCU" Key="Software\Forensic-Claw" Name="installed" Type="integer" Value="1" KeyPath="yes" />')
    [void] $builder.AppendLine('      </Component>')
    [void] $builder.AppendLine('    </DirectoryRef>')
    [void] $builder.AppendLine('  </Fragment>')
    [void] $builder.AppendLine('</Wix>')

    $builder.ToString() | Set-Content -Encoding UTF8 $generatedWxs

    $wixCommand = Get-Command "wix" -ErrorAction SilentlyContinue
    if (-not $wixCommand) {
        throw "WiX Toolset CLI was not found. Generated WiX source at $generatedWxs. Install WiX, then rerun this script. Expected command: wix build"
    }

    & $wixCommand.Source build $generatedWxs -o $msiPath
    if ($LASTEXITCODE -ne 0) {
        throw "WiX MSI build failed."
    }

    Write-Host "MSI build ready: $msiPath"
}
finally {
    Pop-Location
}
