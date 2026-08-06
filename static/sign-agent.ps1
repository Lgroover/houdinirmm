<#
.SYNOPSIS
    Sign the HoudiniRMM agent EXE with a code signing certificate.
.DESCRIPTION
    Uses signtool.exe (Windows SDK) to sign the embedded EXE.
.PARAMETER ExePath
    Path to the agent EXE to sign.
.PARAMETER CertPath
    Path to .pfx or .p12 certificate file.
.PARAMETER CertPassword
    Certificate password (optional — prompts if not provided).
.PARAMETER Timestamp
    Timestamp server URL. Default: http://timestamp.digicert.com
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$ExePath,
    [Parameter(Mandatory=$true)]
    [string]$CertPath,
    [string]$CertPassword,
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$signtool = Get-ChildItem -Path "C:\Program Files*\Windows Kits\*\bin\*\x64\signtool.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $signtool) {
    $signtool = Get-ChildItem -Path "C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
}
if (-not $signtool) {
    Write-Host "signtool.exe not found. Install Windows SDK from:" -ForegroundColor Red
    Write-Host "https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path $ExePath)) { Write-Host "EXE not found: $ExePath" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $CertPath)) { Write-Host "Certificate not found: $CertPath" -ForegroundColor Red; exit 1 }

if (-not $CertPassword) {
    $sec = Read-Host "Certificate password" -AsSecureString
    $CertPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
}

Write-Host "Signing: $ExePath" -ForegroundColor Cyan
$args = @("sign", "/f", $CertPath, "/p", $CertPassword, "/tr", $TimestampUrl, "/td", "SHA256", "/fd", "SHA256", $ExePath)
& $signtool.FullName $args

if ($LASTEXITCODE -eq 0) {
    Write-Host "Signed successfully." -ForegroundColor Green
} else {
    Write-Host "Signing failed. Exit code: $LASTEXITCODE" -ForegroundColor Red
}
