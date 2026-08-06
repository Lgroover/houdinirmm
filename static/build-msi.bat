@echo off
REM Build HoudiniRMM Agent MSI using WiX Toolset
REM Prerequisites: WiX Toolset installed, candle.exe and light.exe in PATH

echo Building HoudiniRMM Agent MSI...

REM Generate GUIDs
set GUID_UPGRADE=YOUR-UPGRADE-GUID
set GUID_COMPONENT=YOUR-COMPONENT-GUID

REM Compile .wxs to .wixobj
candle.exe houdinirmm-agent.wxs -ext WixUtilExtension -out houdinirmm-agent.wixobj
if %ERRORLEVEL% NEQ 0 goto :error

REM Link .wixobj to .msi
light.exe houdinirmm-agent.wixobj -ext WixUtilExtension -out houdinirmm-agent.msi
if %ERRORLEVEL% NEQ 0 goto :error

echo SUCCESS: houdinirmm-agent.msi created
goto :end

:error
echo FAILED: Check errors above
exit /b 1

:end
