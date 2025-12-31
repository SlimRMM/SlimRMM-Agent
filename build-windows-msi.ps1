#
# SlimRMM Agent - Windows MSI Build Script
# Copyright (c) 2025 Kiefer Networks
#
# This script builds an MSI installer for Windows
# Requirements: Python 3.9+, PyInstaller, WiX Toolset v3
#

param(
    [string]$Version = "1.0.0",
    [string]$Arch = "x64"
)

$ErrorActionPreference = "Stop"

# Configuration
$AppName = "SlimRMM Agent"
$AppIdentifier = "SlimRMM.Agent"
$Manufacturer = "Kiefer Networks"
$InstallDir = "C:\Program Files\SlimRMM"
$ServiceName = "SlimRMMAgent"

# Paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildDir = Join-Path $ScriptDir "build"
$DistDir = Join-Path $ScriptDir "dist"
$WixDir = Join-Path $BuildDir "wix"

Write-Host "================================================"
Write-Host "  SlimRMM Agent - Windows MSI Builder"
Write-Host "  Version: $Version"
Write-Host "  Architecture: $Arch"
Write-Host "================================================"
Write-Host ""

# Check for required tools
Write-Host "[1/7] Checking prerequisites..."

# Check Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python is not installed or not in PATH"
    exit 1
}

# Check PyInstaller
$pyinstallerCheck = python -c "import PyInstaller" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing PyInstaller..."
    pip install pyinstaller
}

# Check WiX Toolset
$wixPath = $null
$possibleWixPaths = @(
    "${env:WIX}bin",
    "C:\Program Files (x86)\WiX Toolset v3.11\bin",
    "C:\Program Files (x86)\WiX Toolset v3.14\bin",
    "C:\Program Files\WiX Toolset v3.11\bin",
    "C:\Program Files\WiX Toolset v3.14\bin"
)

foreach ($path in $possibleWixPaths) {
    if (Test-Path (Join-Path $path "candle.exe")) {
        $wixPath = $path
        break
    }
}

if (-not $wixPath) {
    Write-Host ""
    Write-Host "WiX Toolset not found. Please install WiX Toolset v3:"
    Write-Host "  https://wixtoolset.org/releases/"
    Write-Host ""
    Write-Host "Or install via winget:"
    Write-Host "  winget install WixToolset.WixToolset"
    Write-Host ""
    exit 1
}

Write-Host "Found WiX Toolset at: $wixPath"

# Clean previous builds
Write-Host "[2/7] Cleaning previous builds..."
if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
if (Test-Path $DistDir) { Remove-Item -Recurse -Force $DistDir }
New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
New-Item -ItemType Directory -Path $DistDir -Force | Out-Null
New-Item -ItemType Directory -Path $WixDir -Force | Out-Null

# Build the binary with PyInstaller
Write-Host "[3/7] Building agent binary..."
Set-Location $ScriptDir

# Create spec file for Windows build
$specContent = @'
# -*- mode: python ; coding: utf-8 -*-
import os
block_cipher = None

a = Analysis(
    ['agent.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('src/security', 'src/security'),
    ],
    hiddenimports=[
        'websocket',
        'requests',
        'psutil',
        'httpx',
        'src.security.mtls',
        'src.security.path_validator',
        'src.security.command_sandbox',
        'src.security.zip_handler',
        'win32serviceutil',
        'win32service',
        'win32event',
        'servicemanager',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'unittest', 'pydoc'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# Check for icon file
icon_path = 'assets/icon.ico' if os.path.exists('assets/icon.ico') else None

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='slimrmm-agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon=icon_path,
)
'@

$specContent | Out-File -FilePath "slimrmm-agent-windows.spec" -Encoding UTF8

pyinstaller --clean --noconfirm slimrmm-agent-windows.spec

if ($LASTEXITCODE -ne 0) {
    Write-Error "PyInstaller build failed"
    exit 1
}

# Create WiX source file
Write-Host "[4/7] Creating WiX installer configuration..."

# Generate unique GUIDs for this build
$ProductGuid = [guid]::NewGuid().ToString().ToUpper()
$UpgradeGuid = "E8F5C9A1-2B3D-4E5F-6A7B-8C9D0E1F2A3B"  # Fixed for upgrades

$wxsContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi"
     xmlns:util="http://schemas.microsoft.com/wix/UtilExtension">

  <Product Id="$ProductGuid"
           Name="$AppName"
           Language="1033"
           Version="$Version"
           Manufacturer="$Manufacturer"
           UpgradeCode="$UpgradeGuid">

    <Package InstallerVersion="500"
             Compressed="yes"
             InstallScope="perMachine"
             Description="$AppName v$Version"
             Manufacturer="$Manufacturer" />

    <MajorUpgrade DowngradeErrorMessage="A newer version of $AppName is already installed."
                  AllowSameVersionUpgrades="yes" />

    <MediaTemplate EmbedCab="yes" />

    <!-- Properties -->
    <Property Id="SLIMRMM_SERVER" Secure="yes" />
    <Property Id="ARPPRODUCTICON" Value="ProductIcon" />
    <Property Id="WIXUI_INSTALLDIR" Value="INSTALLFOLDER" />

    <!-- Icon -->
    <Icon Id="ProductIcon" SourceFile="$DistDir\slimrmm-agent.exe" />

    <!-- Directory Structure -->
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFiles64Folder">
        <Directory Id="INSTALLFOLDER" Name="SlimRMM">
          <Directory Id="LogFolder" Name="log" />
          <Directory Id="CertsFolder" Name="certs" />
        </Directory>
      </Directory>
    </Directory>

    <!-- Components -->
    <ComponentGroup Id="ProductComponents" Directory="INSTALLFOLDER">
      <Component Id="MainExecutable" Guid="*">
        <File Id="AgentExe"
              Source="$DistDir\slimrmm-agent.exe"
              KeyPath="yes" />

        <!-- Windows Service -->
        <ServiceInstall Id="ServiceInstaller"
                        Type="ownProcess"
                        Name="$ServiceName"
                        DisplayName="$AppName"
                        Description="SlimRMM Remote Monitoring and Management Agent"
                        Start="auto"
                        Account="LocalSystem"
                        ErrorControl="normal">
          <util:ServiceConfig FirstFailureActionType="restart"
                              SecondFailureActionType="restart"
                              ThirdFailureActionType="restart"
                              RestartServiceDelayInSeconds="60" />
        </ServiceInstall>

        <ServiceControl Id="ServiceControl"
                        Name="$ServiceName"
                        Start="install"
                        Stop="both"
                        Remove="uninstall"
                        Wait="yes" />
      </Component>

      <Component Id="LogDirectory" Guid="*">
        <CreateFolder Directory="LogFolder">
          <Permission User="SYSTEM" GenericAll="yes" />
          <Permission User="Administrators" GenericAll="yes" />
        </CreateFolder>
      </Component>

      <Component Id="CertsDirectory" Guid="*">
        <CreateFolder Directory="CertsFolder">
          <Permission User="SYSTEM" GenericAll="yes" />
          <Permission User="Administrators" GenericAll="yes" />
        </CreateFolder>
      </Component>
    </ComponentGroup>

    <!-- Custom Actions for Registration (mTLS based - no installation key required) -->
    <CustomAction Id="SetRegistrationCmd"
                  Property="RegisterAgent"
                  Value="&quot;[INSTALLFOLDER]slimrmm-agent.exe&quot; --install --server &quot;[SLIMRMM_SERVER]&quot;"
                  Execute="immediate" />

    <CustomAction Id="RegisterAgent"
                  BinaryKey="WixCA"
                  DllEntry="WixQuietExec64"
                  Execute="deferred"
                  Return="ignore"
                  Impersonate="no" />

    <InstallExecuteSequence>
      <Custom Action="SetRegistrationCmd" After="InstallFiles">
        SLIMRMM_SERVER
      </Custom>
      <Custom Action="RegisterAgent" After="SetRegistrationCmd">
        SLIMRMM_SERVER
      </Custom>
    </InstallExecuteSequence>

    <!-- Features -->
    <Feature Id="ProductFeature" Title="$AppName" Level="1">
      <ComponentGroupRef Id="ProductComponents" />
    </Feature>

    <!-- UI -->
    <UIRef Id="WixUI_InstallDir" />
    <WixVariable Id="WixUILicenseRtf" Value="$ScriptDir\LICENSE.rtf" />

  </Product>
</Wix>
"@

# Create a simple LICENSE.rtf if it doesn't exist
$licenseRtf = Join-Path $ScriptDir "LICENSE.rtf"
if (-not (Test-Path $licenseRtf)) {
    $rtfContent = @"
{\rtf1\ansi\deff0
{\fonttbl{\f0 Arial;}}
\f0\fs20
SlimRMM Agent\par
\par
Copyright (c) 2025 Kiefer Networks. All rights reserved.\par
\par
This software is proprietary and confidential.\par
Unauthorized copying, distribution, or use is strictly prohibited.\par
\par
For licensing inquiries, contact: support@kiefer-networks.de\par
}
"@
    $rtfContent | Out-File -FilePath $licenseRtf -Encoding ASCII
}

$wxsFile = Join-Path $WixDir "SlimRMM.wxs"
$wxsContent | Out-File -FilePath $wxsFile -Encoding UTF8

# Compile WiX source
Write-Host "[5/7] Compiling WiX source..."
$candleExe = Join-Path $wixPath "candle.exe"
$lightExe = Join-Path $wixPath "light.exe"

$wixobjFile = Join-Path $WixDir "SlimRMM.wixobj"

& $candleExe -arch $Arch -ext WixUtilExtension -ext WixUIExtension -out $wixobjFile $wxsFile
if ($LASTEXITCODE -ne 0) {
    Write-Error "WiX candle failed"
    exit 1
}

# Link to create MSI
Write-Host "[6/7] Creating MSI package..."
$msiFile = Join-Path $DistDir "SlimRMM-Agent-$Version-$Arch.msi"

& $lightExe -ext WixUtilExtension -ext WixUIExtension -out $msiFile $wixobjFile
if ($LASTEXITCODE -ne 0) {
    Write-Error "WiX light failed"
    exit 1
}

# Cleanup
Write-Host "[7/7] Cleaning up..."
Remove-Item -Path "slimrmm-agent-windows.spec" -Force -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $BuildDir -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "================================================"
Write-Host "  Build Complete!"
Write-Host "================================================"
Write-Host ""
Write-Host "MSI Location: $msiFile"
Write-Host ""
Write-Host "Installation:"
Write-Host "  Interactive: Double-click the MSI file"
Write-Host ""
Write-Host "  Command line:"
Write-Host "    msiexec /i SlimRMM-Agent-$Version-$Arch.msi /qn"
Write-Host ""
Write-Host "  Silent with registration (mTLS - no key required):"
Write-Host "    msiexec /i SlimRMM-Agent-$Version-$Arch.msi /qn SLIMRMM_SERVER=`"https://your-server:8800`""
Write-Host ""
Write-Host "Note: Install osquery from https://osquery.io/downloads for full functionality."
Write-Host ""
