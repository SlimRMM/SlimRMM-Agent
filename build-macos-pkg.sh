#!/bin/bash
#
# SlimRMM Agent - macOS PKG Build Script
# Copyright (c) 2025 Kiefer Networks
#
# This script builds a signed PKG installer for macOS (Apple Silicon only)
#

set -e

# Configuration
APP_NAME="SlimRMM Agent"
APP_IDENTIFIER="io.slimrmm.agent"
VERSION="${1:-1.0.0}"
INSTALL_DIR="/var/lib/slimrmm"
LAUNCHD_LABEL="io.slimrmm.agent"

# Paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
DIST_DIR="${SCRIPT_DIR}/dist"
PKG_ROOT="${BUILD_DIR}/pkg-root"
SCRIPTS_DIR="${BUILD_DIR}/scripts"

echo "================================================"
echo "  SlimRMM Agent - macOS PKG Builder"
echo "  Version: ${VERSION}"
echo "  Target: Apple Silicon (arm64)"
echo "================================================"
echo ""

# Clean previous builds
echo "[1/7] Cleaning previous builds..."
rm -rf "${BUILD_DIR}" "${DIST_DIR}"
mkdir -p "${PKG_ROOT}${INSTALL_DIR}"
mkdir -p "${PKG_ROOT}/Library/LaunchDaemons"
mkdir -p "${SCRIPTS_DIR}"
mkdir -p "${DIST_DIR}"

# Add PyInstaller to PATH
for dir in ~/Library/Python/*/bin /Users/*/Library/Python/*/bin; do
    if [ -d "$dir" ]; then
        export PATH="$dir:$PATH"
    fi
done

# Build the binary with PyInstaller (Apple Silicon only)
echo "[2/7] Building agent binary (Apple Silicon)..."
cd "${SCRIPT_DIR}"

# Create spec file for optimized build
cat > slimrmm-agent.spec << 'SPEC'
# -*- mode: python ; coding: utf-8 -*-
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
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'unittest', 'email', 'html', 'http', 'xml', 'pydoc'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

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
    strip=True,
    upx=False,
    console=True,
    target_arch='arm64',
)
SPEC

pyinstaller --clean --noconfirm slimrmm-agent.spec

# Copy binary to PKG root
echo "[3/7] Preparing PKG contents..."
cp "${DIST_DIR}/slimrmm-agent" "${PKG_ROOT}${INSTALL_DIR}/"
chmod 755 "${PKG_ROOT}${INSTALL_DIR}/slimrmm-agent"

# Create LaunchDaemon plist
echo "[4/7] Creating LaunchDaemon configuration..."
cat > "${PKG_ROOT}/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/slimrmm-agent</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>WorkingDirectory</key>
    <string>${INSTALL_DIR}</string>
    <key>StandardOutPath</key>
    <string>${INSTALL_DIR}/log/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>${INSTALL_DIR}/log/stderr.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>
PLIST

# Create preinstall script
echo "[5/7] Creating installation scripts..."
cat > "${SCRIPTS_DIR}/preinstall" << 'PREINSTALL'
#!/bin/bash
# SlimRMM Agent - Pre-installation Script
# Copyright (c) 2025 Kiefer Networks

INSTALL_DIR="/var/lib/slimrmm"
OLD_INSTALL_DIR="/var/lib/rmm"
LAUNCHD_LABEL="io.slimrmm.agent"
OLD_LAUNCHD_LABEL="com.rmm.agent"

echo "SlimRMM Agent - Pre-installation"

# Stop and unload existing SlimRMM agent
if launchctl list | grep -q "${LAUNCHD_LABEL}"; then
    echo "Stopping existing SlimRMM agent..."
    launchctl bootout system/${LAUNCHD_LABEL} 2>/dev/null || true
fi

# Stop and unload old RMM agent (migration)
if launchctl list | grep -q "${OLD_LAUNCHD_LABEL}"; then
    echo "Stopping old RMM agent..."
    launchctl bootout system/${OLD_LAUNCHD_LABEL} 2>/dev/null || true
fi

# Remove old LaunchDaemon plists
rm -f /Library/LaunchDaemons/${LAUNCHD_LABEL}.plist
rm -f /Library/LaunchDaemons/${OLD_LAUNCHD_LABEL}.plist

# Clean old installation directory
if [ -d "${OLD_INSTALL_DIR}" ]; then
    echo "Removing old RMM installation..."
    rm -rf "${OLD_INSTALL_DIR}"
fi

# Clean existing SlimRMM directory (preserve config if exists)
if [ -d "${INSTALL_DIR}" ]; then
    echo "Cleaning existing SlimRMM installation..."
    # Preserve config file if it exists
    if [ -f "${INSTALL_DIR}/.slimrmm_config.json" ]; then
        cp "${INSTALL_DIR}/.slimrmm_config.json" /tmp/.slimrmm_config.json.backup
    fi
    rm -rf "${INSTALL_DIR}"
fi

# Create fresh installation directory
mkdir -p "${INSTALL_DIR}/log"
mkdir -p "${INSTALL_DIR}/certs"

# Restore config if backed up
if [ -f /tmp/.slimrmm_config.json.backup ]; then
    mv /tmp/.slimrmm_config.json.backup "${INSTALL_DIR}/.slimrmm_config.json"
fi

echo "Pre-installation complete."
exit 0
PREINSTALL

# Create postinstall script
cat > "${SCRIPTS_DIR}/postinstall" << 'POSTINSTALL'
#!/bin/bash
# SlimRMM Agent - Post-installation Script
# Copyright (c) 2025 Kiefer Networks

INSTALL_DIR="/var/lib/slimrmm"
LAUNCHD_LABEL="io.slimrmm.agent"
AGENT_BINARY="${INSTALL_DIR}/slimrmm-agent"

echo "SlimRMM Agent - Post-installation"

# Set proper permissions
chmod 755 "${AGENT_BINARY}"
chmod 700 "${INSTALL_DIR}/certs"
chmod 755 "${INSTALL_DIR}/log"

# Load the LaunchDaemon
echo "Loading SlimRMM agent service..."
launchctl bootstrap system /Library/LaunchDaemons/${LAUNCHD_LABEL}.plist

# Request TCC permissions (Full Disk Access, Screen Recording)
echo ""
echo "=============================================="
echo "  IMPORTANT: Permissions Required"
echo "=============================================="
echo ""
echo "SlimRMM Agent requires the following permissions:"
echo ""
echo "1. FULL DISK ACCESS"
echo "   Required for: File management, system monitoring"
echo ""
echo "2. SCREEN RECORDING (optional)"
echo "   Required for: Remote desktop functionality"
echo ""
echo "To grant these permissions:"
echo "  1. Open System Settings"
echo "  2. Go to Privacy & Security"
echo "  3. Add '${AGENT_BINARY}' to:"
echo "     - Full Disk Access"
echo "     - Screen Recording (if using remote desktop)"
echo ""

# Try to open System Settings to the correct pane
open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles" 2>/dev/null || true

# Small delay to ensure service is loaded
sleep 2

# Check if service is running
if launchctl list | grep -q "${LAUNCHD_LABEL}"; then
    echo "SlimRMM Agent service is running."
else
    echo "Starting SlimRMM Agent service..."
    launchctl kickstart -k system/${LAUNCHD_LABEL}
fi

echo ""
echo "Installation complete!"
echo "Agent installed to: ${INSTALL_DIR}"
echo ""

exit 0
POSTINSTALL

chmod +x "${SCRIPTS_DIR}/preinstall"
chmod +x "${SCRIPTS_DIR}/postinstall"

# Build the PKG
echo "[6/7] Building PKG installer..."
pkgbuild \
    --root "${PKG_ROOT}" \
    --scripts "${SCRIPTS_DIR}" \
    --identifier "${APP_IDENTIFIER}" \
    --version "${VERSION}" \
    --install-location "/" \
    "${DIST_DIR}/SlimRMM-Agent-${VERSION}-arm64.pkg"

# Create a product archive (optional: for distribution signing)
echo "[7/7] Finalizing..."

# Cleanup build artifacts
rm -rf "${BUILD_DIR}"
rm -f slimrmm-agent.spec

echo ""
echo "================================================"
echo "  Build Complete!"
echo "================================================"
echo ""
echo "PKG Location: ${DIST_DIR}/SlimRMM-Agent-${VERSION}-arm64.pkg"
echo ""
echo "To install:"
echo "  sudo installer -pkg ${DIST_DIR}/SlimRMM-Agent-${VERSION}-arm64.pkg -target /"
echo ""
echo "Or double-click the PKG file in Finder."
echo ""
