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
    excludes=['tkinter', 'unittest', 'pydoc'],
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
CONFIG_FILE="${INSTALL_DIR}/.slimrmm_config.json"
CERTS_DIR="${INSTALL_DIR}/certs"

echo ""
echo "=============================================="
echo "  SlimRMM Agent - Post-installation"
echo "  Copyright (c) 2025 Kiefer Networks"
echo "=============================================="
echo ""

# Set proper permissions
chmod 755 "${AGENT_BINARY}"
chmod 700 "${CERTS_DIR}"
chmod 755 "${INSTALL_DIR}/log"

# Check for silent installation parameters
# Set via environment variables before running installer:
# SLIMRMM_SERVER="https://..." sudo installer -pkg SlimRMM-Agent.pkg -target /
SILENT_SERVER="${SLIMRMM_SERVER:-}"

# Also check for config file passed during installation
if [ -f "/tmp/slimrmm_install_config.json" ]; then
    SILENT_SERVER=$(python3 -c "import json; print(json.load(open('/tmp/slimrmm_install_config.json')).get('server', ''))" 2>/dev/null)
    rm -f /tmp/slimrmm_install_config.json
fi

# Function to register agent and save mTLS certificates
register_agent() {
    local server_url="$1"

    echo "Registering agent with server: ${server_url}"

    # Get system info
    local hostname=$(hostname)
    local os="darwin"
    local arch=$(uname -m)

    # Register with server (no installation key required - mTLS based)
    local response=$(curl -s -k -X POST "${server_url}/api/v1/agents/register" \
        -H "Content-Type: application/json" \
        -d "{
            \"os\": \"${os}\",
            \"arch\": \"${arch}\",
            \"hostname\": \"${hostname}\",
            \"agent_version\": \"1.0.0\"
        }" 2>/dev/null)

    if [ -z "$response" ]; then
        echo "ERROR: Could not connect to server"
        return 1
    fi

    # Parse response
    local uuid=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('uuid',''))" 2>/dev/null)
    local error=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('detail',''))" 2>/dev/null)

    if [ -z "$uuid" ]; then
        echo "ERROR: Registration failed - ${error:-Unknown error}"
        echo "Response: $response"
        return 1
    fi

    # Extract and save mTLS certificates
    local cert_pem=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('mtls',{}).get('certificate_pem',''))" 2>/dev/null)
    local key_pem=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('mtls',{}).get('private_key_pem',''))" 2>/dev/null)
    local ca_pem=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('mtls',{}).get('ca_certificate_pem',''))" 2>/dev/null)

    if [ -z "$cert_pem" ] || [ -z "$key_pem" ] || [ -z "$ca_pem" ]; then
        echo "ERROR: Server did not return mTLS certificates"
        return 1
    fi

    # Save certificates
    echo "$cert_pem" > "${CERTS_DIR}/client.crt"
    echo "$key_pem" > "${CERTS_DIR}/client.key"
    echo "$ca_pem" > "${CERTS_DIR}/ca.crt"
    chmod 600 "${CERTS_DIR}/client.crt" "${CERTS_DIR}/client.key" "${CERTS_DIR}/ca.crt"

    # Save configuration
    cat > "${CONFIG_FILE}" << CONFIGEOF
{
    "server": "${server_url}",
    "uuid": "${uuid}"
}
CONFIGEOF
    chmod 600 "${CONFIG_FILE}"

    echo "Agent registered successfully!"
    echo "  UUID: ${uuid}"
    echo "  Certificates saved to: ${CERTS_DIR}"
    return 0
}

# Interactive or silent installation
if [ -n "$SILENT_SERVER" ]; then
    # Silent installation with provided server URL
    echo "Silent installation mode detected."
    register_agent "$SILENT_SERVER"
    REGISTRATION_SUCCESS=$?
else
    # Check if we're in an interactive terminal
    if [ -t 0 ]; then
        # Interactive mode - prompt for configuration
        echo "Please enter your SlimRMM server URL:"
        echo ""

        read -p "Server URL (e.g., https://rmm.example.com:8800): " SERVER_URL

        if [ -n "$SERVER_URL" ]; then
            register_agent "$SERVER_URL"
            REGISTRATION_SUCCESS=$?
        else
            echo ""
            echo "No server URL provided. Skipping registration."
            echo "You can register later with:"
            echo "  sudo ${AGENT_BINARY} --install --server <URL>"
            REGISTRATION_SUCCESS=1
        fi
    else
        # Non-interactive without silent params - show instructions
        echo "Non-interactive installation without configuration."
        echo ""
        echo "To configure the agent, either:"
        echo ""
        echo "1. Run the installer with environment variable:"
        echo "   SLIMRMM_SERVER=\"https://...\" sudo installer -pkg SlimRMM-Agent.pkg -target /"
        echo ""
        echo "2. Or configure manually after installation:"
        echo "   sudo ${AGENT_BINARY} --install --server <URL>"
        echo ""
        REGISTRATION_SUCCESS=1
    fi
fi

# Load the LaunchDaemon only if registration was successful
if [ "$REGISTRATION_SUCCESS" -eq 0 ]; then
    echo ""
    echo "Loading SlimRMM agent service..."
    launchctl bootstrap system /Library/LaunchDaemons/${LAUNCHD_LABEL}.plist 2>/dev/null || true

    sleep 2

    if launchctl list | grep -q "${LAUNCHD_LABEL}"; then
        echo "SlimRMM Agent service is running."
    else
        launchctl kickstart -k system/${LAUNCHD_LABEL} 2>/dev/null || true
    fi
else
    echo ""
    echo "Agent installed but not started (no configuration)."
    echo "Configure and start manually when ready."
fi

# Request TCC permissions
echo ""
echo "=============================================="
echo "  IMPORTANT: Permissions Required"
echo "=============================================="
echo ""
echo "SlimRMM Agent requires the following permissions:"
echo ""
echo "1. FULL DISK ACCESS (Required)"
echo "   For: File management, system monitoring"
echo ""
echo "2. SCREEN RECORDING (Optional)"
echo "   For: Remote desktop functionality"
echo ""
echo "Opening System Settings..."

# Try to open System Settings to the correct pane
open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles" 2>/dev/null || true

echo ""
echo "=============================================="
echo "  Installation Complete"
echo "=============================================="
echo ""
echo "Agent binary: ${AGENT_BINARY}"
echo "Config file:  ${CONFIG_FILE}"
echo "Log files:    ${INSTALL_DIR}/log/"
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
