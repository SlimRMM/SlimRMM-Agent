#!/bin/bash
#
# SlimRMM Agent - Linux DEB Build Script
# Copyright (c) 2025 Kiefer Networks
#
# This script builds a DEB package for Debian/Ubuntu systems
#

set -e

# Configuration
APP_NAME="slimrmm-agent"
VERSION="${1:-1.0.0}"
MAINTAINER="Kiefer Networks <support@slimrmm.io>"
DESCRIPTION="SlimRMM Agent - Remote Monitoring and Management"
INSTALL_DIR="/var/lib/slimrmm"
SYSTEMD_SERVICE="slimrmm-agent"

# Detect architecture
MACHINE_ARCH=$(uname -m)
case "${MACHINE_ARCH}" in
    x86_64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    *)
        ARCH="${2:-${MACHINE_ARCH}}"
        ;;
esac

# Paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
DIST_DIR="${SCRIPT_DIR}/dist"
DEB_ROOT="${BUILD_DIR}/deb-root"

echo "================================================"
echo "  SlimRMM Agent - Linux DEB Builder"
echo "  Version: ${VERSION}"
echo "  Architecture: ${ARCH}"
echo "================================================"
echo ""

# Clean previous builds
echo "[1/6] Cleaning previous builds..."
rm -rf "${BUILD_DIR}" "${DIST_DIR}"
mkdir -p "${DEB_ROOT}/DEBIAN"
mkdir -p "${DEB_ROOT}${INSTALL_DIR}"
mkdir -p "${DEB_ROOT}/etc/systemd/system"
mkdir -p "${DEB_ROOT}/usr/bin"
mkdir -p "${DIST_DIR}"

# Build the binary with PyInstaller
echo "[2/6] Building agent binary..."
cd "${SCRIPT_DIR}"

# Install dependencies if needed
if ! command -v pyinstaller &> /dev/null; then
    echo "Installing PyInstaller..."
    pip3 install pyinstaller --user
fi

# Create spec file for Linux build
cat > slimrmm-agent-linux.spec << 'SPEC'
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
)
SPEC

pyinstaller --clean --noconfirm slimrmm-agent-linux.spec

# Copy binary to DEB root
echo "[3/6] Preparing DEB contents..."
cp "${DIST_DIR}/slimrmm-agent" "${DEB_ROOT}${INSTALL_DIR}/"
chmod 755 "${DEB_ROOT}${INSTALL_DIR}/slimrmm-agent"

# Create symlink in /usr/bin
ln -sf "${INSTALL_DIR}/slimrmm-agent" "${DEB_ROOT}/usr/bin/slimrmm-agent"

# Create systemd service file
echo "[4/6] Creating systemd service..."
cat > "${DEB_ROOT}/etc/systemd/system/${SYSTEMD_SERVICE}.service" << SERVICE
[Unit]
Description=SlimRMM Agent - Remote Monitoring and Management
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/slimrmm-agent
WorkingDirectory=${INSTALL_DIR}
Restart=on-failure
RestartSec=10
StandardOutput=append:${INSTALL_DIR}/log/stdout.log
StandardError=append:${INSTALL_DIR}/log/stderr.log
Environment=PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin

[Install]
WantedBy=multi-user.target
SERVICE

# Create DEBIAN control file
echo "[5/6] Creating package metadata..."
INSTALLED_SIZE=$(du -sk "${DEB_ROOT}" | cut -f1)

cat > "${DEB_ROOT}/DEBIAN/control" << CONTROL
Package: ${APP_NAME}
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Installed-Size: ${INSTALLED_SIZE}
Maintainer: ${MAINTAINER}
Description: ${DESCRIPTION}
 SlimRMM Agent provides remote monitoring and management
 capabilities for Linux systems. Features include:
 - Real-time system monitoring (CPU, memory, disk, network)
 - Remote command execution
 - Software inventory
 - File management
 - Remote desktop support
CONTROL

# Create preinst script
cat > "${DEB_ROOT}/DEBIAN/preinst" << 'PREINST'
#!/bin/bash
# SlimRMM Agent - Pre-installation Script
# Copyright (c) 2025 Kiefer Networks

set -e

INSTALL_DIR="/var/lib/slimrmm"
SYSTEMD_SERVICE="slimrmm-agent"

echo "SlimRMM Agent - Pre-installation"

# Stop existing service
if systemctl is-active --quiet ${SYSTEMD_SERVICE} 2>/dev/null; then
    echo "Stopping existing SlimRMM agent..."
    systemctl stop ${SYSTEMD_SERVICE} || true
fi

if systemctl is-enabled --quiet ${SYSTEMD_SERVICE} 2>/dev/null; then
    systemctl disable ${SYSTEMD_SERVICE} || true
fi

# Backup config if exists
if [ -f "${INSTALL_DIR}/.slimrmm_config.json" ]; then
    cp "${INSTALL_DIR}/.slimrmm_config.json" /tmp/.slimrmm_config.json.backup
    echo "Configuration backed up."
fi

exit 0
PREINST
chmod 755 "${DEB_ROOT}/DEBIAN/preinst"

# Create postinst script
cat > "${DEB_ROOT}/DEBIAN/postinst" << 'POSTINST'
#!/bin/bash
# SlimRMM Agent - Post-installation Script
# Copyright (c) 2025 Kiefer Networks

set -e

INSTALL_DIR="/var/lib/slimrmm"
SYSTEMD_SERVICE="slimrmm-agent"
CONFIG_FILE="${INSTALL_DIR}/.slimrmm_config.json"

echo ""
echo "=============================================="
echo "  SlimRMM Agent - Post-installation"
echo "  Copyright (c) 2025 Kiefer Networks"
echo "=============================================="
echo ""

# Create directories
mkdir -p "${INSTALL_DIR}/log"
mkdir -p "${INSTALL_DIR}/certs"
chmod 755 "${INSTALL_DIR}"
chmod 700 "${INSTALL_DIR}/certs"
chmod 755 "${INSTALL_DIR}/log"

# Restore config if backed up
if [ -f /tmp/.slimrmm_config.json.backup ]; then
    mv /tmp/.slimrmm_config.json.backup "${CONFIG_FILE}"
    chmod 600 "${CONFIG_FILE}"
    echo "Configuration restored."
fi

# Reload systemd
systemctl daemon-reload

# Check for silent installation parameters
SILENT_SERVER="${SLIMRMM_SERVER:-}"
SILENT_KEY="${SLIMRMM_KEY:-}"

# Function to register agent
register_agent() {
    local server_url="$1"
    local install_key="$2"

    echo "Registering agent with server: ${server_url}"

    # Get system info
    local hostname=$(hostname)
    local os="linux"
    local arch=$(uname -m)
    [ "$arch" = "x86_64" ] && arch="amd64"
    [ "$arch" = "aarch64" ] && arch="arm64"

    # Register with server
    local response=$(curl -s -X POST "${server_url}/api/v1/agents/register" \
        -H "Content-Type: application/json" \
        -d "{
            \"installation_key\": \"${install_key}\",
            \"os\": \"${os}\",
            \"arch\": \"${arch}\",
            \"hostname\": \"${hostname}\",
            \"agent_version\": \"1.0.0\"
        }" 2>/dev/null)

    if [ -z "$response" ]; then
        echo "ERROR: Could not connect to server"
        return 1
    fi

    # Parse response (requires python3 or jq)
    local uuid=""
    local api_key=""

    if command -v python3 &> /dev/null; then
        uuid=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('uuid',''))" 2>/dev/null)
        api_key=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('api_key',''))" 2>/dev/null)
    elif command -v jq &> /dev/null; then
        uuid=$(echo "$response" | jq -r '.uuid // empty' 2>/dev/null)
        api_key=$(echo "$response" | jq -r '.api_key // empty' 2>/dev/null)
    fi

    if [ -z "$uuid" ] || [ -z "$api_key" ]; then
        echo "ERROR: Registration failed"
        return 1
    fi

    # Save configuration
    cat > "${CONFIG_FILE}" << CONFIGEOF
{
    "server": "${server_url}",
    "uuid": "${uuid}",
    "api_key": "${api_key}"
}
CONFIGEOF
    chmod 600 "${CONFIG_FILE}"

    echo "Agent registered successfully!"
    echo "  UUID: ${uuid}"
    return 0
}

# Interactive or silent installation
REGISTRATION_SUCCESS=1

if [ -n "$SILENT_SERVER" ] && [ -n "$SILENT_KEY" ]; then
    echo "Silent installation mode detected."
    register_agent "$SILENT_SERVER" "$SILENT_KEY"
    REGISTRATION_SUCCESS=$?
elif [ -f "${CONFIG_FILE}" ]; then
    echo "Existing configuration found."
    REGISTRATION_SUCCESS=0
else
    echo ""
    echo "No configuration found."
    echo ""
    echo "To configure the agent, run:"
    echo "  sudo slimrmm-agent --install --installation-key YOUR_KEY --server https://your-server.com"
    echo ""
    echo "Or reinstall with environment variables:"
    echo "  SLIMRMM_SERVER=\"https://...\" SLIMRMM_KEY=\"...\" sudo dpkg -i slimrmm-agent_*.deb"
    echo ""
fi

# Enable and start service if registration successful
if [ "$REGISTRATION_SUCCESS" -eq 0 ]; then
    echo "Enabling and starting SlimRMM agent service..."
    systemctl enable ${SYSTEMD_SERVICE}
    systemctl start ${SYSTEMD_SERVICE}

    sleep 2

    if systemctl is-active --quiet ${SYSTEMD_SERVICE}; then
        echo "SlimRMM Agent service is running."
    else
        echo "Warning: Service may not have started correctly. Check logs with:"
        echo "  journalctl -u ${SYSTEMD_SERVICE} -f"
    fi
else
    echo "Agent installed but not started (no configuration)."
    echo "Configure and start manually when ready."
fi

echo ""
echo "=============================================="
echo "  Installation Complete"
echo "=============================================="
echo ""
echo "Agent binary: ${INSTALL_DIR}/slimrmm-agent"
echo "Config file:  ${CONFIG_FILE}"
echo "Log files:    ${INSTALL_DIR}/log/"
echo "Service:      systemctl status ${SYSTEMD_SERVICE}"
echo ""

exit 0
POSTINST
chmod 755 "${DEB_ROOT}/DEBIAN/postinst"

# Create prerm script
cat > "${DEB_ROOT}/DEBIAN/prerm" << 'PRERM'
#!/bin/bash
# SlimRMM Agent - Pre-removal Script

set -e

SYSTEMD_SERVICE="slimrmm-agent"

if systemctl is-active --quiet ${SYSTEMD_SERVICE} 2>/dev/null; then
    echo "Stopping SlimRMM agent..."
    systemctl stop ${SYSTEMD_SERVICE} || true
fi

if systemctl is-enabled --quiet ${SYSTEMD_SERVICE} 2>/dev/null; then
    systemctl disable ${SYSTEMD_SERVICE} || true
fi

exit 0
PRERM
chmod 755 "${DEB_ROOT}/DEBIAN/prerm"

# Create postrm script
cat > "${DEB_ROOT}/DEBIAN/postrm" << 'POSTRM'
#!/bin/bash
# SlimRMM Agent - Post-removal Script

INSTALL_DIR="/var/lib/slimrmm"

if [ "$1" = "purge" ]; then
    echo "Removing SlimRMM data..."
    rm -rf "${INSTALL_DIR}"
fi

systemctl daemon-reload

exit 0
POSTRM
chmod 755 "${DEB_ROOT}/DEBIAN/postrm"

# Build the DEB package
echo "[6/6] Building DEB package..."
DEB_FILE="${DIST_DIR}/${APP_NAME}_${VERSION}_${ARCH}.deb"
dpkg-deb --build "${DEB_ROOT}" "${DEB_FILE}"

# Cleanup
rm -rf "${BUILD_DIR}"
rm -f slimrmm-agent-linux.spec

echo ""
echo "================================================"
echo "  Build Complete!"
echo "================================================"
echo ""
echo "DEB Location: ${DEB_FILE}"
echo ""
echo "To install:"
echo "  sudo dpkg -i ${DEB_FILE}"
echo ""
echo "Silent installation:"
echo "  SLIMRMM_SERVER=\"https://...\" SLIMRMM_KEY=\"...\" sudo dpkg -i ${DEB_FILE}"
echo ""
