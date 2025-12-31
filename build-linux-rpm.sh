#!/bin/bash
#
# SlimRMM Agent - Linux RPM Build Script
# Copyright (c) 2025 Kiefer Networks
#
# This script builds an RPM package for RHEL/Fedora/CentOS systems
#

set -e

# Configuration
APP_NAME="slimrmm-agent"
VERSION="${1:-1.0.0}"
RELEASE="1"
MAINTAINER="Kiefer Networks <support@slimrmm.io>"
SUMMARY="SlimRMM Agent - Remote Monitoring and Management"
INSTALL_DIR="/var/lib/slimrmm"
SYSTEMD_SERVICE="slimrmm-agent"

# Detect architecture
MACHINE_ARCH=$(uname -m)
case "${MACHINE_ARCH}" in
    x86_64)
        ARCH="x86_64"
        ;;
    aarch64|arm64)
        ARCH="aarch64"
        ;;
    *)
        ARCH="${2:-${MACHINE_ARCH}}"
        ;;
esac

# Paths
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
DIST_DIR="${SCRIPT_DIR}/dist"
RPM_BUILD_ROOT="${BUILD_DIR}/rpmbuild"

echo "================================================"
echo "  SlimRMM Agent - Linux RPM Builder"
echo "  Version: ${VERSION}"
echo "  Architecture: ${ARCH}"
echo "================================================"
echo ""

# Clean previous builds
echo "[1/6] Cleaning previous builds..."
rm -rf "${BUILD_DIR}" "${DIST_DIR}"
mkdir -p "${RPM_BUILD_ROOT}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
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

# Create source tarball
echo "[3/6] Preparing RPM sources..."
SOURCE_DIR="${RPM_BUILD_ROOT}/SOURCES/${APP_NAME}-${VERSION}"
mkdir -p "${SOURCE_DIR}"

cp "${DIST_DIR}/slimrmm-agent" "${SOURCE_DIR}/"

# Create systemd service file in source
cat > "${SOURCE_DIR}/${SYSTEMD_SERVICE}.service" << SERVICE
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

# Create tarball
cd "${RPM_BUILD_ROOT}/SOURCES"
tar czf "${APP_NAME}-${VERSION}.tar.gz" "${APP_NAME}-${VERSION}"
rm -rf "${APP_NAME}-${VERSION}"

# Create RPM spec file
echo "[4/6] Creating RPM spec..."
cat > "${RPM_BUILD_ROOT}/SPECS/${APP_NAME}.spec" << RPMSPEC
Name:           ${APP_NAME}
Version:        ${VERSION}
Release:        ${RELEASE}%{?dist}
Summary:        ${SUMMARY}

License:        Proprietary
URL:            https://slimrmm.io
Source0:        %{name}-%{version}.tar.gz

BuildArch:      ${ARCH}
Requires:       curl

%description
SlimRMM Agent provides remote monitoring and management
capabilities for Linux systems. Features include:
- Real-time system monitoring (CPU, memory, disk, network)
- Remote command execution
- Software inventory
- File management
- Remote desktop support

%prep
%setup -q

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}${INSTALL_DIR}
mkdir -p %{buildroot}${INSTALL_DIR}/log
mkdir -p %{buildroot}${INSTALL_DIR}/certs
mkdir -p %{buildroot}/usr/lib/systemd/system
mkdir -p %{buildroot}/usr/bin

install -m 755 slimrmm-agent %{buildroot}${INSTALL_DIR}/
install -m 644 ${SYSTEMD_SERVICE}.service %{buildroot}/usr/lib/systemd/system/
ln -sf ${INSTALL_DIR}/slimrmm-agent %{buildroot}/usr/bin/slimrmm-agent

%pre
# Stop existing service
if systemctl is-active --quiet ${SYSTEMD_SERVICE} 2>/dev/null; then
    systemctl stop ${SYSTEMD_SERVICE} || true
fi

if systemctl is-enabled --quiet ${SYSTEMD_SERVICE} 2>/dev/null; then
    systemctl disable ${SYSTEMD_SERVICE} || true
fi

# Backup config
if [ -f "${INSTALL_DIR}/.slimrmm_config.json" ]; then
    cp "${INSTALL_DIR}/.slimrmm_config.json" /tmp/.slimrmm_config.json.backup
fi

%post
echo ""
echo "=============================================="
echo "  SlimRMM Agent - Post-installation"
echo "  Copyright (c) 2025 Kiefer Networks"
echo "=============================================="
echo ""

# Set permissions
chmod 700 ${INSTALL_DIR}/certs
chmod 755 ${INSTALL_DIR}/log

# Restore config if backed up
if [ -f /tmp/.slimrmm_config.json.backup ]; then
    mv /tmp/.slimrmm_config.json.backup "${INSTALL_DIR}/.slimrmm_config.json"
    chmod 600 "${INSTALL_DIR}/.slimrmm_config.json"
    echo "Configuration restored."
fi

# Reload systemd
systemctl daemon-reload

# Check for silent installation parameters
SILENT_SERVER="\${SLIMRMM_SERVER:-}"

# Also check for config file passed during installation
if [ -f "/tmp/slimrmm_install_config.json" ]; then
    if command -v python3 &> /dev/null; then
        SILENT_SERVER=\$(python3 -c "import json; print(json.load(open('/tmp/slimrmm_install_config.json')).get('server', ''))" 2>/dev/null)
    fi
    rm -f /tmp/slimrmm_install_config.json
fi

CONFIG_FILE="${INSTALL_DIR}/.slimrmm_config.json"
REGISTRATION_SUCCESS=1

if [ -n "\$SILENT_SERVER" ]; then
    echo "Silent installation mode detected."
    echo "Registering agent with server: \${SILENT_SERVER}"

    hostname=\$(hostname)
    os="linux"
    arch=\$(uname -m)
    [ "\$arch" = "x86_64" ] && arch="amd64"
    [ "\$arch" = "aarch64" ] && arch="arm64"

    response=\$(curl -s -k -X POST "\${SILENT_SERVER}/api/v1/agents/register" \\
        -H "Content-Type: application/json" \\
        -d "{
            \"os\": \"\${os}\",
            \"arch\": \"\${arch}\",
            \"hostname\": \"\${hostname}\",
            \"agent_version\": \"${VERSION}\"
        }" 2>/dev/null)

    if [ -n "\$response" ]; then
        if command -v python3 &> /dev/null; then
            uuid=\$(echo "\$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('uuid',''))" 2>/dev/null)
            cert_pem=\$(echo "\$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('mtls',{}).get('certificate_pem',''))" 2>/dev/null)
            key_pem=\$(echo "\$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('mtls',{}).get('private_key_pem',''))" 2>/dev/null)
            ca_pem=\$(echo "\$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('mtls',{}).get('ca_certificate_pem',''))" 2>/dev/null)
        fi

        if [ -n "\$uuid" ]; then
            # Save mTLS certificates
            if [ -n "\$cert_pem" ] && [ -n "\$key_pem" ] && [ -n "\$ca_pem" ]; then
                echo "\$cert_pem" > "${INSTALL_DIR}/certs/agent.crt"
                echo "\$key_pem" > "${INSTALL_DIR}/certs/agent.key"
                echo "\$ca_pem" > "${INSTALL_DIR}/certs/ca.crt"
                chmod 644 "${INSTALL_DIR}/certs/agent.crt"
                chmod 600 "${INSTALL_DIR}/certs/agent.key"
                chmod 644 "${INSTALL_DIR}/certs/ca.crt"
                echo "mTLS certificates saved."
            fi

            cat > "\${CONFIG_FILE}" << CONFIGEOF
{
    "server": "\${SILENT_SERVER}",
    "uuid": "\${uuid}",
    "mtls_enabled": true
}
CONFIGEOF
            chmod 600 "\${CONFIG_FILE}"
            echo "Agent registered successfully! UUID: \${uuid}"
            REGISTRATION_SUCCESS=0
        else
            echo "ERROR: Registration failed"
            echo "Response: \$response"
        fi
    fi
elif [ -f "\${CONFIG_FILE}" ]; then
    echo "Existing configuration found."
    REGISTRATION_SUCCESS=0
else
    echo ""
    echo "No configuration found."
    echo "To configure, run:"
    echo "  sudo slimrmm-agent --install --server https://your-server.com:8800"
    echo ""
    echo "Or reinstall with environment variable:"
    echo "  SLIMRMM_SERVER=\"https://...\" sudo rpm -i slimrmm-agent-*.rpm"
    echo ""
fi

if [ "\$REGISTRATION_SUCCESS" -eq 0 ]; then
    systemctl enable ${SYSTEMD_SERVICE}
    systemctl start ${SYSTEMD_SERVICE}
    echo "SlimRMM Agent service started."
else
    echo "Agent installed but not started (no configuration)."
fi

echo ""
echo "Installation complete!"
echo "Agent binary: ${INSTALL_DIR}/slimrmm-agent"
echo "Service: systemctl status ${SYSTEMD_SERVICE}"
echo ""

%preun
if [ \$1 -eq 0 ]; then
    # Package removal
    if systemctl is-active --quiet ${SYSTEMD_SERVICE} 2>/dev/null; then
        systemctl stop ${SYSTEMD_SERVICE} || true
    fi
    if systemctl is-enabled --quiet ${SYSTEMD_SERVICE} 2>/dev/null; then
        systemctl disable ${SYSTEMD_SERVICE} || true
    fi
fi

%postun
systemctl daemon-reload
if [ \$1 -eq 0 ]; then
    # Package removal (not upgrade)
    rm -rf ${INSTALL_DIR}
fi

%files
%defattr(-,root,root,-)
${INSTALL_DIR}/slimrmm-agent
%dir ${INSTALL_DIR}
%dir ${INSTALL_DIR}/log
%dir %attr(700,root,root) ${INSTALL_DIR}/certs
/usr/lib/systemd/system/${SYSTEMD_SERVICE}.service
/usr/bin/slimrmm-agent

%changelog
* $(date "+%a %b %d %Y") Kiefer Networks <support@slimrmm.io> - ${VERSION}-${RELEASE}
- Initial release of SlimRMM Agent
RPMSPEC

# Build the RPM
echo "[5/6] Building RPM package..."
rpmbuild --define "_topdir ${RPM_BUILD_ROOT}" -bb "${RPM_BUILD_ROOT}/SPECS/${APP_NAME}.spec"

# Copy RPM to dist
echo "[6/6] Finalizing..."
cp "${RPM_BUILD_ROOT}/RPMS/${ARCH}/"*.rpm "${DIST_DIR}/" 2>/dev/null || \
cp "${RPM_BUILD_ROOT}/RPMS/noarch/"*.rpm "${DIST_DIR}/" 2>/dev/null || true

# Cleanup
rm -rf "${BUILD_DIR}"
rm -f slimrmm-agent-linux.spec

RPM_FILE=$(ls "${DIST_DIR}"/*.rpm 2>/dev/null | head -1)

echo ""
echo "================================================"
echo "  Build Complete!"
echo "================================================"
echo ""
echo "RPM Location: ${RPM_FILE}"
echo ""
echo "To install:"
echo "  sudo rpm -i ${RPM_FILE}"
echo ""
echo "Silent installation with auto-registration:"
echo "  SLIMRMM_SERVER=\"http://your-server:8800\" sudo rpm -i ${RPM_FILE}"
echo ""
echo "Or create config file before installing:"
echo "  echo '{\"server\": \"http://your-server:8800\"}' | sudo tee /tmp/slimrmm_install_config.json"
echo "  sudo rpm -i ${RPM_FILE}"
echo ""
