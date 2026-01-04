#!/bin/bash
set -e

# SlimRMM Agent Post-Installation Script for Linux
# This script runs after the package manager installs the binary
#
# The installer only places files - configuration is done separately via:
#   sudo slimrmm-agent install -s https://server.com -k TOKEN
#
# Arguments:
#   Debian: $1 = "configure" (fresh install or upgrade)
#   RPM: $1 = number of packages (1 = fresh install, 2+ = upgrade)

CONFIG_DIR="/var/lib/slimrmm"
CONFIG_FILE="${CONFIG_DIR}/.slimrmm_config.json"
BACKUP_DIR="/tmp/slimrmm-upgrade-backup"
BINARY="/usr/local/bin/slimrmm-agent"

echo "Installing SlimRMM Agent..."

# Restore configuration from upgrade backup if available
restore_backup() {
    if [ -d "${BACKUP_DIR}" ] && [ -f "${BACKUP_DIR}/.slimrmm_config.json" ]; then
        echo "Restoring configuration from upgrade backup..."
        mkdir -p "${CONFIG_DIR}"

        # Restore config file
        cp -p "${BACKUP_DIR}/.slimrmm_config.json" "${CONFIG_FILE}"

        # Restore certificates
        for cert_file in ca.crt client.crt client.key; do
            if [ -f "${BACKUP_DIR}/${cert_file}" ]; then
                cp -p "${BACKUP_DIR}/${cert_file}" "${CONFIG_DIR}/"
            fi
        done

        # Restore Proxmox token
        if [ -f "${BACKUP_DIR}/.proxmox_token.json" ]; then
            cp -p "${BACKUP_DIR}/.proxmox_token.json" "${CONFIG_DIR}/"
        fi

        # Clean up backup
        rm -rf "${BACKUP_DIR}"
        return 0
    fi
    return 1
}

# Create directories
mkdir -p "${CONFIG_DIR}"
chmod 700 "${CONFIG_DIR}"
mkdir -p /var/log/slimrmm
chmod 755 /var/log/slimrmm

# Check for upgrade backup
if restore_backup; then
    echo "Upgrade detected - restarting service with existing configuration..."

    # Reload systemd and restart service
    systemctl daemon-reload
    systemctl enable slimrmm-agent 2>/dev/null || true
    systemctl start slimrmm-agent

    echo "SlimRMM Agent upgraded successfully"
    exit 0
fi

# Check if already configured (upgrade without backup - old version)
if [ -f "${CONFIG_FILE}" ]; then
    echo "Existing configuration found, restarting service..."

    # Use the new install command which handles everything
    "${BINARY}" install 2>/dev/null || {
        # Fallback to manual restart
        systemctl daemon-reload
        systemctl enable slimrmm-agent 2>/dev/null || true
        systemctl start slimrmm-agent
    }

    echo "SlimRMM Agent upgraded successfully"
    exit 0
fi

# Check for environment variables (silent install mode)
if [ -n "${SLIMRMM_SERVER}" ]; then
    echo "Server URL provided via environment: ${SLIMRMM_SERVER}"

    # Build install command
    INSTALL_CMD="${BINARY} install -s ${SLIMRMM_SERVER}"
    if [ -n "${SLIMRMM_TOKEN}" ]; then
        INSTALL_CMD="${INSTALL_CMD} -k ${SLIMRMM_TOKEN}"
    fi

    # Run installation
    eval "${INSTALL_CMD}"

    echo "SlimRMM Agent installed successfully"
    exit 0
fi

# Fresh install without configuration
echo ""
echo "================================================"
echo "SlimRMM Agent installed successfully!"
echo ""
echo "To complete setup, run:"
echo "  sudo slimrmm-agent install -s https://your-server.com -k TOKEN"
echo ""
echo "Or check status:"
echo "  slimrmm-agent status"
echo "================================================"

exit 0
