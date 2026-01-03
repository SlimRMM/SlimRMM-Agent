#!/bin/bash
set -e

# SlimRMM Agent Post-Installation Script
# Installs as systemd service and auto-registers if SLIMRMM_SERVER is set
# Arguments:
#   Debian: $1 = "configure" (fresh install or upgrade)
#   RPM: $1 = number of packages (1 = fresh install, 2+ = upgrade)

CONFIG_DIR="/var/lib/slimrmm"
CONFIG_FILE="$CONFIG_DIR/.slimrmm_config.json"
BACKUP_DIR="/tmp/slimrmm-upgrade-backup"

echo "Installing SlimRMM Agent..."

# Restore backed up configuration from upgrade
restore_backup() {
    if [ -d "$BACKUP_DIR" ]; then
        echo "Restoring configuration from upgrade backup..."
        mkdir -p "$CONFIG_DIR"

        # Restore config file
        if [ -f "$BACKUP_DIR/.slimrmm_config.json" ]; then
            cp -p "$BACKUP_DIR/.slimrmm_config.json" "$CONFIG_FILE"
            echo "Configuration restored"
        fi

        # Restore certificates
        for cert_file in ca.crt client.crt client.key; do
            if [ -f "$BACKUP_DIR/$cert_file" ]; then
                cp -p "$BACKUP_DIR/$cert_file" "$CONFIG_DIR/"
            fi
        done

        # Restore Proxmox token
        if [ -f "$BACKUP_DIR/.proxmox_token.json" ]; then
            cp -p "$BACKUP_DIR/.proxmox_token.json" "$CONFIG_DIR/"
        fi

        # Clean up backup
        rm -rf "$BACKUP_DIR"
        return 0
    fi
    return 1
}

# Check for upgrade backup first
if restore_backup; then
    echo "Upgrade detected - starting service with existing configuration..."
    # Install and start service with existing config
    systemctl daemon-reload
    systemctl enable slimrmm-agent 2>/dev/null || true
    systemctl start slimrmm-agent
    echo "SlimRMM Agent upgraded and started successfully"
elif [ -n "$SLIMRMM_SERVER" ]; then
    # Fresh install with server URL provided
    echo "Server URL provided: $SLIMRMM_SERVER"
    export SLIMRMM_SERVER
    /usr/local/bin/slimrmm-agent --install-service
elif [ -f "$CONFIG_FILE" ]; then
    # Config exists (shouldn't happen normally, but handle it)
    echo "Existing configuration found, starting service..."
    /usr/local/bin/slimrmm-agent --install-service
else
    # Fresh install without server URL
    echo ""
    echo "================================================"
    echo "SlimRMM Agent installed but not configured."
    echo ""
    echo "To complete setup, run:"
    echo "  SLIMRMM_SERVER=https://your-server.com slimrmm-agent --install-service"
    echo ""
    echo "Or with enrollment token for auto-approval:"
    echo "  SLIMRMM_SERVER=https://your-server.com SLIMRMM_TOKEN=your-token slimrmm-agent --install-service"
    echo "================================================"
fi

echo "SlimRMM Agent installation complete"
