#!/bin/bash
set -e

# SlimRMM Agent Pre-Removal Script
# Arguments:
#   Debian: $1 = "remove" | "upgrade" | "deconfigure"
#   RPM: $1 = number of packages remaining (0 = remove, 1+ = upgrade)

CONFIG_DIR="/var/lib/slimrmm"
CONFIG_FILE="$CONFIG_DIR/.slimrmm_config.json"
BACKUP_DIR="/tmp/slimrmm-upgrade-backup"

# Determine if this is an upgrade or complete removal
is_upgrade() {
    # Debian package manager passes "upgrade" as first argument
    if [ "$1" = "upgrade" ]; then
        return 0
    fi
    # RPM: if $1 > 0, it's an upgrade
    if [ -n "$1" ] && [ "$1" -gt 0 ] 2>/dev/null; then
        return 0
    fi
    return 1
}

if is_upgrade "$1"; then
    echo "Upgrading SlimRMM Agent - preserving configuration..."

    # Backup configuration files
    mkdir -p "$BACKUP_DIR"
    if [ -f "$CONFIG_FILE" ]; then
        cp -p "$CONFIG_FILE" "$BACKUP_DIR/"
        echo "Configuration backed up to $BACKUP_DIR"
    fi

    # Backup certificates if they exist
    for cert_file in ca.crt client.crt client.key; do
        if [ -f "$CONFIG_DIR/$cert_file" ]; then
            cp -p "$CONFIG_DIR/$cert_file" "$BACKUP_DIR/"
        fi
    done

    # Backup Proxmox token if exists
    if [ -f "$CONFIG_DIR/.proxmox_token.json" ]; then
        cp -p "$CONFIG_DIR/.proxmox_token.json" "$BACKUP_DIR/"
    fi

    # Only stop service, don't uninstall (preserves config)
    systemctl stop slimrmm-agent 2>/dev/null || true
    echo "SlimRMM Agent stopped for upgrade"
else
    echo "Removing SlimRMM Agent..."

    # Full uninstall - remove everything
    if [ -x "/usr/local/bin/slimrmm-agent" ]; then
        /usr/local/bin/slimrmm-agent --uninstall || true
    else
        # Fallback if binary is missing
        systemctl stop slimrmm-agent 2>/dev/null || true
        systemctl disable slimrmm-agent 2>/dev/null || true
        rm -f /etc/systemd/system/slimrmm-agent.service
        systemctl daemon-reload
    fi

    echo "SlimRMM Agent stopped and service removed"
fi
