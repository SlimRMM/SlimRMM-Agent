#!/bin/bash
set -e

# SlimRMM Agent Pre-Removal Script
echo "Stopping SlimRMM Agent..."

# Use the agent's uninstall command to cleanly remove service and config
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
