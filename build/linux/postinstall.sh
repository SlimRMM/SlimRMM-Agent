#!/bin/bash
set -e

# Create directories
mkdir -p /var/lib/slimrmm/{certs,log}
chmod 700 /var/lib/slimrmm/certs
chmod 755 /var/lib/slimrmm/log

# Check for environment variables for auto-registration
if [ -n "$SLIMRMM_SERVER" ]; then
    echo "Registering agent with server: $SLIMRMM_SERVER"
    /usr/local/bin/slimrmm-agent --install --server "$SLIMRMM_SERVER" ${SLIMRMM_KEY:+--key "$SLIMRMM_KEY"} || true
fi

# Reload systemd
systemctl daemon-reload

# Enable and start service
systemctl enable slimrmm-agent
systemctl start slimrmm-agent || true

echo "SlimRMM Agent installed successfully"
echo "Configure with: slimrmm-agent --install --server https://your-server.com"
