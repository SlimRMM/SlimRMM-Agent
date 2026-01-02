#!/bin/bash
set -e

# Stop and disable service
systemctl stop slimrmm-agent || true
systemctl disable slimrmm-agent || true

echo "SlimRMM Agent stopped"
