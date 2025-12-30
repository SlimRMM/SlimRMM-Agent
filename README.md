# SlimRMM Agent

A lightweight, cross-platform Remote Monitoring and Management (RMM) agent developed by Kiefer Networks.

## Features

- **Real-time Monitoring**: CPU, memory, disk, and network statistics
- **Remote Management**: Execute commands, manage files, control services
- **Software Inventory**: Track installed applications and updates
- **Remote Desktop**: Secure screen sharing and remote control (macOS/Linux)
- **Secure Communication**: WebSocket-based with certificate authentication
- **Cross-Platform**: Supports macOS (Apple Silicon) and Linux

## System Requirements

### macOS
- macOS 12.0 (Monterey) or later
- Apple Silicon (M1/M2/M3)
- Administrator privileges for installation

### Linux
- Ubuntu 20.04+, Debian 11+, RHEL 8+, or compatible
- x86_64 architecture
- Root privileges for installation

## Installation

### macOS (PKG Installer)

Download the latest `.pkg` file from the [Releases](https://github.com/SlimRMM/SlimRMM-Agent/releases) page and run:

```bash
sudo installer -pkg SlimRMM-Agent-x.x.x-arm64.pkg -target /
```

Or double-click the PKG file in Finder.

After installation, grant the required permissions:
1. Open **System Settings** > **Privacy & Security**
2. Add `/var/lib/slimrmm/slimrmm-agent` to:
   - **Full Disk Access** (required)
   - **Screen Recording** (optional, for remote desktop)

### Linux (DEB)

```bash
sudo dpkg -i slimrmm-agent_x.x.x_amd64.deb
```

### Linux (RPM)

```bash
sudo rpm -i slimrmm-agent-x.x.x.x86_64.rpm
```

## Configuration

After installation, register the agent with your SlimRMM server:

```bash
sudo slimrmm-agent --install --installation-key <YOUR_KEY> --server https://your-server.com
```

The configuration is stored in `/var/lib/slimrmm/.slimrmm_config.json`.

## Directory Structure

```
/var/lib/slimrmm/
├── slimrmm-agent          # Main binary
├── .slimrmm_config.json   # Configuration file
├── certs/                 # TLS certificates
│   ├── agent.crt
│   ├── agent.key
│   └── ca.crt
└── log/                   # Log files
    ├── stdout.log
    └── stderr.log
```

## Service Management

### macOS

```bash
# Start
sudo launchctl kickstart system/io.slimrmm.agent

# Stop
sudo launchctl kill SIGTERM system/io.slimrmm.agent

# Restart
sudo launchctl kickstart -k system/io.slimrmm.agent

# View status
sudo launchctl list | grep slimrmm
```

### Linux (systemd)

```bash
# Start
sudo systemctl start slimrmm-agent

# Stop
sudo systemctl stop slimrmm-agent

# Restart
sudo systemctl restart slimrmm-agent

# View status
sudo systemctl status slimrmm-agent

# View logs
sudo journalctl -u slimrmm-agent -f
```

## Uninstallation

### macOS

```bash
sudo slimrmm-agent --uninstall
```

Or manually:

```bash
sudo launchctl bootout system/io.slimrmm.agent
sudo rm /Library/LaunchDaemons/io.slimrmm.agent.plist
sudo rm -rf /var/lib/slimrmm
sudo pkgutil --forget io.slimrmm.agent
```

### Linux

```bash
# DEB-based
sudo apt remove slimrmm-agent

# RPM-based
sudo rpm -e slimrmm-agent
```

## Building from Source

### Prerequisites

- Python 3.9+
- PyInstaller
- Required Python packages (see `requirements.txt`)

### Build Commands

```bash
# macOS PKG
./build-macos-pkg.sh 1.0.0

# Linux
./build-linux-agent.sh 1.0.0
```

## Security

- All communication is encrypted using TLS
- Agent authenticates using client certificates
- Configuration files have restricted permissions (600)
- Certificate private keys are never transmitted

## License

Copyright (c) 2025 Kiefer Networks. All rights reserved.

## Support

For support, please contact support@kiefer-networks.de or visit https://slimrmm.io
