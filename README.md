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

### Windows
- Windows 10/11 (64-bit)
- Administrator privileges for installation

### macOS
- macOS 12.0 (Monterey) or later
- Apple Silicon (M1/M2/M3)
- Administrator privileges for installation

### Linux
- Ubuntu 20.04+, Debian 11+, RHEL 8+, or compatible
- x86_64 or ARM64 architecture
- Root privileges for installation

## Installation

### Windows (MSI Installer)

Download the latest `.msi` file from the [Releases](https://github.com/SlimRMM/SlimRMM-Agent/releases) page.

Double-click the MSI file, or install via command line (Run as Administrator):

```cmd
msiexec /i SlimRMM-Agent-x.x.x-x64.msi
```

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

### Windows

```cmd
# Start (Run as Administrator)
sc start SlimRMMAgent

# Stop
sc stop SlimRMMAgent

# Query status
sc query SlimRMMAgent

# View logs (in Event Viewer or)
Get-EventLog -LogName Application -Source SlimRMMAgent
```

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

### Windows

Via Control Panel > Programs and Features, or:

```cmd
msiexec /x SlimRMM-Agent-*.msi /qn
```

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

## Silent Installation

For automated deployments, you can pass server credentials during installation:

### Windows

```cmd
msiexec /i SlimRMM-Agent-1.0.0-x64.msi /qn SLIMRMM_SERVER="https://rmm.example.com" SLIMRMM_KEY="your-installation-key"
```

### macOS

```bash
SLIMRMM_SERVER="https://rmm.example.com" SLIMRMM_KEY="your-installation-key" \
  sudo installer -pkg SlimRMM-Agent-1.0.0-arm64.pkg -target /
```

### Linux

```bash
SLIMRMM_SERVER="https://rmm.example.com" SLIMRMM_KEY="your-installation-key" \
  sudo dpkg -i slimrmm-agent_1.0.0_amd64.deb
```

## Building from Source

### Prerequisites

- Python 3.9+
- PyInstaller
- Required Python packages (see `requirements.txt`)
- For Linux builds: Docker (recommended) or dpkg-dev/rpm-build
- For Windows builds: WiX Toolset v3

### Windows MSI

On a Windows system with WiX Toolset installed:

```powershell
.\build-windows-msi.ps1 -Version 1.0.0
```

Or using the batch file:

```cmd
build-windows.bat 1.0.0
```

Output: `dist\SlimRMM-Agent-1.0.0-x64.msi`

### macOS PKG

```bash
./build-macos-pkg.sh 1.0.0
```

Output: `dist/SlimRMM-Agent-1.0.0-arm64.pkg`

### Linux (Docker-based - Recommended)

Build both DEB and RPM packages using Docker (works on any OS):

```bash
# Build all packages
./build-linux.sh 1.0.0 all

# Build DEB only
./build-linux.sh 1.0.0 deb

# Build RPM only
./build-linux.sh 1.0.0 rpm
```

Using Docker Compose:

```bash
# Build all
VERSION=1.0.0 docker compose -f docker-compose.build.yml up build-all

# Build DEB only
VERSION=1.0.0 docker compose -f docker-compose.build.yml up build-deb

# Build RPM only
VERSION=1.0.0 docker compose -f docker-compose.build.yml up build-rpm
```

### Linux (Native)

On a Linux system with build tools installed:

```bash
# DEB package (requires dpkg-dev)
./build-linux-deb.sh 1.0.0 amd64

# RPM package (requires rpm-build)
./build-linux-rpm.sh 1.0.0 x86_64
```

Output:
- `dist/slimrmm-agent_1.0.0_amd64.deb`
- `dist/slimrmm-agent-1.0.0-1.x86_64.rpm`

## Security

- All communication is encrypted using TLS
- Agent authenticates using client certificates
- Configuration files have restricted permissions (600)
- Certificate private keys are never transmitted

## License

Copyright (c) 2025 Kiefer Networks. All rights reserved.

## Support

For support, please contact support@kiefer-networks.de or visit https://slimrmm.io
