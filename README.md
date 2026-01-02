# SlimRMM Agent v2.0

Lightweight, secure Remote Monitoring & Management agent rewritten in Go.

> **Note**: This is v2.0 of the SlimRMM Agent. The previous Python implementation has been archived to [SlimRMM-Agent-Python](https://github.com/SlimRMM/SlimRMM-Agent-Python).

## Features

- **Cross-Platform**: Linux, macOS, Windows
- **Secure**: mTLS, command whitelisting, path validation
- **Lightweight**: ~10 MB binary, ~20 MB RAM
- **Real-time**: WebSocket-based communication
- **Monitoring**: CPU, memory, disk, network stats
- **Management**: Remote commands, file operations, software inventory

## Installation

### Linux (DEB)

```bash
# With auto-registration
SLIMRMM_SERVER="https://your-server.com" SLIMRMM_KEY="your-key" \
  sudo dpkg -i slimrmm-agent_*.deb

# Manual registration
sudo dpkg -i slimrmm-agent_*.deb
sudo slimrmm-agent --install --server https://your-server.com --key your-key
```

### macOS (PKG)

```bash
sudo installer -pkg slimrmm-agent_*.pkg -target /
sudo slimrmm-agent --install --server https://your-server.com
```

### Windows (MSI)

```powershell
msiexec /i SlimRMM-Agent.msi /qn SLIMRMM_SERVER="https://your-server.com"
```

## Building

### Development

```bash
go build -o slimrmm-agent ./cmd/slimrmm-agent
./slimrmm-agent --version
```

### Production

```bash
VERSION=1.0.0
COMMIT=$(git rev-parse --short HEAD)
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

go build -ldflags "-s -w \
  -X github.com/kiefernetworks/slimrmm-agent/pkg/version.Version=$VERSION \
  -X github.com/kiefernetworks/slimrmm-agent/pkg/version.GitCommit=$COMMIT \
  -X github.com/kiefernetworks/slimrmm-agent/pkg/version.BuildDate=$DATE" \
  -o slimrmm-agent ./cmd/slimrmm-agent
```

### Cross-Compile

```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o slimrmm-agent-linux-amd64 ./cmd/slimrmm-agent

# macOS ARM64
GOOS=darwin GOARCH=arm64 go build -o slimrmm-agent-darwin-arm64 ./cmd/slimrmm-agent

# Windows AMD64
GOOS=windows GOARCH=amd64 go build -o slimrmm-agent-windows-amd64.exe ./cmd/slimrmm-agent
```

### Release

```bash
goreleaser release --clean
```

## Configuration

Configuration is stored in `/var/lib/slimrmm/.slimrmm_config.json`:

```json
{
  "server": "https://your-server.com",
  "uuid": "agent-uuid",
  "mtls_enabled": true
}
```

## Service Management

### Linux (systemd)

```bash
sudo systemctl status slimrmm-agent
sudo systemctl restart slimrmm-agent
sudo journalctl -u slimrmm-agent -f
```

### macOS (launchd)

```bash
sudo launchctl list | grep slimrmm
sudo launchctl kickstart -k system/io.slimrmm.agent
```

### Windows

```powershell
sc query SlimRMMAgent
sc stop SlimRMMAgent
sc start SlimRMMAgent
```

## Architecture

```
cmd/slimrmm-agent/     # Entry point
internal/
├── config/            # Configuration management
├── handler/           # WebSocket message handling
├── actions/           # Action implementations
├── monitor/           # System monitoring
├── service/           # Service management
├── installer/         # Registration
├── osquery/           # osquery integration
└── security/
    ├── mtls/          # mTLS certificates
    ├── sandbox/       # Command whitelisting
    ├── pathval/       # Path validation
    └── archive/       # ZIP security
pkg/version/           # Version info
```

## Security

- **mTLS**: Mutual TLS authentication
- **Command Whitelist**: Only approved commands
- **Path Validation**: Prevents directory traversal
- **ZIP-Slip Prevention**: Safe archive extraction
- **Least Privilege**: Minimal required permissions

## License

Copyright (c) 2025 Kiefer Networks. All rights reserved.
