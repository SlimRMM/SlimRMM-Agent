// Package installer provides service installation for different platforms.
package installer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// Linux systemd service
	systemdServiceName = "slimrmm-agent"
	systemdServicePath = "/etc/systemd/system/slimrmm-agent.service"

	// macOS launchd plist
	launchdPlistName = "io.slimrmm.agent"
	launchdPlistPath = "/Library/LaunchDaemons/io.slimrmm.agent.plist"
)

// systemdServiceTemplate is the systemd unit file template.
const systemdServiceTemplate = `[Unit]
Description=SlimRMM Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=10
User=root
Environment="SLIMRMM_SERVICE=1"

[Install]
WantedBy=multi-user.target
`

// launchdPlistTemplate is the launchd plist template.
const launchdPlistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.slimrmm.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/Library/Logs/SlimRMM/agent.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/SlimRMM/agent.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>SLIMRMM_SERVICE</key>
        <string>1</string>
    </dict>
</dict>
</plist>
`

// InstallService installs and starts the service for the current platform.
func InstallService() error {
	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("getting executable path: %w", err)
	}

	// Resolve symlinks to get the real path
	binaryPath, err = filepath.EvalSymlinks(binaryPath)
	if err != nil {
		return fmt.Errorf("resolving executable path: %w", err)
	}

	switch runtime.GOOS {
	case "linux":
		return installSystemdService(binaryPath)
	case "darwin":
		return installLaunchdService(binaryPath)
	case "windows":
		return installWindowsService(binaryPath)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// installSystemdService installs and starts a systemd service on Linux.
func installSystemdService(binaryPath string) error {
	// Generate service file content
	serviceContent := fmt.Sprintf(systemdServiceTemplate, binaryPath)

	// Write service file
	if err := os.WriteFile(systemdServicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("writing service file: %w", err)
	}

	// Reload systemd
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("reloading systemd: %w", err)
	}

	// Enable service
	if err := exec.Command("systemctl", "enable", systemdServiceName).Run(); err != nil {
		return fmt.Errorf("enabling service: %w", err)
	}

	// Start service
	if err := exec.Command("systemctl", "start", systemdServiceName).Run(); err != nil {
		return fmt.Errorf("starting service: %w", err)
	}

	return nil
}

// installLaunchdService installs and starts a launchd service on macOS.
func installLaunchdService(binaryPath string) error {
	// Ensure log directory exists
	logDir := "/Library/Logs/SlimRMM"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("creating log directory: %w", err)
	}

	// Also ensure data directory exists for config file
	dataDir := "/Applications/SlimRMM.app/Contents/Data"
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("creating data directory: %w", err)
	}

	// Ensure certs directory exists
	certsDir := filepath.Join(dataDir, "certs")
	if err := os.MkdirAll(certsDir, 0700); err != nil {
		return fmt.Errorf("creating certs directory: %w", err)
	}

	// Create CLI symlink at /usr/local/bin for easy command-line access
	cliSymlink := "/usr/local/bin/slimrmm-agent"
	appBinary := "/Applications/SlimRMM.app/Contents/MacOS/slimrmm-agent"

	// Ensure /usr/local/bin exists
	if err := os.MkdirAll("/usr/local/bin", 0755); err == nil {
		// Remove existing symlink or file
		os.Remove(cliSymlink)
		// Create symlink to App bundle binary
		if err := os.Symlink(appBinary, cliSymlink); err != nil {
			// Not fatal - user can still use full path
			fmt.Printf("Note: Could not create CLI symlink at %s: %v\n", cliSymlink, err)
		}
	}

	// Generate plist content
	plistContent := fmt.Sprintf(launchdPlistTemplate, binaryPath)

	// Stop and remove existing service if present (use both old and new methods)
	// Try modern bootout first
	exec.Command("launchctl", "bootout", "system/"+launchdPlistName).Run()
	// Also try legacy unload as fallback
	exec.Command("launchctl", "unload", launchdPlistPath).Run()

	// Write plist file
	if err := os.WriteFile(launchdPlistPath, []byte(plistContent), 0644); err != nil {
		return fmt.Errorf("writing plist file: %w", err)
	}

	// Use launchctl bootstrap for modern macOS (10.11+)
	// bootstrap system <path> is the modern way to load system daemons
	bootstrapCmd := exec.Command("launchctl", "bootstrap", "system", launchdPlistPath)
	if err := bootstrapCmd.Run(); err != nil {
		// Fallback to legacy load command for older macOS versions
		loadCmd := exec.Command("launchctl", "load", "-w", launchdPlistPath)
		if err := loadCmd.Run(); err != nil {
			return fmt.Errorf("loading service: %w", err)
		}
	}

	// Verify service actually started by checking if it's listed
	// Give it a moment to start
	time.Sleep(1 * time.Second)

	listCmd := exec.Command("launchctl", "list", launchdPlistName)
	if err := listCmd.Run(); err != nil {
		// Service isn't listed - check the log for errors
		logPath := filepath.Join(logDir, "agent.log")
		if logData, readErr := os.ReadFile(logPath); readErr == nil && len(logData) > 0 {
			// Return last 500 bytes of log
			logStr := string(logData)
			if len(logStr) > 500 {
				logStr = logStr[len(logStr)-500:]
			}
			return fmt.Errorf("service not running after start. Check log: %s", logStr)
		}
		return fmt.Errorf("service failed to start (not listed in launchctl)")
	}

	return nil
}

// installWindowsService installs a Windows service.
func installWindowsService(binaryPath string) error {
	// Use PowerShell for better error handling and timeout support
	psInstall := fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		try {
			$serviceName = 'SlimRMMAgent'
			$binaryPath = '%s'

			# Stop existing service if running
			$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
			if ($existing) {
				if ($existing.Status -ne 'Stopped') {
					Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
					$existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) 2>$null
				}
				# Update binary path using sc.exe (works on all PowerShell versions)
				# Note: sc.exe requires a space after 'binPath='
				$quotedPath = '"' + $binaryPath + '"'
				$scResult = & sc.exe config $serviceName binPath= $quotedPath 2>&1
				if ($LASTEXITCODE -ne 0) {
					throw "Failed to update service binary path: $scResult"
				}
			} else {
				# Create new service
				New-Service -Name $serviceName -BinaryPathName $binaryPath -DisplayName 'SlimRMM Agent' -StartupType Automatic -Description 'SlimRMM Remote Monitoring and Management Agent' | Out-Null
			}

			# Configure failure recovery using sc.exe
			& sc.exe failure $serviceName reset= 86400 actions= restart/10000/restart/10000/restart/10000 | Out-Null

			# Start service
			Start-Service -Name $serviceName -ErrorAction Stop
			$svc = Get-Service -Name $serviceName
			$svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))

			Write-Output 'SUCCESS'
		} catch {
			Write-Error $_.Exception.Message
			exit 1
		}
	`, binaryPath)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psInstall)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("installing service: %s", strings.TrimSpace(string(output)))
	}

	return nil
}

// UninstallService stops and removes the service.
func UninstallService() error {
	switch runtime.GOOS {
	case "linux":
		return uninstallSystemdService()
	case "darwin":
		return uninstallLaunchdService()
	case "windows":
		return uninstallWindowsService()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// uninstallSystemdService stops and removes the systemd service.
func uninstallSystemdService() error {
	// Stop service
	exec.Command("systemctl", "stop", systemdServiceName).Run()

	// Disable service
	exec.Command("systemctl", "disable", systemdServiceName).Run()

	// Remove service file
	os.Remove(systemdServicePath)

	// Reload systemd
	exec.Command("systemctl", "daemon-reload").Run()

	return nil
}

// uninstallLaunchdService stops and removes the launchd service.
func uninstallLaunchdService() error {
	// Try modern bootout first
	exec.Command("launchctl", "bootout", "system/"+launchdPlistName).Run()
	// Also try legacy unload as fallback
	exec.Command("launchctl", "unload", launchdPlistPath).Run()

	// Remove plist file
	os.Remove(launchdPlistPath)

	return nil
}

// uninstallWindowsService stops and removes the Windows service.
func uninstallWindowsService() error {
	// Use PowerShell for reliable service removal with force stop
	psUninstall := `
		$ErrorActionPreference = 'SilentlyContinue'
		$serviceName = 'SlimRMMAgent'

		$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
		if ($svc) {
			# Force stop with timeout
			if ($svc.Status -ne 'Stopped') {
				Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
				$svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) 2>$null
			}

			# Remove service (Windows 10 1903+ has Remove-Service)
			if (Get-Command Remove-Service -ErrorAction SilentlyContinue) {
				Remove-Service -Name $serviceName -ErrorAction SilentlyContinue
			} else {
				& sc.exe delete $serviceName 2>&1 | Out-Null
			}
		}
		Write-Output 'SUCCESS'
	`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psUninstall)
	cmd.Run() // Ignore errors - service may not exist
	return nil
}

// IsServiceInstalled checks if the service is installed.
func IsServiceInstalled() bool {
	switch runtime.GOOS {
	case "linux":
		_, err := os.Stat(systemdServicePath)
		return err == nil
	case "darwin":
		_, err := os.Stat(launchdPlistPath)
		return err == nil
	case "windows":
		// Use PowerShell Get-Service for reliable detection
		psCheck := `
			$svc = Get-Service -Name 'SlimRMMAgent' -ErrorAction SilentlyContinue
			if ($svc) { exit 0 } else { exit 1 }
		`
		cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCheck)
		return cmd.Run() == nil
	default:
		return false
	}
}

// IsServiceRunning checks if the service is currently running.
func IsServiceRunning() (bool, error) {
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("systemctl", "is-active", systemdServiceName).Output()
		if err != nil {
			return false, nil // Service not active is not an error
		}
		return strings.TrimSpace(string(out)) == "active", nil
	case "darwin":
		err := exec.Command("launchctl", "list", launchdPlistName).Run()
		return err == nil, nil
	case "windows":
		// Use PowerShell Get-Service for reliable status check
		psCheck := `
			$svc = Get-Service -Name 'SlimRMMAgent' -ErrorAction SilentlyContinue
			if ($svc -and $svc.Status -eq 'Running') { exit 0 } else { exit 1 }
		`
		cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCheck)
		return cmd.Run() == nil, nil
	default:
		return false, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// StopService stops the service without uninstalling it.
func StopService() error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("systemctl", "stop", systemdServiceName).Run()
	case "darwin":
		// Use bootout for modern macOS, fallback to unload
		err := exec.Command("launchctl", "bootout", "system", launchdPlistPath).Run()
		if err != nil {
			// Fallback to older unload command
			return exec.Command("launchctl", "unload", launchdPlistPath).Run()
		}
		return nil
	case "windows":
		// Use PowerShell Stop-Service with -Force and timeout
		psStop := `
			$ErrorActionPreference = 'SilentlyContinue'
			$svc = Get-Service -Name 'SlimRMMAgent' -ErrorAction SilentlyContinue
			if ($svc -and $svc.Status -ne 'Stopped') {
				Stop-Service -Name 'SlimRMMAgent' -Force -ErrorAction SilentlyContinue
				$svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) 2>$null
			}
		`
		cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psStop)
		return cmd.Run()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// RestartService restarts the service.
func RestartService() error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("systemctl", "restart", systemdServiceName).Run()
	case "darwin":
		// Use kickstart for restart on modern macOS
		kickstartCmd := exec.Command("launchctl", "kickstart", "-k", "system/"+launchdPlistName)
		if err := kickstartCmd.Run(); err != nil {
			// Fallback to bootout/bootstrap for older systems
			exec.Command("launchctl", "bootout", "system/"+launchdPlistName).Run()
			time.Sleep(500 * time.Millisecond)
			if err := exec.Command("launchctl", "bootstrap", "system", launchdPlistPath).Run(); err != nil {
				// Final fallback to legacy unload/load
				exec.Command("launchctl", "unload", launchdPlistPath).Run()
				return exec.Command("launchctl", "load", "-w", launchdPlistPath).Run()
			}
		}
		return nil
	case "windows":
		// Use PowerShell Restart-Service with -Force and timeout
		psRestart := `
			$ErrorActionPreference = 'Stop'
			try {
				Restart-Service -Name 'SlimRMMAgent' -Force -ErrorAction Stop
				$svc = Get-Service -Name 'SlimRMMAgent'
				$svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
				Write-Output 'SUCCESS'
			} catch {
				Write-Error $_.Exception.Message
				exit 1
			}
		`
		cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psRestart)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("restarting service: %s", strings.TrimSpace(string(output)))
		}
		return nil
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// IsRunningAsService returns true if the process is running as a system service.
func IsRunningAsService() bool {
	return os.Getenv("SLIMRMM_SERVICE") == "1"
}
