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
	// Check if service exists
	checkCmd := exec.Command("sc", "query", "SlimRMMAgent")
	if checkCmd.Run() == nil {
		// Service exists, stop it first
		exec.Command("sc", "stop", "SlimRMMAgent").Run()
	}

	// Create or update service
	createCmd := exec.Command("sc", "create", "SlimRMMAgent",
		"binPath=", binaryPath,
		"start=", "auto",
		"DisplayName=", "SlimRMM Agent",
	)
	if err := createCmd.Run(); err != nil {
		// Try to update if creation fails
		updateCmd := exec.Command("sc", "config", "SlimRMMAgent",
			"binPath=", binaryPath,
		)
		if err := updateCmd.Run(); err != nil {
			return fmt.Errorf("configuring service: %w", err)
		}
	}

	// Set service description
	exec.Command("sc", "description", "SlimRMMAgent", "SlimRMM Remote Monitoring and Management Agent").Run()

	// Start service
	if err := exec.Command("sc", "start", "SlimRMMAgent").Run(); err != nil {
		return fmt.Errorf("starting service: %w", err)
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
	// Stop service
	exec.Command("sc", "stop", "SlimRMMAgent").Run()

	// Delete service
	exec.Command("sc", "delete", "SlimRMMAgent").Run()

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
		return exec.Command("sc", "query", "SlimRMMAgent").Run() == nil
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
		out, err := exec.Command("sc", "query", "SlimRMMAgent").Output()
		if err != nil {
			return false, nil
		}
		return strings.Contains(string(out), "RUNNING"), nil
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
		return exec.Command("sc", "stop", "SlimRMMAgent").Run()
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
		exec.Command("sc", "stop", "SlimRMMAgent").Run()
		return exec.Command("sc", "start", "SlimRMMAgent").Run()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// IsRunningAsService returns true if the process is running as a system service.
func IsRunningAsService() bool {
	return os.Getenv("SLIMRMM_SERVICE") == "1"
}
