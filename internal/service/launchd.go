// Package service provides launchd service management for macOS.
package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
)

const launchdPlistPath = "/Library/LaunchDaemons"

const launchdPlistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{{.Name}}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{.ExecPath}}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{{.WorkingDir}}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/lib/slimrmm/log/agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/lib/slimrmm/log/agent.log</string>
    <key>ThrottleInterval</key>
    <integer>10</integer>
</dict>
</plist>
`

// LaunchdManager manages launchd services on macOS.
type LaunchdManager struct{}

// Install installs a launchd service.
func (m *LaunchdManager) Install(name, displayName, description, execPath string) error {
	if m.IsInstalled(name) {
		return ErrServiceExists
	}

	cfg := &ServiceConfig{
		Name:       name,
		ExecPath:   execPath,
		WorkingDir: "/var/lib/slimrmm",
	}

	return m.InstallWithConfig(cfg)
}

// InstallWithConfig installs a launchd service with full configuration.
func (m *LaunchdManager) InstallWithConfig(cfg *ServiceConfig) error {
	plistPath := filepath.Join(launchdPlistPath, cfg.Name+".plist")

	tmpl, err := template.New("launchd").Parse(launchdPlistTemplate)
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	f, err := os.Create(plistPath)
	if err != nil {
		return fmt.Errorf("creating plist file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, cfg); err != nil {
		return fmt.Errorf("writing plist file: %w", err)
	}

	// Set permissions
	if err := os.Chmod(plistPath, 0644); err != nil {
		return fmt.Errorf("setting permissions: %w", err)
	}

	// Load the service
	if err := exec.Command("launchctl", "bootstrap", "system", plistPath).Run(); err != nil {
		// Try legacy load command
		exec.Command("launchctl", "load", "-w", plistPath).Run()
	}

	return nil
}

// Uninstall removes a launchd service.
func (m *LaunchdManager) Uninstall(name string) error {
	plistPath := filepath.Join(launchdPlistPath, name+".plist")

	// Unload the service
	exec.Command("launchctl", "bootout", "system", plistPath).Run()
	exec.Command("launchctl", "unload", "-w", plistPath).Run()

	// Remove plist file
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing plist file: %w", err)
	}

	return nil
}

// Start starts a launchd service.
func (m *LaunchdManager) Start(name string) error {
	cmd := exec.Command("launchctl", "kickstart", "-k", "system/"+name)
	if _, err := cmd.CombinedOutput(); err != nil {
		// Try legacy start
		cmd = exec.Command("launchctl", "start", name)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("starting service: %s", string(output))
		}
	}
	return nil
}

// Stop stops a launchd service.
func (m *LaunchdManager) Stop(name string) error {
	cmd := exec.Command("launchctl", "kill", "SIGTERM", "system/"+name)
	if _, err := cmd.CombinedOutput(); err != nil {
		// Try legacy stop
		exec.Command("launchctl", "stop", name).Run()
	}
	return nil
}

// Status returns the status of a launchd service.
func (m *LaunchdManager) Status(name string) (ServiceStatus, error) {
	cmd := exec.Command("launchctl", "list", name)
	output, err := cmd.Output()
	if err != nil {
		return StatusStopped, nil
	}

	outputStr := string(output)

	// Parse output - if PID is present, service is running
	if strings.Contains(outputStr, "PID") {
		return StatusRunning, nil
	}

	// Check for running processes
	lines := strings.Split(outputStr, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[2] == name {
			if fields[0] != "-" {
				return StatusRunning, nil
			}
		}
	}

	return StatusStopped, nil
}

// IsInstalled checks if a launchd service is installed.
func (m *LaunchdManager) IsInstalled(name string) bool {
	plistPath := filepath.Join(launchdPlistPath, name+".plist")
	_, err := os.Stat(plistPath)
	return err == nil
}
