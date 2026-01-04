//go:build linux

package tamper

import (
	"fmt"
	"os/exec"
)

// protectFilePlatform makes a file immutable using chattr +i.
// This prevents modification, deletion, and renaming even by root.
func (p *Protection) protectFilePlatform(path string) error {
	cmd := exec.Command("chattr", "+i", path)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("chattr +i failed: %w", err)
	}
	return nil
}

// unprotectFilePlatform removes the immutable attribute.
func (p *Protection) unprotectFilePlatform(path string) error {
	cmd := exec.Command("chattr", "-i", path)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("chattr -i failed: %w", err)
	}
	return nil
}

// InstallWatchdog installs a systemd watchdog service for the agent.
func InstallWatchdog() error {
	watchdogService := `[Unit]
Description=SlimRMM Agent Watchdog
After=slimrmm-agent.service
Requires=slimrmm-agent.service
PartOf=slimrmm-agent.service

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do systemctl is-active --quiet slimrmm-agent || systemctl start slimrmm-agent; sleep 10; done'
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`

	// Write watchdog service file
	servicePath := "/etc/systemd/system/slimrmm-watchdog.service"
	cmd := exec.Command("bash", "-c", fmt.Sprintf("echo '%s' > %s", watchdogService, servicePath))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to write watchdog service: %w", err)
	}

	// Reload systemd
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	// Enable and start watchdog
	if err := exec.Command("systemctl", "enable", "slimrmm-watchdog").Run(); err != nil {
		return fmt.Errorf("failed to enable watchdog: %w", err)
	}

	if err := exec.Command("systemctl", "start", "slimrmm-watchdog").Run(); err != nil {
		return fmt.Errorf("failed to start watchdog: %w", err)
	}

	return nil
}

// UninstallWatchdog removes the watchdog service.
func UninstallWatchdog() error {
	// Stop and disable watchdog
	_ = exec.Command("systemctl", "stop", "slimrmm-watchdog").Run()
	_ = exec.Command("systemctl", "disable", "slimrmm-watchdog").Run()

	// Remove service file
	_ = exec.Command("rm", "-f", "/etc/systemd/system/slimrmm-watchdog.service").Run()

	// Reload systemd
	return exec.Command("systemctl", "daemon-reload").Run()
}

// ProtectServiceFile makes the systemd service file immutable.
func ProtectServiceFile() error {
	return exec.Command("chattr", "+i", "/etc/systemd/system/slimrmm-agent.service").Run()
}

// UnprotectServiceFile removes immutable attribute from service file.
func UnprotectServiceFile() error {
	return exec.Command("chattr", "-i", "/etc/systemd/system/slimrmm-agent.service").Run()
}
