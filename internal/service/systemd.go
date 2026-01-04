// Package service provides systemd service management for Linux.
package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
)

const systemdUnitPath = "/etc/systemd/system"

const systemdUnitTemplate = `[Unit]
Description={{.Description}}
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={{.ExecPath}}
WorkingDirectory={{.WorkingDir}}
Restart=always
RestartSec=10
User={{.User}}
Group={{.Group}}
{{range $key, $value := .Environment}}
Environment="{{$key}}={{$value}}"
{{end}}

# Logging - use standard log location
StandardOutput=append:/var/log/slimrmm/agent.log
StandardError=append:/var/log/slimrmm/agent.log

[Install]
WantedBy=multi-user.target
`

// SystemdManager manages systemd services.
type SystemdManager struct{}

// Install installs a systemd service.
func (m *SystemdManager) Install(name, displayName, description, execPath string) error {
	if m.IsInstalled(name) {
		return ErrServiceExists
	}

	cfg := &ServiceConfig{
		Name:        name,
		DisplayName: displayName,
		Description: description,
		ExecPath:    execPath,
		WorkingDir:  "/var/lib/slimrmm",
		User:        "root",
		Group:       "root",
		Environment: make(map[string]string),
	}

	return m.InstallWithConfig(cfg)
}

// InstallWithConfig installs a systemd service with full configuration.
func (m *SystemdManager) InstallWithConfig(cfg *ServiceConfig) error {
	unitPath := filepath.Join(systemdUnitPath, cfg.Name+".service")

	tmpl, err := template.New("systemd").Parse(systemdUnitTemplate)
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	f, err := os.Create(unitPath)
	if err != nil {
		return fmt.Errorf("creating unit file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, cfg); err != nil {
		return fmt.Errorf("writing unit file: %w", err)
	}

	// Reload systemd
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("reloading systemd: %w", err)
	}

	// Enable service
	if err := exec.Command("systemctl", "enable", cfg.Name).Run(); err != nil {
		return fmt.Errorf("enabling service: %w", err)
	}

	return nil
}

// Uninstall removes a systemd service.
func (m *SystemdManager) Uninstall(name string) error {
	// Stop service first
	exec.Command("systemctl", "stop", name).Run()

	// Disable service
	exec.Command("systemctl", "disable", name).Run()

	// Remove unit file
	unitPath := filepath.Join(systemdUnitPath, name+".service")
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing unit file: %w", err)
	}

	// Reload systemd
	exec.Command("systemctl", "daemon-reload").Run()

	return nil
}

// Start starts a systemd service.
func (m *SystemdManager) Start(name string) error {
	cmd := exec.Command("systemctl", "start", name)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("starting service: %s", string(output))
	}
	return nil
}

// Stop stops a systemd service.
func (m *SystemdManager) Stop(name string) error {
	cmd := exec.Command("systemctl", "stop", name)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("stopping service: %s", string(output))
	}
	return nil
}

// Status returns the status of a systemd service.
func (m *SystemdManager) Status(name string) (ServiceStatus, error) {
	cmd := exec.Command("systemctl", "is-active", name)
	output, _ := cmd.Output()

	status := strings.TrimSpace(string(output))
	switch status {
	case "active":
		return StatusRunning, nil
	case "inactive", "failed":
		return StatusStopped, nil
	default:
		return StatusUnknown, nil
	}
}

// IsInstalled checks if a systemd service is installed.
func (m *SystemdManager) IsInstalled(name string) bool {
	unitPath := filepath.Join(systemdUnitPath, name+".service")
	_, err := os.Stat(unitPath)
	return err == nil
}

// Restart restarts a systemd service.
func (m *SystemdManager) Restart(name string) error {
	cmd := exec.Command("systemctl", "restart", name)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("restarting service: %s", string(output))
	}
	return nil
}

// List lists all systemd services.
func (m *SystemdManager) List() ([]ServiceInfo, error) {
	// List all unit files
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("listing services: %w", err)
	}

	var services []ServiceInfo
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse: UNIT LOAD ACTIVE SUB DESCRIPTION
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		name := strings.TrimSuffix(fields[0], ".service")
		active := fields[2]
		// Description is the rest of the fields
		description := ""
		if len(fields) > 4 {
			description = strings.Join(fields[4:], " ")
		}

		// Get enabled status
		enabledCmd := exec.Command("systemctl", "is-enabled", name)
		enabledOutput, _ := enabledCmd.Output()
		enabledStatus := strings.TrimSpace(string(enabledOutput))
		enabled := enabledStatus == "enabled"

		startType := "manual"
		if enabled {
			startType = "auto"
		} else if enabledStatus == "disabled" {
			startType = "disabled"
		}

		status := StatusStopped
		if active == "active" {
			status = StatusRunning
		}

		services = append(services, ServiceInfo{
			Name:        name,
			DisplayName: name,
			Description: description,
			Status:      status,
			Enabled:     enabled,
			StartType:   startType,
		})
	}

	return services, nil
}
