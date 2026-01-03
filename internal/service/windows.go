//go:build windows
// +build windows

// Package service provides Windows service management.
package service

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// WindowsManager manages Windows services.
type WindowsManager struct{}

// newWindowsManager creates a new Windows service manager.
func newWindowsManager() Manager {
	return &WindowsManager{}
}

// Install installs a Windows service.
func (m *WindowsManager) Install(name, displayName, description, execPath string) error {
	if m.IsInstalled(name) {
		return ErrServiceExists
	}

	// Use sc.exe to create the service
	cmd := exec.Command("sc", "create", name,
		"binPath=", execPath,
		"DisplayName=", displayName,
		"start=", "auto",
		"obj=", "LocalSystem",
	)

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("creating service: %s", string(output))
	}

	// Set description
	cmd = exec.Command("sc", "description", name, description)
	cmd.Run()

	// Configure failure recovery
	cmd = exec.Command("sc", "failure", name,
		"reset=", "86400",
		"actions=", "restart/10000/restart/10000/restart/10000",
	)
	cmd.Run()

	return nil
}

// Uninstall removes a Windows service.
func (m *WindowsManager) Uninstall(name string) error {
	// Stop service first
	m.Stop(name)

	// Delete service
	cmd := exec.Command("sc", "delete", name)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("deleting service: %s", string(output))
	}

	return nil
}

// Start starts a Windows service.
func (m *WindowsManager) Start(name string) error {
	cmd := exec.Command("sc", "start", name)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("starting service: %s", string(output))
	}
	return nil
}

// Stop stops a Windows service.
func (m *WindowsManager) Stop(name string) error {
	cmd := exec.Command("sc", "stop", name)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Ignore if service is already stopped
		if !strings.Contains(string(output), "not started") {
			return fmt.Errorf("stopping service: %s", string(output))
		}
	}
	return nil
}

// Status returns the status of a Windows service.
func (m *WindowsManager) Status(name string) (ServiceStatus, error) {
	cmd := exec.Command("sc", "query", name)
	output, err := cmd.Output()
	if err != nil {
		return StatusUnknown, ErrServiceNotFound
	}

	outputStr := string(output)
	if strings.Contains(outputStr, "RUNNING") {
		return StatusRunning, nil
	} else if strings.Contains(outputStr, "STOPPED") {
		return StatusStopped, nil
	}

	return StatusUnknown, nil
}

// IsInstalled checks if a Windows service is installed.
func (m *WindowsManager) IsInstalled(name string) bool {
	cmd := exec.Command("sc", "query", name)
	err := cmd.Run()
	return err == nil
}

// Restart restarts a Windows service.
func (m *WindowsManager) Restart(name string) error {
	if err := m.Stop(name); err != nil {
		return err
	}
	return m.Start(name)
}

// List lists all Windows services.
func (m *WindowsManager) List() ([]ServiceInfo, error) {
	// Use PowerShell to get service information
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Get-Service | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json`)
	output, err := cmd.Output()
	if err != nil {
		// Fall back to sc query
		return m.listWithSc()
	}

	// Parse JSON output
	var psServices []struct {
		Name        string `json:"Name"`
		DisplayName string `json:"DisplayName"`
		Status      int    `json:"Status"`
		StartType   int    `json:"StartType"`
	}

	if err := json.Unmarshal(output, &psServices); err != nil {
		return m.listWithSc()
	}

	var services []ServiceInfo
	for _, s := range psServices {
		status := StatusStopped
		if s.Status == 4 { // Running
			status = StatusRunning
		}

		startType := "manual"
		enabled := false
		switch s.StartType {
		case 2: // Automatic
			startType = "auto"
			enabled = true
		case 3: // Manual
			startType = "manual"
		case 4: // Disabled
			startType = "disabled"
		}

		services = append(services, ServiceInfo{
			Name:        s.Name,
			DisplayName: s.DisplayName,
			Status:      status,
			Enabled:     enabled,
			StartType:   startType,
		})
	}

	return services, nil
}

// listWithSc lists services using sc.exe as fallback.
func (m *WindowsManager) listWithSc() ([]ServiceInfo, error) {
	cmd := exec.Command("sc", "query", "state=", "all")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("listing services: %w", err)
	}

	var services []ServiceInfo
	lines := strings.Split(string(output), "\n")

	var currentService *ServiceInfo
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "SERVICE_NAME:") {
			if currentService != nil {
				services = append(services, *currentService)
			}
			name := strings.TrimPrefix(line, "SERVICE_NAME:")
			name = strings.TrimSpace(name)
			currentService = &ServiceInfo{
				Name:      name,
				Status:    StatusUnknown,
				StartType: "manual",
			}
		} else if currentService != nil {
			if strings.HasPrefix(line, "DISPLAY_NAME:") {
				currentService.DisplayName = strings.TrimSpace(strings.TrimPrefix(line, "DISPLAY_NAME:"))
			} else if strings.Contains(line, "STATE") {
				if strings.Contains(line, "RUNNING") {
					currentService.Status = StatusRunning
				} else if strings.Contains(line, "STOPPED") {
					currentService.Status = StatusStopped
				}
			}
		}
	}

	if currentService != nil {
		services = append(services, *currentService)
	}

	return services, nil
}
