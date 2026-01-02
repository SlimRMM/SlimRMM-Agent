//go:build windows
// +build windows

// Package service provides Windows service management.
package service

import (
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
