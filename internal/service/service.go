// Package service provides cross-platform service management.
package service

import (
	"fmt"
	"runtime"
)

// ServiceStatus represents the status of a service.
type ServiceStatus string

const (
	StatusRunning ServiceStatus = "running"
	StatusStopped ServiceStatus = "stopped"
	StatusUnknown ServiceStatus = "unknown"
)

// ServiceInfo contains information about a system service.
type ServiceInfo struct {
	Name        string        `json:"name"`
	DisplayName string        `json:"display_name,omitempty"`
	Description string        `json:"description,omitempty"`
	Status      ServiceStatus `json:"status"`
	Enabled     bool          `json:"enabled"`
	StartType   string        `json:"start_type,omitempty"` // auto, manual, disabled
}

// Manager provides service management operations.
type Manager interface {
	Install(name, displayName, description, execPath string) error
	Uninstall(name string) error
	Start(name string) error
	Stop(name string) error
	Restart(name string) error
	Status(name string) (ServiceStatus, error)
	IsInstalled(name string) bool
	List() ([]ServiceInfo, error)
}

// New creates a new service manager for the current OS.
func New() Manager {
	switch runtime.GOOS {
	case "linux":
		return &SystemdManager{}
	case "darwin":
		return &LaunchdManager{}
	case "windows":
		return newWindowsManager()
	default:
		return nil
	}
}

// ServiceConfig contains service configuration.
type ServiceConfig struct {
	Name        string
	DisplayName string
	Description string
	ExecPath    string
	Args        []string
	WorkingDir  string
	User        string
	Group       string
	Environment map[string]string
}

// DefaultConfig returns the default service configuration.
func DefaultConfig(execPath string) *ServiceConfig {
	return &ServiceConfig{
		Name:        "slimrmm-agent",
		DisplayName: "SlimRMM Agent",
		Description: "SlimRMM Remote Monitoring & Management Agent",
		ExecPath:    execPath,
		WorkingDir:  "/var/lib/slimrmm",
		User:        "root",
		Group:       "root",
	}
}

// ErrServiceNotFound is returned when a service is not found.
var ErrServiceNotFound = fmt.Errorf("service not found")

// ErrServiceExists is returned when trying to install an existing service.
var ErrServiceExists = fmt.Errorf("service already exists")
