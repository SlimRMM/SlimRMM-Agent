// Package validation provides pre-uninstall validation services.
package validation

import (
	"context"
)

// ValidationResult contains the result of pre-uninstall validation.
type ValidationResult struct {
	IsInstalled         bool          `json:"is_installed"`
	CurrentVersion      string        `json:"current_version,omitempty"`
	InstallLocation     string        `json:"install_location,omitempty"`
	Dependencies        []string      `json:"dependencies,omitempty"`
	DependentPackages   []string      `json:"dependent_packages,omitempty"`
	RunningProcesses    []ProcessInfo `json:"running_processes,omitempty"`
	FileLocks           []FileLock    `json:"file_locks,omitempty"`
	EstimatedSpaceBytes int64         `json:"estimated_space_bytes"`
	InstallType         string        `json:"install_type,omitempty"`
	PackageManager      string        `json:"package_manager,omitempty"`
	Warnings            []string      `json:"warnings,omitempty"`
	Errors              []string      `json:"errors,omitempty"`
}

// ProcessInfo represents a running process.
type ProcessInfo struct {
	Name string `json:"name"`
	PID  int    `json:"pid"`
	User string `json:"user"`
	CPU  string `json:"cpu,omitempty"`
	Mem  string `json:"mem,omitempty"`
}

// FileLock represents a file lock held by a process.
type FileLock struct {
	Path    string `json:"path"`
	Process string `json:"process"`
	PID     int    `json:"pid"`
	Type    string `json:"type,omitempty"`
}

// ValidationRequest represents a request to validate an uninstallation.
type ValidationRequest struct {
	InstallationType  string `json:"installation_type"`
	PackageIdentifier string `json:"package_identifier"`
	WingetPackageID   string `json:"winget_package_id,omitempty"`
	MSIProductCode    string `json:"msi_product_code,omitempty"`
	CaskName          string `json:"cask_name,omitempty"`
	AppName           string `json:"app_name,omitempty"`
	PackageName       string `json:"package_name,omitempty"`
}

// DependencyAnalysis contains the result of dependency analysis.
type DependencyAnalysis struct {
	Dependencies      []DependencyInfo `json:"dependencies"`
	DependentPackages []DependencyInfo `json:"dependent_packages"`
	SafeToUninstall   bool             `json:"safe_to_uninstall"`
	Warnings          []string         `json:"warnings,omitempty"`
}

// DependencyInfo represents a package dependency.
type DependencyInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Type    string `json:"type,omitempty"`
}

// StopServicesRequest represents a request to stop services.
type StopServicesRequest struct {
	Services       []string `json:"services"`
	ForceKill      bool     `json:"force_kill"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
}

// StopServicesResult contains the result of stopping services.
type StopServicesResult struct {
	StoppedServices []string `json:"stopped_services"`
	FailedServices  []string `json:"failed_services"`
	Errors          []string `json:"errors,omitempty"`
}

// ValidationService defines the interface for pre-uninstall validation.
type ValidationService interface {
	// Validate validates if a package can be uninstalled.
	Validate(ctx context.Context, req *ValidationRequest) (*ValidationResult, error)

	// AnalyzeDependencies analyzes package dependencies.
	AnalyzeDependencies(ctx context.Context, installationType, packageIdentifier string) (*DependencyAnalysis, error)

	// StopServices stops services before uninstallation.
	StopServices(ctx context.Context, req *StopServicesRequest) (*StopServicesResult, error)
}

// PlatformValidator defines the interface for platform-specific validation.
type PlatformValidator interface {
	// CanHandle returns true if this validator can handle the installation type.
	CanHandle(installationType string) bool

	// IsAvailable returns true if this validator is available on the current platform.
	IsAvailable() bool

	// Validate validates the specified installation.
	Validate(ctx context.Context, req *ValidationRequest) (*ValidationResult, error)
}
