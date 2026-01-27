// Package validation provides pre-uninstall validation services.
package validation

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"strings"
)

// DefaultValidationService implements ValidationService using platform-specific validators.
type DefaultValidationService struct {
	logger     *slog.Logger
	validators []PlatformValidator
}

// NewValidationService creates a new validation service with the provided validators.
func NewValidationService(logger *slog.Logger, validators ...PlatformValidator) *DefaultValidationService {
	return &DefaultValidationService{
		logger:     logger,
		validators: validators,
	}
}

// Validate validates if a package can be uninstalled.
func (s *DefaultValidationService) Validate(ctx context.Context, req *ValidationRequest) (*ValidationResult, error) {
	s.logger.Info("validating uninstall",
		"installation_type", req.InstallationType,
		"package_identifier", req.PackageIdentifier,
	)

	// Find a validator that can handle this installation type
	for _, validator := range s.validators {
		if validator.CanHandle(req.InstallationType) && validator.IsAvailable() {
			result, err := validator.Validate(ctx, req)
			if err != nil {
				s.logger.Error("validation failed",
					"installation_type", req.InstallationType,
					"error", err,
				)
				return nil, err
			}

			s.logger.Info("validation completed",
				"installation_type", req.InstallationType,
				"is_installed", result.IsInstalled,
				"running_processes", len(result.RunningProcesses),
			)

			return result, nil
		}
	}

	return nil, fmt.Errorf("no validator available for installation type: %s", req.InstallationType)
}

// AnalyzeDependencies analyzes package dependencies.
func (s *DefaultValidationService) AnalyzeDependencies(ctx context.Context, installationType, packageIdentifier string) (*DependencyAnalysis, error) {
	s.logger.Info("analyzing dependencies",
		"installation_type", installationType,
		"package_identifier", packageIdentifier,
	)

	result := &DependencyAnalysis{
		Dependencies:      []DependencyInfo{},
		DependentPackages: []DependencyInfo{},
		SafeToUninstall:   true,
	}

	switch installationType {
	case "deb":
		s.analyzeDEBDependencies(ctx, packageIdentifier, result)
	case "rpm":
		s.analyzeRPMDependencies(ctx, packageIdentifier, result)
	case "homebrew_cask":
		// Casks typically don't have dependencies
		result.SafeToUninstall = true
	case "winget", "msi", "pkg":
		// These don't have standard dependency management
		result.SafeToUninstall = true
	}

	return result, nil
}

// analyzeDEBDependencies analyzes DEB package dependencies.
func (s *DefaultValidationService) analyzeDEBDependencies(ctx context.Context, packageName string, result *DependencyAnalysis) {
	if runtime.GOOS != "linux" {
		return
	}

	// Get reverse dependencies
	cmd := exec.CommandContext(ctx, "apt-cache", "rdepends", "--installed", packageName)
	output, err := cmd.Output()
	if err != nil {
		return
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines[1:] { // Skip first line
		dep := strings.TrimSpace(line)
		if dep != "" && !strings.HasPrefix(dep, "|") && dep != packageName {
			result.DependentPackages = append(result.DependentPackages, DependencyInfo{
				Name: dep,
				Type: "reverse",
			})
		}
	}

	if len(result.DependentPackages) > 0 {
		result.SafeToUninstall = false
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("%d packages depend on this package", len(result.DependentPackages)))
	}
}

// analyzeRPMDependencies analyzes RPM package dependencies.
func (s *DefaultValidationService) analyzeRPMDependencies(ctx context.Context, packageName string, result *DependencyAnalysis) {
	if runtime.GOOS != "linux" {
		return
	}

	pkgMgr := s.detectRPMPackageManager()
	var cmd *exec.Cmd

	switch pkgMgr {
	case "dnf":
		cmd = exec.CommandContext(ctx, "dnf", "repoquery", "--installed", "--whatrequires", packageName)
	case "yum":
		cmd = exec.CommandContext(ctx, "repoquery", "--installed", "--whatrequires", packageName)
	default:
		return
	}

	output, err := cmd.Output()
	if err != nil {
		return
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		dep := strings.TrimSpace(line)
		if dep != "" && dep != packageName {
			result.DependentPackages = append(result.DependentPackages, DependencyInfo{
				Name: dep,
				Type: "reverse",
			})
		}
	}

	if len(result.DependentPackages) > 0 {
		result.SafeToUninstall = false
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("%d packages depend on this package", len(result.DependentPackages)))
	}
}

// detectRPMPackageManager detects the available RPM package manager.
func (s *DefaultValidationService) detectRPMPackageManager() string {
	managers := []string{"dnf", "yum", "zypper"}
	for _, mgr := range managers {
		if _, err := exec.LookPath(mgr); err == nil {
			return mgr
		}
	}
	return ""
}

// StopServices stops services before uninstallation.
func (s *DefaultValidationService) StopServices(ctx context.Context, req *StopServicesRequest) (*StopServicesResult, error) {
	s.logger.Info("stopping services",
		"services", req.Services,
		"force_kill", req.ForceKill,
	)

	result := &StopServicesResult{
		StoppedServices: []string{},
		FailedServices:  []string{},
	}

	for _, service := range req.Services {
		if err := s.stopService(ctx, service, req.ForceKill); err != nil {
			result.FailedServices = append(result.FailedServices, service)
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", service, err))
		} else {
			result.StoppedServices = append(result.StoppedServices, service)
		}
	}

	return result, nil
}

// stopService stops a single service based on platform.
func (s *DefaultValidationService) stopService(ctx context.Context, service string, forceKill bool) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		// Try launchctl first
		cmd = exec.CommandContext(ctx, "launchctl", "stop", service)
		if err := cmd.Run(); err != nil {
			// Try pkill as fallback
			cmd = exec.CommandContext(ctx, "pkill", "-f", service)
			return cmd.Run()
		}
		return nil

	case "linux":
		// Try systemctl first
		cmd = exec.CommandContext(ctx, "systemctl", "stop", service)
		if err := cmd.Run(); err != nil {
			// Try service command as fallback
			cmd = exec.CommandContext(ctx, "service", service, "stop")
			return cmd.Run()
		}
		return nil

	case "windows":
		// Use sc.exe to stop service
		cmd = exec.CommandContext(ctx, "sc.exe", "stop", service)
		if err := cmd.Run(); err != nil && forceKill {
			// Force kill via taskkill
			cmd = exec.CommandContext(ctx, "taskkill", "/F", "/IM", service+".exe")
			return cmd.Run()
		}
		return cmd.Run()

	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// isValidAppName validates that an app name is safe for use in file paths.
// This prevents path traversal attacks via malicious app names.
func isValidAppName(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	// Disallow path separators and traversal sequences
	if strings.ContainsAny(name, `/\`) {
		return false
	}
	if strings.Contains(name, "..") {
		return false
	}
	// Disallow other dangerous characters
	if strings.ContainsAny(name, `<>:"|?*`) {
		return false
	}
	// Ensure the name doesn't start or end with whitespace or dots
	if strings.HasPrefix(name, " ") || strings.HasSuffix(name, " ") {
		return false
	}
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return false
	}
	return true
}
