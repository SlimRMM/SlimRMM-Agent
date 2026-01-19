// Package handler provides pre-uninstall validation handlers.
// All handlers delegate to the validation service layer for proper MVC separation.
package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/slimrmm/slimrmm-agent/internal/services/validation"
)

// registerValidationHandlers registers validation handlers.
func (h *Handler) registerValidationHandlers() {
	h.handlers["validate_uninstall"] = h.handleValidateUninstall
	h.handlers["detect_file_locks"] = h.handleDetectFileLocks
	h.handlers["analyze_dependencies"] = h.handleAnalyzeDependencies
	h.handlers["stop_services"] = h.handleStopServices
}

// handleValidateUninstall validates if a package can be uninstalled.
// Delegates to the validation service layer for proper MVC separation.
func (h *Handler) handleValidateUninstall(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req validation.ValidationRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("validating uninstall via service layer",
		"installation_type", req.InstallationType,
		"package_identifier", req.PackageIdentifier,
	)

	// Delegate to validation service
	result, err := h.validationService.Validate(ctx, &req)
	if err != nil {
		return map[string]interface{}{
			"action": "validate_uninstall_result",
			"status": "error",
			"error":  err.Error(),
		}, nil
	}

	return map[string]interface{}{
		"action":     "validate_uninstall_result",
		"status":     "success",
		"validation": result,
	}, nil
}

// =============================================================================
// Dependency Analysis Handler
// =============================================================================

// DependencyAnalysisRequest represents a request to analyze dependencies.
type DependencyAnalysisRequest struct {
	InstallationType  string `json:"installation_type"`
	PackageIdentifier string `json:"package_identifier"`
}

// DependencyAnalysisResult contains the result of dependency analysis.
type DependencyAnalysisResult struct {
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

// handleAnalyzeDependencies analyzes package dependencies.
func (h *Handler) handleAnalyzeDependencies(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req DependencyAnalysisRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("analyzing dependencies",
		"installation_type", req.InstallationType,
		"package_identifier", req.PackageIdentifier,
	)

	result := &DependencyAnalysisResult{
		Dependencies:      []DependencyInfo{},
		DependentPackages: []DependencyInfo{},
		SafeToUninstall:   true,
	}

	switch req.InstallationType {
	case "deb":
		h.analyzeDEBDependencies(ctx, req.PackageIdentifier, result)
	case "rpm":
		h.analyzeRPMDependencies(ctx, req.PackageIdentifier, result)
	case "homebrew_cask":
		// Casks typically don't have dependencies
		result.SafeToUninstall = true
	case "winget", "msi", "pkg":
		// These don't have standard dependency management
		result.SafeToUninstall = true
	}

	return map[string]interface{}{
		"action":   "analyze_dependencies_result",
		"status":   "success",
		"analysis": result,
	}, nil
}

// analyzeDEBDependencies analyzes DEB package dependencies.
func (h *Handler) analyzeDEBDependencies(ctx context.Context, packageName string, result *DependencyAnalysisResult) {
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
func (h *Handler) analyzeRPMDependencies(ctx context.Context, packageName string, result *DependencyAnalysisResult) {
	if runtime.GOOS != "linux" {
		return
	}

	pkgMgr := detectRPMPackageManagerForValidation()
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

// =============================================================================
// Service Management Handler
// =============================================================================

// StopServicesRequest represents a request to stop services.
type StopServicesRequest struct {
	Services        []string `json:"services"`
	Platform        string   `json:"platform,omitempty"`
	ForceKill       bool     `json:"force_kill"`
	TimeoutSeconds  int      `json:"timeout_seconds,omitempty"`
}

// StopServicesResult contains the result of stopping services.
type StopServicesResult struct {
	StoppedServices []string `json:"stopped_services"`
	FailedServices  []string `json:"failed_services"`
	Errors          []string `json:"errors,omitempty"`
}

// handleStopServices stops services before uninstallation.
func (h *Handler) handleStopServices(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req StopServicesRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("stopping services",
		"services", req.Services,
		"force_kill", req.ForceKill,
	)

	result := &StopServicesResult{
		StoppedServices: []string{},
		FailedServices:  []string{},
	}

	for _, service := range req.Services {
		if err := h.stopService(ctx, service, req.ForceKill); err != nil {
			result.FailedServices = append(result.FailedServices, service)
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", service, err))
		} else {
			result.StoppedServices = append(result.StoppedServices, service)
		}
	}

	return map[string]interface{}{
		"action": "stop_services_result",
		"status": "success",
		"result": result,
	}, nil
}

// stopService stops a single service based on platform.
func (h *Handler) stopService(ctx context.Context, service string, forceKill bool) error {
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

// =============================================================================
// Helper Functions
// =============================================================================

// detectRPMPackageManagerForValidation detects the available RPM package manager.
// Note: This is a copy for validation handlers. The main detectRPMPackageManager is in software_uninstall.go
func detectRPMPackageManagerForValidation() string {
	managers := []string{"dnf", "yum", "zypper"}
	for _, mgr := range managers {
		if _, err := exec.LookPath(mgr); err == nil {
			return mgr
		}
	}
	return ""
}
