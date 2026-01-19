// Package handler provides pre-uninstall validation functions.
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/homebrew"
)

// UninstallValidation contains the result of pre-uninstall validation.
type UninstallValidation struct {
	IsInstalled        bool              `json:"is_installed"`
	CurrentVersion     string            `json:"current_version,omitempty"`
	InstallLocation    string            `json:"install_location,omitempty"`
	Dependencies       []string          `json:"dependencies,omitempty"`
	DependentPackages  []string          `json:"dependent_packages,omitempty"`
	RunningProcesses   []ProcessInfo     `json:"running_processes,omitempty"`
	FileLocks          []FileLockInfo    `json:"file_locks,omitempty"`
	EstimatedSpaceBytes int64            `json:"estimated_space_bytes"`
	InstallType        string            `json:"install_type,omitempty"`
	PackageManager     string            `json:"package_manager,omitempty"`
	Warnings           []string          `json:"warnings,omitempty"`
	Errors             []string          `json:"errors,omitempty"`
}

// ProcessInfo represents a running process.
type ProcessInfo struct {
	Name string `json:"name"`
	PID  int    `json:"pid"`
	User string `json:"user"`
	CPU  string `json:"cpu,omitempty"`
	Mem  string `json:"mem,omitempty"`
}

// FileLockInfo represents a file lock held by a process.
type FileLockInfo struct {
	Path    string `json:"path"`
	Process string `json:"process"`
	PID     int    `json:"pid"`
	Type    string `json:"type,omitempty"`
}

// ValidateUninstallRequest represents a request to validate an uninstallation.
type ValidateUninstallRequest struct {
	InstallationType  string `json:"installation_type"`
	PackageIdentifier string `json:"package_identifier"`
	WingetPackageID   string `json:"winget_package_id,omitempty"`
	MSIProductCode    string `json:"msi_product_code,omitempty"`
	CaskName          string `json:"cask_name,omitempty"`
	AppName           string `json:"app_name,omitempty"`
	PackageName       string `json:"package_name,omitempty"`
}

// registerValidationHandlers registers validation handlers.
func (h *Handler) registerValidationHandlers() {
	h.handlers["validate_uninstall"] = h.handleValidateUninstall
	h.handlers["detect_file_locks"] = h.handleDetectFileLocks
	h.handlers["analyze_dependencies"] = h.handleAnalyzeDependencies
	h.handlers["stop_services"] = h.handleStopServices
}

// handleValidateUninstall validates if a package can be uninstalled.
func (h *Handler) handleValidateUninstall(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req ValidateUninstallRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("validating uninstall",
		"installation_type", req.InstallationType,
		"package_identifier", req.PackageIdentifier,
	)

	var validation *UninstallValidation
	var err error

	switch req.InstallationType {
	case "winget":
		validation, err = h.validateWindowsWingetInstallation(ctx, req.WingetPackageID)
	case "msi":
		validation, err = h.validateWindowsMSIInstallation(ctx, req.MSIProductCode)
	case "pkg":
		validation, err = h.validateMacOSPKGInstallation(ctx, req.PackageIdentifier)
	case "homebrew_cask":
		validation, err = h.validateMacOSCaskInstallation(ctx, req.CaskName, req.AppName)
	case "deb":
		validation, err = h.validateLinuxDEBInstallation(ctx, req.PackageName)
	case "rpm":
		validation, err = h.validateLinuxRPMInstallation(ctx, req.PackageName)
	default:
		return nil, fmt.Errorf("unsupported installation type: %s", req.InstallationType)
	}

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
		"validation": validation,
	}, nil
}

// =============================================================================
// Windows Validation
// =============================================================================

// validateWindowsWingetInstallation validates a Windows winget installation.
func (h *Handler) validateWindowsWingetInstallation(ctx context.Context, packageID string) (*UninstallValidation, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("winget validation only available on Windows")
	}

	validation := &UninstallValidation{
		InstallType:    "winget",
		PackageManager: "winget",
	}

	// Check if winget can find the package
	cmd := exec.CommandContext(ctx, "winget", "list", "--id", packageID, "--accept-source-agreements")
	output, err := cmd.Output()
	if err != nil {
		validation.IsInstalled = false
		validation.Errors = append(validation.Errors, "Package not found via winget")
		return validation, nil
	}

	outputStr := string(output)
	if strings.Contains(outputStr, packageID) {
		validation.IsInstalled = true

		// Try to parse version from output
		lines := strings.Split(outputStr, "\n")
		for _, line := range lines {
			if strings.Contains(line, packageID) {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					// Version is typically the second-to-last or last field
					for i := len(parts) - 1; i >= 0; i-- {
						if matched, _ := regexp.MatchString(`^\d+\.`, parts[i]); matched {
							validation.CurrentVersion = parts[i]
							break
						}
					}
				}
				break
			}
		}

		// Check for running processes
		validation.RunningProcesses = h.findWindowsRunningProcesses(ctx, packageID)

		// Estimate space from registry
		validation.EstimatedSpaceBytes = h.estimateWindowsPackageSize(ctx, packageID)
	}

	return validation, nil
}

// validateWindowsMSIInstallation validates a Windows MSI installation.
func (h *Handler) validateWindowsMSIInstallation(ctx context.Context, productCode string) (*UninstallValidation, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("MSI validation only available on Windows")
	}

	validation := &UninstallValidation{
		InstallType:    "msi",
		PackageManager: "msiexec",
	}

	// Query registry for MSI product
	// Check both 32-bit and 64-bit registry locations
	regPaths := []string{
		fmt.Sprintf(`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\%s`, productCode),
		fmt.Sprintf(`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\%s`, productCode),
		fmt.Sprintf(`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\%s`, productCode),
	}

	for _, regPath := range regPaths {
		cmd := exec.CommandContext(ctx, "reg", "query", regPath, "/v", "DisplayName")
		output, err := cmd.Output()
		if err == nil {
			validation.IsInstalled = true

			// Parse display name
			outputStr := string(output)
			if idx := strings.Index(outputStr, "REG_SZ"); idx != -1 {
				validation.InstallLocation = strings.TrimSpace(outputStr[idx+6:])
			}

			// Get version
			cmd = exec.CommandContext(ctx, "reg", "query", regPath, "/v", "DisplayVersion")
			if verOutput, err := cmd.Output(); err == nil {
				if idx := strings.Index(string(verOutput), "REG_SZ"); idx != -1 {
					validation.CurrentVersion = strings.TrimSpace(string(verOutput)[idx+6:])
				}
			}

			// Get estimated size
			cmd = exec.CommandContext(ctx, "reg", "query", regPath, "/v", "EstimatedSize")
			if sizeOutput, err := cmd.Output(); err == nil {
				if idx := strings.Index(string(sizeOutput), "REG_DWORD"); idx != -1 {
					sizeStr := strings.TrimSpace(string(sizeOutput)[idx+9:])
					if size, err := strconv.ParseInt(strings.TrimPrefix(sizeStr, "0x"), 16, 64); err == nil {
						validation.EstimatedSpaceBytes = size * 1024 // Convert KB to bytes
					}
				}
			}

			break
		}
	}

	return validation, nil
}

// findWindowsRunningProcesses finds running processes related to a package.
func (h *Handler) findWindowsRunningProcesses(ctx context.Context, packageID string) []ProcessInfo {
	var processes []ProcessInfo

	// Use tasklist to find processes
	cmd := exec.CommandContext(ctx, "tasklist", "/FO", "CSV", "/NH")
	output, err := cmd.Output()
	if err != nil {
		return processes
	}

	// Simplify package ID for matching
	searchTerm := strings.ToLower(strings.ReplaceAll(packageID, ".", ""))
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) >= 2 {
			processName := strings.Trim(parts[0], "\"")
			pid := strings.Trim(parts[1], "\"")

			if strings.Contains(strings.ToLower(processName), searchTerm) {
				pidInt, _ := strconv.Atoi(pid)
				processes = append(processes, ProcessInfo{
					Name: processName,
					PID:  pidInt,
				})
			}
		}
	}

	return processes
}

// estimateWindowsPackageSize estimates package size from registry.
func (h *Handler) estimateWindowsPackageSize(ctx context.Context, packageID string) int64 {
	// Try to get size from winget show
	cmd := exec.CommandContext(ctx, "winget", "show", "--id", packageID, "--accept-source-agreements")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	// Parse size from output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "size") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				sizeStr := strings.TrimSpace(parts[1])
				return parseHumanSize(sizeStr)
			}
		}
	}

	return 0
}

// =============================================================================
// macOS Validation
// =============================================================================

// validateMacOSPKGInstallation validates a macOS PKG installation.
func (h *Handler) validateMacOSPKGInstallation(ctx context.Context, packageID string) (*UninstallValidation, error) {
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("PKG validation only available on macOS")
	}

	validation := &UninstallValidation{
		InstallType:    "pkg",
		PackageManager: "pkgutil",
	}

	// Check if package is installed via pkgutil
	cmd := exec.CommandContext(ctx, "pkgutil", "--pkg-info", packageID)
	output, err := cmd.Output()
	if err != nil {
		validation.IsInstalled = false
		validation.Errors = append(validation.Errors, "Package not found via pkgutil")
		return validation, nil
	}

	validation.IsInstalled = true

	// Parse pkgutil output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			switch key {
			case "version":
				validation.CurrentVersion = value
			case "location":
				validation.InstallLocation = value
			case "install-time":
				// Could add install time if needed
			}
		}
	}

	// Get file list and estimate size
	cmd = exec.CommandContext(ctx, "pkgutil", "--files", packageID)
	filesOutput, _ := cmd.Output()
	files := strings.Split(strings.TrimSpace(string(filesOutput)), "\n")

	var totalSize int64
	baseLocation := validation.InstallLocation
	if baseLocation == "" {
		baseLocation = "/"
	}

	for _, file := range files {
		if file != "" {
			fullPath := filepath.Join(baseLocation, file)
			if info, err := os.Stat(fullPath); err == nil {
				totalSize += info.Size()
			}
		}
	}
	validation.EstimatedSpaceBytes = totalSize

	return validation, nil
}

// validateMacOSCaskInstallation validates a macOS Homebrew cask installation.
func (h *Handler) validateMacOSCaskInstallation(ctx context.Context, caskName, appName string) (*UninstallValidation, error) {
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("Cask validation only available on macOS")
	}

	validation := &UninstallValidation{
		InstallType:    "homebrew_cask",
		PackageManager: "homebrew",
	}

	// Check for .app bundle
	appPaths := []string{
		"/Applications",
		filepath.Join(os.Getenv("HOME"), "Applications"),
	}

	// Determine app name to look for
	searchName := appName
	if searchName == "" {
		// Try to determine from cask name
		searchName = caskNameToAppName(caskName)
	}

	for _, basePath := range appPaths {
		appPath := filepath.Join(basePath, searchName+".app")
		if info, err := os.Stat(appPath); err == nil {
			validation.IsInstalled = true
			validation.InstallLocation = appPath

			// Calculate app bundle size
			size, _ := getDirSizeRecursive(appPath)
			validation.EstimatedSpaceBytes = size

			// Get app version from Info.plist
			validation.CurrentVersion = getAppVersion(appPath)

			// Check for running processes
			validation.RunningProcesses = h.findMacOSRunningProcesses(ctx, searchName)

			// Check for file locks
			validation.FileLocks = h.detectMacOSFileLocks(ctx, appPath)

			_ = info
			break
		}
	}

	// Also check via brew if not found
	if !validation.IsInstalled {
		cmd := exec.CommandContext(ctx, "brew", "list", "--cask", caskName)
		if err := cmd.Run(); err == nil {
			validation.IsInstalled = true
			validation.Warnings = append(validation.Warnings, "Installed via Homebrew but app bundle not found")
		}
	}

	// Fetch zap stanza for additional info
	if validation.IsInstalled {
		if fullInfo, err := homebrew.FetchCaskInfoFull(caskName); err == nil {
			// Add dependent cleanup paths to estimate
			if zapItems, _ := homebrew.ParseZapStanza(fullInfo); len(zapItems) > 0 {
				for _, zap := range zapItems {
					for _, path := range append(zap.Trash, zap.Delete...) {
						expandedPath := expandPath(path)
						if size, err := getDirSizeRecursive(expandedPath); err == nil {
							validation.EstimatedSpaceBytes += size
						}
					}
				}
			}
		}
	}

	return validation, nil
}

// findMacOSRunningProcesses finds running processes by app name.
func (h *Handler) findMacOSRunningProcesses(ctx context.Context, appName string) []ProcessInfo {
	var processes []ProcessInfo

	// Use pgrep to find processes
	cmd := exec.CommandContext(ctx, "pgrep", "-l", "-f", appName)
	output, _ := cmd.Output()

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) >= 1 {
			pid, _ := strconv.Atoi(parts[0])
			name := appName
			if len(parts) > 1 {
				name = parts[1]
			}
			processes = append(processes, ProcessInfo{
				Name: name,
				PID:  pid,
			})
		}
	}

	return processes
}

// detectMacOSFileLocks detects file locks using lsof.
func (h *Handler) detectMacOSFileLocks(ctx context.Context, path string) []FileLockInfo {
	var locks []FileLockInfo

	cmd := exec.CommandContext(ctx, "lsof", "+D", path)
	output, _ := cmd.Output()

	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i == 0 || line == "" { // Skip header
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 9 {
			pid, _ := strconv.Atoi(fields[1])
			locks = append(locks, FileLockInfo{
				Process: fields[0],
				PID:     pid,
				Path:    fields[8],
				Type:    fields[4],
			})
		}
	}

	return locks
}

// =============================================================================
// Linux Validation
// =============================================================================

// validateLinuxDEBInstallation validates a Linux DEB installation.
func (h *Handler) validateLinuxDEBInstallation(ctx context.Context, packageName string) (*UninstallValidation, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("DEB validation only available on Linux")
	}

	validation := &UninstallValidation{
		InstallType:    "deb",
		PackageManager: "apt",
	}

	// Check if package is installed via dpkg
	cmd := exec.CommandContext(ctx, "dpkg", "-s", packageName)
	output, err := cmd.Output()
	if err != nil {
		validation.IsInstalled = false
		validation.Errors = append(validation.Errors, "Package not installed")
		return validation, nil
	}

	validation.IsInstalled = true

	// Parse dpkg output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			switch key {
			case "Version":
				validation.CurrentVersion = value
			case "Installed-Size":
				if size, err := strconv.ParseInt(value, 10, 64); err == nil {
					validation.EstimatedSpaceBytes = size * 1024 // KB to bytes
				}
			}
		}
	}

	// Check for reverse dependencies
	cmd = exec.CommandContext(ctx, "apt-cache", "rdepends", "--installed", packageName)
	rdepOutput, _ := cmd.Output()
	lines = strings.Split(strings.TrimSpace(string(rdepOutput)), "\n")
	for i, line := range lines {
		if i <= 1 { // Skip header lines
			continue
		}
		dep := strings.TrimSpace(strings.TrimPrefix(line, "|"))
		if dep != "" && dep != packageName {
			validation.DependentPackages = append(validation.DependentPackages, dep)
		}
	}

	if len(validation.DependentPackages) > 0 {
		validation.Warnings = append(validation.Warnings,
			fmt.Sprintf("%d packages depend on this package", len(validation.DependentPackages)))
	}

	// Check for running processes
	validation.RunningProcesses = h.findLinuxRunningProcesses(ctx, packageName)

	return validation, nil
}

// validateLinuxRPMInstallation validates a Linux RPM installation.
func (h *Handler) validateLinuxRPMInstallation(ctx context.Context, packageName string) (*UninstallValidation, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("RPM validation only available on Linux")
	}

	validation := &UninstallValidation{
		InstallType:    "rpm",
		PackageManager: detectRPMPackageManager(),
	}

	// Check if package is installed via rpm
	cmd := exec.CommandContext(ctx, "rpm", "-q", packageName)
	output, err := cmd.Output()
	if err != nil {
		validation.IsInstalled = false
		validation.Errors = append(validation.Errors, "Package not installed")
		return validation, nil
	}

	validation.IsInstalled = true
	validation.CurrentVersion = strings.TrimSpace(string(output))

	// Get package size
	cmd = exec.CommandContext(ctx, "rpm", "-q", "--queryformat", "%{SIZE}", packageName)
	sizeOutput, _ := cmd.Output()
	if size, err := strconv.ParseInt(strings.TrimSpace(string(sizeOutput)), 10, 64); err == nil {
		validation.EstimatedSpaceBytes = size
	}

	// Check for reverse dependencies using dnf/yum
	pkgMgr := validation.PackageManager
	if pkgMgr == "dnf" {
		cmd = exec.CommandContext(ctx, "dnf", "repoquery", "--installed", "--whatrequires", packageName)
	} else if pkgMgr == "yum" {
		cmd = exec.CommandContext(ctx, "repoquery", "--installed", "--whatrequires", packageName)
	}

	if cmd != nil {
		rdepOutput, _ := cmd.Output()
		lines := strings.Split(strings.TrimSpace(string(rdepOutput)), "\n")
		for _, line := range lines {
			dep := strings.TrimSpace(line)
			if dep != "" && dep != packageName && !strings.HasPrefix(dep, "Last metadata") {
				validation.DependentPackages = append(validation.DependentPackages, dep)
			}
		}
	}

	// Check for running processes
	validation.RunningProcesses = h.findLinuxRunningProcesses(ctx, packageName)

	return validation, nil
}

// findLinuxRunningProcesses finds running processes by package name.
func (h *Handler) findLinuxRunningProcesses(ctx context.Context, packageName string) []ProcessInfo {
	var processes []ProcessInfo

	// Use pgrep to find processes
	cmd := exec.CommandContext(ctx, "pgrep", "-l", "-f", packageName)
	output, _ := cmd.Output()

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) >= 1 {
			pid, _ := strconv.Atoi(parts[0])
			name := packageName
			if len(parts) > 1 {
				name = parts[1]
			}
			processes = append(processes, ProcessInfo{
				Name: name,
				PID:  pid,
			})
		}
	}

	return processes
}

// =============================================================================
// Dependency Analysis Handler
// =============================================================================

// DependencyAnalysisRequest represents a dependency analysis request.
type DependencyAnalysisRequest struct {
	InstallationType string `json:"installation_type"`
	PackageName      string `json:"package_name"`
}

// DependencyAnalysisResponse contains the result of dependency analysis.
type DependencyAnalysisResponse struct {
	Package             string   `json:"package"`
	DirectDependents    []string `json:"direct_dependents"`
	IndirectDependents  []string `json:"indirect_dependents"`
	WillBreak           []string `json:"will_break"`
	SafeToRemove        bool     `json:"safe_to_remove"`
	OrphanedAfter       []string `json:"orphaned_after"`
	Warnings            []string `json:"warnings"`
}

// handleAnalyzeDependencies analyzes package dependencies.
func (h *Handler) handleAnalyzeDependencies(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req DependencyAnalysisRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("analyzing dependencies",
		"installation_type", req.InstallationType,
		"package_name", req.PackageName,
	)

	response := &DependencyAnalysisResponse{
		Package:      req.PackageName,
		SafeToRemove: true,
	}

	switch req.InstallationType {
	case "deb":
		h.analyzeDEBDependencies(ctx, req.PackageName, response)
	case "rpm":
		h.analyzeRPMDependencies(ctx, req.PackageName, response)
	case "homebrew_cask":
		// Casks typically don't have dependents
		response.SafeToRemove = true
	default:
		// Winget, MSI, PKG don't typically track dependencies
		response.SafeToRemove = true
	}

	return map[string]interface{}{
		"action":   "analyze_dependencies_result",
		"status":   "success",
		"analysis": response,
	}, nil
}

// analyzeDEBDependencies analyzes DEB package dependencies.
func (h *Handler) analyzeDEBDependencies(ctx context.Context, packageName string, response *DependencyAnalysisResponse) {
	// Get direct dependents
	cmd := exec.CommandContext(ctx, "apt-cache", "rdepends", "--installed", packageName)
	output, _ := cmd.Output()

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for i, line := range lines {
		if i <= 1 { // Skip header
			continue
		}
		dep := strings.TrimSpace(strings.TrimPrefix(line, "|"))
		if dep != "" && dep != packageName {
			response.DirectDependents = append(response.DirectDependents, dep)
		}
	}

	// Check what would be autoremoved
	cmd = exec.CommandContext(ctx, "apt-get", "--dry-run", "autoremove")
	autoOutput, _ := cmd.Output()

	lines = strings.Split(string(autoOutput), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Remv ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				response.OrphanedAfter = append(response.OrphanedAfter, parts[1])
			}
		}
	}

	if len(response.DirectDependents) > 0 {
		response.SafeToRemove = false
		response.WillBreak = response.DirectDependents
		response.Warnings = append(response.Warnings,
			fmt.Sprintf("Removing this package may break %d other packages", len(response.DirectDependents)))
	}
}

// analyzeRPMDependencies analyzes RPM package dependencies.
func (h *Handler) analyzeRPMDependencies(ctx context.Context, packageName string, response *DependencyAnalysisResponse) {
	pkgMgr := detectRPMPackageManager()

	var cmd *exec.Cmd
	if pkgMgr == "dnf" {
		cmd = exec.CommandContext(ctx, "dnf", "repoquery", "--installed", "--whatrequires", packageName)
	} else if pkgMgr == "yum" {
		cmd = exec.CommandContext(ctx, "repoquery", "--installed", "--whatrequires", packageName)
	}

	if cmd != nil {
		output, _ := cmd.Output()
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			dep := strings.TrimSpace(line)
			if dep != "" && dep != packageName && !strings.HasPrefix(dep, "Last metadata") {
				response.DirectDependents = append(response.DirectDependents, dep)
			}
		}
	}

	if len(response.DirectDependents) > 0 {
		response.SafeToRemove = false
		response.WillBreak = response.DirectDependents
		response.Warnings = append(response.Warnings,
			fmt.Sprintf("Removing this package may break %d other packages", len(response.DirectDependents)))
	}
}

// =============================================================================
// Service Stop Handler
// =============================================================================

// StopServicesRequest represents a request to stop services.
type StopServicesRequest struct {
	Services      []string `json:"services"`
	ProcessPIDs   []int    `json:"process_pids,omitempty"`
	ForceKill     bool     `json:"force_kill"`
	TimeoutSeconds int     `json:"timeout_seconds"`
}

// handleStopServices stops services before uninstallation.
func (h *Handler) handleStopServices(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req StopServicesRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("stopping services", "services", req.Services, "pids", req.ProcessPIDs)

	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var results []map[string]interface{}

	// Stop services based on OS
	switch runtime.GOOS {
	case "darwin":
		for _, service := range req.Services {
			result := h.stopMacOSService(ctx, service)
			results = append(results, result)
		}
	case "linux":
		for _, service := range req.Services {
			result := h.stopLinuxService(ctx, service)
			results = append(results, result)
		}
	case "windows":
		for _, service := range req.Services {
			result := h.stopWindowsService(ctx, service)
			results = append(results, result)
		}
	}

	// Kill processes by PID
	for _, pid := range req.ProcessPIDs {
		signal := "TERM"
		if req.ForceKill {
			signal = "KILL"
		}
		result := h.killProcess(ctx, pid, signal)
		results = append(results, result)
	}

	return map[string]interface{}{
		"action":  "stop_services_result",
		"status":  "success",
		"results": results,
	}, nil
}

// stopMacOSService stops a macOS launchd service.
func (h *Handler) stopMacOSService(ctx context.Context, service string) map[string]interface{} {
	result := map[string]interface{}{
		"service": service,
		"type":    "launchctl",
	}

	// Get current user UID
	uid := homebrew.GetCurrentUID()

	// Try user domain first, then system
	domains := []string{
		fmt.Sprintf("gui/%s/%s", uid, service),
		fmt.Sprintf("system/%s", service),
	}

	for _, domain := range domains {
		cmd := exec.CommandContext(ctx, "launchctl", "bootout", domain)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		if err := cmd.Run(); err == nil {
			result["success"] = true
			result["domain"] = domain
			return result
		}
	}

	result["success"] = false
	result["error"] = "service not found or already stopped"
	return result
}

// stopLinuxService stops a Linux systemd service.
func (h *Handler) stopLinuxService(ctx context.Context, service string) map[string]interface{} {
	result := map[string]interface{}{
		"service": service,
		"type":    "systemd",
	}

	cmd := exec.CommandContext(ctx, "systemctl", "stop", service)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		result["success"] = false
		result["error"] = stderr.String()
	} else {
		result["success"] = true
	}

	return result
}

// stopWindowsService stops a Windows service.
func (h *Handler) stopWindowsService(ctx context.Context, service string) map[string]interface{} {
	result := map[string]interface{}{
		"service": service,
		"type":    "sc",
	}

	cmd := exec.CommandContext(ctx, "sc", "stop", service)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		result["success"] = false
		result["error"] = stderr.String()
	} else {
		result["success"] = true
		result["output"] = stdout.String()
	}

	return result
}

// killProcess kills a process by PID.
func (h *Handler) killProcess(ctx context.Context, pid int, signal string) map[string]interface{} {
	result := map[string]interface{}{
		"pid":    pid,
		"signal": signal,
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		if signal == "KILL" {
			cmd = exec.CommandContext(ctx, "taskkill", "/PID", strconv.Itoa(pid), "/F")
		} else {
			cmd = exec.CommandContext(ctx, "taskkill", "/PID", strconv.Itoa(pid))
		}
	} else {
		cmd = exec.CommandContext(ctx, "kill", fmt.Sprintf("-%s", signal), strconv.Itoa(pid))
	}

	if err := cmd.Run(); err != nil {
		result["success"] = false
		result["error"] = err.Error()
	} else {
		result["success"] = true
	}

	return result
}

// =============================================================================
// Helper Functions
// =============================================================================

// caskNameToAppName converts a cask name to potential app name.
func caskNameToAppName(caskName string) string {
	// Known mappings
	knownMappings := map[string]string{
		"visual-studio-code": "Visual Studio Code",
		"google-chrome":      "Google Chrome",
		"firefox":            "Firefox",
		"slack":              "Slack",
		"discord":            "Discord",
		"spotify":            "Spotify",
		"1password":          "1Password",
		"docker":             "Docker",
		"iterm2":             "iTerm",
		"rectangle":          "Rectangle",
	}

	if name, ok := knownMappings[caskName]; ok {
		return name
	}

	// Default: title case each word
	parts := strings.Split(caskName, "-")
	for i := range parts {
		if len(parts[i]) > 0 {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, " ")
}

// getAppVersion reads version from app's Info.plist.
func getAppVersion(appPath string) string {
	plistPath := filepath.Join(appPath, "Contents", "Info.plist")

	cmd := exec.Command("defaults", "read", plistPath, "CFBundleShortVersionString")
	output, err := cmd.Output()
	if err == nil {
		return strings.TrimSpace(string(output))
	}

	// Try CFBundleVersion as fallback
	cmd = exec.Command("defaults", "read", plistPath, "CFBundleVersion")
	output, err = cmd.Output()
	if err == nil {
		return strings.TrimSpace(string(output))
	}

	return ""
}

// getDirSizeRecursive calculates directory size recursively.
func getDirSizeRecursive(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Ignore errors
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

// parseHumanSize parses human-readable size strings.
func parseHumanSize(sizeStr string) int64 {
	sizeStr = strings.TrimSpace(sizeStr)
	sizeStr = strings.ToUpper(sizeStr)

	multipliers := map[string]int64{
		"B":  1,
		"KB": 1024,
		"MB": 1024 * 1024,
		"GB": 1024 * 1024 * 1024,
		"TB": 1024 * 1024 * 1024 * 1024,
	}

	for suffix, mult := range multipliers {
		if strings.HasSuffix(sizeStr, suffix) {
			numStr := strings.TrimSuffix(sizeStr, suffix)
			numStr = strings.TrimSpace(numStr)
			if num, err := strconv.ParseFloat(numStr, 64); err == nil {
				return int64(num * float64(mult))
			}
		}
	}

	return 0
}
