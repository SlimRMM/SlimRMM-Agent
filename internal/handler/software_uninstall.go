// Package handler provides software uninstallation handlers.
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/homebrew"
)

// OperationLog represents a single operation executed during uninstallation.
type OperationLog struct {
	Timestamp  time.Time `json:"timestamp"`
	Operation  string    `json:"operation"`
	Command    string    `json:"command"`
	Args       []string  `json:"args"`
	WorkDir    string    `json:"work_dir,omitempty"`
	Stdout     string    `json:"stdout"`
	Stderr     string    `json:"stderr"`
	ExitCode   int       `json:"exit_code"`
	DurationMs int64     `json:"duration_ms"`
	Success    bool      `json:"success"`
	Error      string    `json:"error,omitempty"`
}

// UninstallLog represents the complete log of an uninstallation operation.
type UninstallLog struct {
	UninstallationID string         `json:"uninstallation_id"`
	StartedAt        time.Time      `json:"started_at"`
	CompletedAt      time.Time      `json:"completed_at"`
	CleanupMode      string         `json:"cleanup_mode"`
	Operations       []OperationLog `json:"operations"`
	Summary          struct {
		TotalOperations int   `json:"total_operations"`
		SuccessCount    int   `json:"success_count"`
		FailedCount     int   `json:"failed_count"`
		FilesRemoved    int   `json:"files_removed"`
		SpaceFreedBytes int64 `json:"space_freed_bytes"`
	} `json:"summary"`
}

// CleanupResults tracks what was actually cleaned during uninstallation.
type CleanupResults struct {
	FilesRemoved    int   `json:"files_removed"`
	SpaceFreedBytes int64 `json:"space_freed_bytes"`
	PathsRemoved    []string `json:"paths_removed,omitempty"`
	ServicesUnloaded []string `json:"services_unloaded,omitempty"`
	ReceiptsForgotten []string `json:"receipts_forgotten,omitempty"`
}

// runningUninstallation tracks a running uninstallation process
type runningUninstallation struct {
	cancel context.CancelFunc
}

// runningUninstallations tracks all running uninstallations by ID
var runningUninstallations = struct {
	sync.RWMutex
	m map[string]*runningUninstallation
}{m: make(map[string]*runningUninstallation)}

// Protected paths that should never be deleted (macOS)
var protectedPathsMacOS = []string{
	"/System",
	"/Library",
	"/usr",
	"/bin",
	"/sbin",
	"/private/var",
	"/cores",
}

// Protected paths that should never be deleted (Windows)
var protectedPathsWindows = []string{
	`C:\Windows`,
	`C:\Program Files\WindowsApps`,
}

// Protected paths that should never be deleted (Linux)
var protectedPathsLinux = []string{
	"/etc",
	"/usr",
	"/bin",
	"/sbin",
	"/lib",
	"/lib64",
	"/var",
	"/boot",
}

// RetryConfig defines retry behavior for uninstallation operations.
type RetryConfig struct {
	MaxAttempts      int           `json:"max_attempts"`
	InitialDelay     time.Duration `json:"initial_delay"`
	MaxDelay         time.Duration `json:"max_delay"`
	BackoffFactor    float64       `json:"backoff_factor"`
	RetryOnExitCodes []int         `json:"retry_on_exit_codes,omitempty"`
}

// DefaultRetryConfig returns the default retry configuration.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  5 * time.Second,
		MaxDelay:      60 * time.Second,
		BackoffFactor: 2.0,
	}
}

// MSI exit codes that should trigger a retry
var MSIRetryExitCodes = []int{
	1602, // User cancelled (retry without UI)
	1618, // Another installation in progress
	1619, // Installation package could not be opened
}

// UninstallSnapshot represents a snapshot taken before uninstallation.
type UninstallSnapshot struct {
	ID               string    `json:"id"`
	UninstallationID string    `json:"uninstallation_id"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	AppBundlePath    string    `json:"app_bundle_path,omitempty"`
	ConfigFiles      []string  `json:"config_files,omitempty"`
	RegistryBackup   string    `json:"registry_backup,omitempty"`
	InstallCommand   string    `json:"install_command,omitempty"`
	PackageInfo      map[string]interface{} `json:"package_info,omitempty"`
}

// ThoroughCleanupWindows defines thorough cleanup paths for Windows.
type ThoroughCleanupWindows struct {
	AppDataLocal   []string       `json:"appdata_local"`
	AppDataRoaming []string       `json:"appdata_roaming"`
	ProgramData    []string       `json:"program_data"`
	RegistryPaths  []RegistryPath `json:"registry_paths"`
	Services       []string       `json:"services"`
	ScheduledTasks []string       `json:"scheduled_tasks"`
	FirewallRules  []string       `json:"firewall_rules"`
}

// RegistryPath represents a Windows registry path.
type RegistryPath struct {
	Root string `json:"root"`
	Path string `json:"path"`
}

// ThoroughCleanupMacOS defines thorough cleanup paths for macOS.
type ThoroughCleanupMacOS struct {
	Trash            []string `json:"trash"`
	Delete           []string `json:"delete"`
	Launchctl        []string `json:"launchctl"`
	Pkgutil          []string `json:"pkgutil"`
	Quit             []string `json:"quit"`
	Kext             []string `json:"kext"`
	LoginItems       []string `json:"login_items"`
	SystemExtensions []string `json:"system_extensions"`
}

// ThoroughCleanupLinux defines thorough cleanup paths for Linux.
type ThoroughCleanupLinux struct {
	Purge          bool     `json:"purge"`
	AutoRemove     bool     `json:"auto_remove"`
	ConfigDirs     []string `json:"config_dirs"`
	DataDirs       []string `json:"data_dirs"`
	CacheDirs      []string `json:"cache_dirs"`
	SystemdUser    []string `json:"systemd_user"`
	DesktopFiles   []string `json:"desktop_files"`
	PurgeResidual  bool     `json:"purge_residual"`
}

// registerUninstallHandlers registers software uninstallation handlers.
func (h *Handler) registerUninstallHandlers() {
	h.handlers["uninstall_software"] = h.handleUninstallSoftware
	h.handlers["uninstall_msi"] = h.handleUninstallMSI
	h.handlers["uninstall_pkg"] = h.handleUninstallPKG
	h.handlers["uninstall_cask"] = h.handleUninstallCask
	h.handlers["uninstall_deb"] = h.handleUninstallDEB
	h.handlers["uninstall_rpm"] = h.handleUninstallRPM
	h.handlers["cancel_software_uninstall"] = h.handleCancelSoftwareUninstall

	// Register validation handlers
	h.registerValidationHandlers()

	// Register file lock handlers
	h.registerFileLockHandlers()

	// Register new handlers
	h.handlers["create_uninstall_snapshot"] = h.handleCreateUninstallSnapshot
	h.handlers["batch_kill_processes"] = h.handleBatchKillProcesses
}

// cancelSoftwareUninstallRequest represents a cancel uninstallation request.
type cancelSoftwareUninstallRequest struct {
	UninstallationID string `json:"uninstallation_id"`
}

// handleCancelSoftwareUninstall handles cancellation of a running software uninstallation.
func (h *Handler) handleCancelSoftwareUninstall(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req cancelSoftwareUninstallRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("received cancel request for uninstallation", "uninstallation_id", req.UninstallationID)

	runningUninstallations.RLock()
	uninstallation, exists := runningUninstallations.m[req.UninstallationID]
	runningUninstallations.RUnlock()

	if !exists {
		h.logger.Warn("uninstallation not found or already completed", "uninstallation_id", req.UninstallationID)
		return map[string]interface{}{
			"status":           "not_found",
			"uninstallation_id": req.UninstallationID,
			"message":          "uninstallation not found or already completed",
		}, nil
	}

	// Cancel the uninstallation context
	uninstallation.cancel()

	h.logger.Info("cancelled uninstallation", "uninstallation_id", req.UninstallationID)

	// Send cancellation result
	response := map[string]interface{}{
		"action":            "software_uninstall_result",
		"uninstallation_id": req.UninstallationID,
		"status":            "cancelled",
		"output":            "Uninstallation cancelled by user request",
	}
	h.SendRaw(response)

	return map[string]interface{}{
		"status":           "cancelled",
		"uninstallation_id": req.UninstallationID,
	}, nil
}

// executeWithLogging executes a command and logs all details.
func (h *Handler) executeWithLogging(
	ctx context.Context,
	operation string,
	command string,
	args []string,
	logs *[]OperationLog,
) (string, string, int, error) {
	start := time.Now()

	cmd := exec.CommandContext(ctx, command, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	duration := time.Since(start)

	log := OperationLog{
		Timestamp:  start,
		Operation:  operation,
		Command:    command,
		Args:       args,
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		ExitCode:   exitCode,
		DurationMs: duration.Milliseconds(),
		Success:    exitCode == 0,
	}
	if err != nil && exitCode != 0 {
		log.Error = err.Error()
	}

	*logs = append(*logs, log)

	// Also log to agent logger
	h.logger.Info("executed command",
		"operation", operation,
		"command", command,
		"args", args,
		"exit_code", exitCode,
		"duration_ms", duration.Milliseconds(),
		"stdout_len", len(stdout.String()),
		"stderr_len", len(stderr.String()),
	)

	return stdout.String(), stderr.String(), exitCode, err
}

// isProtectedPath checks if a path is protected and should not be deleted.
func isProtectedPath(path string) bool {
	// Expand home directory
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, path[1:])
		}
	}

	// Clean and normalize path
	path = filepath.Clean(path)

	var protectedPaths []string
	switch runtime.GOOS {
	case "darwin":
		protectedPaths = protectedPathsMacOS
	case "windows":
		protectedPaths = protectedPathsWindows
	case "linux":
		protectedPaths = protectedPathsLinux
	}

	for _, protected := range protectedPaths {
		protected = filepath.Clean(protected)
		// Check if path is exactly the protected path or under it
		if path == protected || strings.HasPrefix(path, protected+string(filepath.Separator)) {
			// Allow ~/Library paths on macOS (user preferences)
			if runtime.GOOS == "darwin" && strings.Contains(path, "/Library/") {
				home, _ := os.UserHomeDir()
				if strings.HasPrefix(path, home) {
					return false // User Library paths are OK
				}
			}
			return true
		}
	}

	return false
}

// expandPath expands ~ and environment variables in a path.
func expandPath(path string) string {
	// Expand home directory
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, path[2:])
		}
	}

	// Expand environment variables
	path = os.ExpandEnv(path)

	return path
}

// removePathSafely removes a path after checking it's not protected.
func (h *Handler) removePathSafely(path string, logs *[]OperationLog, results *CleanupResults) error {
	expandedPath := expandPath(path)

	if isProtectedPath(expandedPath) {
		h.logger.Warn("refusing to remove protected path", "path", expandedPath)
		return fmt.Errorf("path is protected: %s", expandedPath)
	}

	// Check if path exists
	info, err := os.Stat(expandedPath)
	if os.IsNotExist(err) {
		h.logger.Info("path does not exist, skipping", "path", expandedPath)
		return nil
	}
	if err != nil {
		return err
	}

	// Get size before removal
	var size int64
	if info.IsDir() {
		size, _ = getDirSize(expandedPath)
	} else {
		size = info.Size()
	}

	// Remove the path
	_, _, exitCode, err := h.executeWithLogging(
		context.Background(),
		"remove_path",
		"rm",
		[]string{"-rf", expandedPath},
		logs,
	)

	if exitCode == 0 {
		results.FilesRemoved++
		results.SpaceFreedBytes += size
		results.PathsRemoved = append(results.PathsRemoved, expandedPath)
	}

	return err
}

// getDirSize calculates the total size of a directory.
func getDirSize(path string) (int64, error) {
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

// =============================================================================
// Winget Uninstallation (Windows)
// =============================================================================

type uninstallSoftwareRequest struct {
	UninstallationID string            `json:"uninstallation_id"`
	InstallationType string            `json:"installation_type"` // "winget"
	WingetPackageID  string            `json:"winget_package_id"`
	SoftwareName     string            `json:"software_name,omitempty"`
	CleanupMode      string            `json:"cleanup_mode"` // "simple" or "complete"
	CleanupInfo      map[string]interface{} `json:"cleanup_info,omitempty"`
	TimeoutSeconds   int               `json:"timeout_seconds,omitempty"`
}

// handleUninstallSoftware handles software uninstallation via winget on Windows.
func (h *Handler) handleUninstallSoftware(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if runtime.GOOS != "windows" {
		return map[string]interface{}{
			"status": "failed",
			"error":  "winget uninstallation is only available on Windows",
		}, nil
	}

	var req uninstallSoftwareRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("starting winget uninstallation",
		"uninstallation_id", req.UninstallationID,
		"package_id", req.WingetPackageID,
		"cleanup_mode", req.CleanupMode,
	)

	// Set timeout
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Track this uninstallation
	runningUninstallations.Lock()
	runningUninstallations.m[req.UninstallationID] = &runningUninstallation{cancel: cancel}
	runningUninstallations.Unlock()
	defer func() {
		runningUninstallations.Lock()
		delete(runningUninstallations.m, req.UninstallationID)
		runningUninstallations.Unlock()
	}()

	startedAt := time.Now()
	var operationLogs []OperationLog
	cleanupResults := &CleanupResults{}

	// Send progress
	h.SendRaw(map[string]interface{}{
		"action":            "software_uninstall_progress",
		"uninstallation_id": req.UninstallationID,
		"status":            "uninstalling",
		"output":            fmt.Sprintf("Uninstalling %s via winget...\n", req.WingetPackageID),
	})

	// Execute winget uninstall
	args := []string{"uninstall", "--id", req.WingetPackageID, "--silent", "--accept-source-agreements"}
	stdout, stderr, exitCode, _ := h.executeWithLogging(
		ctx,
		"winget_uninstall",
		"winget",
		args,
		&operationLogs,
	)

	// Complete cleanup if requested
	if req.CleanupMode == "complete" && exitCode == 0 {
		h.SendRaw(map[string]interface{}{
			"action":            "software_uninstall_progress",
			"uninstallation_id": req.UninstallationID,
			"status":            "cleaning_up",
			"output":            "Performing complete cleanup...\n",
		})

		// Clean up common Windows paths
		h.cleanupWindowsPaths(req.SoftwareName, &operationLogs, cleanupResults)
	}

	// Determine status
	completedAt := time.Now()
	status := "completed"
	if ctx.Err() == context.DeadlineExceeded {
		status = "timeout"
	} else if ctx.Err() == context.Canceled {
		status = "cancelled"
	} else if exitCode != 0 {
		status = "failed"
	}

	// Build operation log summary
	uninstallLog := UninstallLog{
		UninstallationID: req.UninstallationID,
		StartedAt:        startedAt,
		CompletedAt:      completedAt,
		CleanupMode:      req.CleanupMode,
		Operations:       operationLogs,
	}
	for _, op := range operationLogs {
		uninstallLog.Summary.TotalOperations++
		if op.Success {
			uninstallLog.Summary.SuccessCount++
		} else {
			uninstallLog.Summary.FailedCount++
		}
	}
	uninstallLog.Summary.FilesRemoved = cleanupResults.FilesRemoved
	uninstallLog.Summary.SpaceFreedBytes = cleanupResults.SpaceFreedBytes

	response := map[string]interface{}{
		"action":            "software_uninstall_result",
		"uninstallation_id": req.UninstallationID,
		"status":            status,
		"exit_code":         exitCode,
		"output":            stdout,
		"error_output":      stderr,
		"operation_log":     uninstallLog,
		"cleanup_results":   cleanupResults,
		"started_at":        startedAt.UTC().Format(time.RFC3339),
		"completed_at":      completedAt.UTC().Format(time.RFC3339),
		"duration_ms":       completedAt.Sub(startedAt).Milliseconds(),
	}

	h.SendRaw(response)
	return response, nil
}

// cleanupWindowsPaths cleans up common Windows application data paths.
func (h *Handler) cleanupWindowsPaths(appName string, logs *[]OperationLog, results *CleanupResults) {
	if appName == "" {
		return
	}

	// Normalize app name for path matching
	normalizedName := strings.ReplaceAll(appName, " ", "")

	// Common cleanup paths
	pathPatterns := []string{
		filepath.Join(os.Getenv("LOCALAPPDATA"), appName),
		filepath.Join(os.Getenv("APPDATA"), appName),
		filepath.Join(os.Getenv("PROGRAMDATA"), appName),
		filepath.Join(os.Getenv("LOCALAPPDATA"), normalizedName),
		filepath.Join(os.Getenv("APPDATA"), normalizedName),
	}

	for _, path := range pathPatterns {
		if path != "" {
			h.removePathSafely(path, logs, results)
		}
	}
}

// =============================================================================
// MSI Uninstallation (Windows)
// =============================================================================

type uninstallMSIRequest struct {
	UninstallationID string            `json:"uninstallation_id"`
	MSIProductCode   string            `json:"msi_product_code"` // GUID like {12345-...}
	SoftwareName     string            `json:"software_name,omitempty"`
	CleanupMode      string            `json:"cleanup_mode"`
	TimeoutSeconds   int               `json:"timeout_seconds,omitempty"`
}

// handleUninstallMSI handles MSI uninstallation on Windows.
func (h *Handler) handleUninstallMSI(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if runtime.GOOS != "windows" {
		return map[string]interface{}{
			"status": "failed",
			"error":  "MSI uninstallation is only available on Windows",
		}, nil
	}

	var req uninstallMSIRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("starting MSI uninstallation",
		"uninstallation_id", req.UninstallationID,
		"product_code", req.MSIProductCode,
		"cleanup_mode", req.CleanupMode,
	)

	// Validate product code format (should be a GUID)
	if !strings.HasPrefix(req.MSIProductCode, "{") || !strings.HasSuffix(req.MSIProductCode, "}") {
		return map[string]interface{}{
			"status": "failed",
			"error":  "invalid MSI product code format, expected GUID like {12345678-...}",
		}, nil
	}

	// Set timeout
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Track this uninstallation
	runningUninstallations.Lock()
	runningUninstallations.m[req.UninstallationID] = &runningUninstallation{cancel: cancel}
	runningUninstallations.Unlock()
	defer func() {
		runningUninstallations.Lock()
		delete(runningUninstallations.m, req.UninstallationID)
		runningUninstallations.Unlock()
	}()

	startedAt := time.Now()
	var operationLogs []OperationLog
	cleanupResults := &CleanupResults{}

	// Send progress
	h.SendRaw(map[string]interface{}{
		"action":            "software_uninstall_progress",
		"uninstallation_id": req.UninstallationID,
		"status":            "uninstalling",
		"output":            fmt.Sprintf("Uninstalling MSI package %s...\n", req.MSIProductCode),
	})

	// Execute msiexec /x
	args := []string{"/x", req.MSIProductCode, "/qn", "/norestart"}
	stdout, stderr, exitCode, _ := h.executeWithLogging(
		ctx,
		"msiexec_uninstall",
		"msiexec",
		args,
		&operationLogs,
	)

	// Complete cleanup if requested
	if req.CleanupMode == "complete" && (exitCode == 0 || exitCode == 3010) {
		h.SendRaw(map[string]interface{}{
			"action":            "software_uninstall_progress",
			"uninstallation_id": req.UninstallationID,
			"status":            "cleaning_up",
			"output":            "Performing complete cleanup...\n",
		})

		h.cleanupWindowsPaths(req.SoftwareName, &operationLogs, cleanupResults)
	}

	// Determine status
	completedAt := time.Now()
	status := "completed"
	if ctx.Err() == context.DeadlineExceeded {
		status = "timeout"
	} else if ctx.Err() == context.Canceled {
		status = "cancelled"
	} else if exitCode != 0 && exitCode != 3010 {
		status = "failed"
	}

	// Build operation log summary
	uninstallLog := UninstallLog{
		UninstallationID: req.UninstallationID,
		StartedAt:        startedAt,
		CompletedAt:      completedAt,
		CleanupMode:      req.CleanupMode,
		Operations:       operationLogs,
	}
	for _, op := range operationLogs {
		uninstallLog.Summary.TotalOperations++
		if op.Success {
			uninstallLog.Summary.SuccessCount++
		} else {
			uninstallLog.Summary.FailedCount++
		}
	}
	uninstallLog.Summary.FilesRemoved = cleanupResults.FilesRemoved
	uninstallLog.Summary.SpaceFreedBytes = cleanupResults.SpaceFreedBytes

	response := map[string]interface{}{
		"action":            "software_uninstall_result",
		"uninstallation_id": req.UninstallationID,
		"status":            status,
		"exit_code":         exitCode,
		"output":            stdout,
		"error_output":      stderr,
		"operation_log":     uninstallLog,
		"cleanup_results":   cleanupResults,
		"started_at":        startedAt.UTC().Format(time.RFC3339),
		"completed_at":      completedAt.UTC().Format(time.RFC3339),
		"duration_ms":       completedAt.Sub(startedAt).Milliseconds(),
	}

	if exitCode == 3010 {
		response["reboot_required"] = true
	}

	h.SendRaw(response)
	return response, nil
}

// =============================================================================
// PKG Uninstallation (macOS)
// =============================================================================

type uninstallPKGRequest struct {
	UninstallationID  string `json:"uninstallation_id"`
	PackageIdentifier string `json:"package_identifier"` // e.g., "com.company.app"
	SoftwareName      string `json:"software_name,omitempty"`
	CleanupMode       string `json:"cleanup_mode"`
	TimeoutSeconds    int    `json:"timeout_seconds,omitempty"`
}

// handleUninstallPKG handles PKG uninstallation on macOS.
func (h *Handler) handleUninstallPKG(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if runtime.GOOS != "darwin" {
		return map[string]interface{}{
			"status": "failed",
			"error":  "PKG uninstallation is only available on macOS",
		}, nil
	}

	var req uninstallPKGRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("starting PKG uninstallation",
		"uninstallation_id", req.UninstallationID,
		"package_identifier", req.PackageIdentifier,
		"cleanup_mode", req.CleanupMode,
	)

	// Set timeout
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Track this uninstallation
	runningUninstallations.Lock()
	runningUninstallations.m[req.UninstallationID] = &runningUninstallation{cancel: cancel}
	runningUninstallations.Unlock()
	defer func() {
		runningUninstallations.Lock()
		delete(runningUninstallations.m, req.UninstallationID)
		runningUninstallations.Unlock()
	}()

	startedAt := time.Now()
	var operationLogs []OperationLog
	cleanupResults := &CleanupResults{}

	// Send progress
	h.SendRaw(map[string]interface{}{
		"action":            "software_uninstall_progress",
		"uninstallation_id": req.UninstallationID,
		"status":            "uninstalling",
		"output":            fmt.Sprintf("Uninstalling PKG %s...\n", req.PackageIdentifier),
	})

	// Get list of files installed by the package
	stdout, stderr, exitCode, _ := h.executeWithLogging(
		ctx,
		"pkgutil_files",
		"pkgutil",
		[]string{"--files", req.PackageIdentifier},
		&operationLogs,
	)

	var output strings.Builder
	output.WriteString(stdout)

	// If we got files, remove them
	if exitCode == 0 && stdout != "" {
		files := strings.Split(strings.TrimSpace(stdout), "\n")
		for _, file := range files {
			if file == "" {
				continue
			}
			// Files are relative to /
			fullPath := "/" + strings.TrimPrefix(file, "/")
			if !isProtectedPath(fullPath) {
				h.removePathSafely(fullPath, &operationLogs, cleanupResults)
			}
		}
	}

	// Forget the package receipt
	_, _, forgetExitCode, _ := h.executeWithLogging(
		ctx,
		"pkgutil_forget",
		"pkgutil",
		[]string{"--forget", req.PackageIdentifier},
		&operationLogs,
	)

	if forgetExitCode == 0 {
		cleanupResults.ReceiptsForgotten = append(cleanupResults.ReceiptsForgotten, req.PackageIdentifier)
	}

	// Complete cleanup if requested
	if req.CleanupMode == "complete" {
		h.SendRaw(map[string]interface{}{
			"action":            "software_uninstall_progress",
			"uninstallation_id": req.UninstallationID,
			"status":            "cleaning_up",
			"output":            "Performing complete cleanup...\n",
		})

		h.cleanupMacOSPaths(req.SoftwareName, &operationLogs, cleanupResults)
	}

	// Determine status
	completedAt := time.Now()
	status := "completed"
	if ctx.Err() == context.DeadlineExceeded {
		status = "timeout"
	} else if ctx.Err() == context.Canceled {
		status = "cancelled"
	} else if exitCode != 0 {
		status = "failed"
	}

	// Build operation log summary
	uninstallLog := UninstallLog{
		UninstallationID: req.UninstallationID,
		StartedAt:        startedAt,
		CompletedAt:      completedAt,
		CleanupMode:      req.CleanupMode,
		Operations:       operationLogs,
	}
	for _, op := range operationLogs {
		uninstallLog.Summary.TotalOperations++
		if op.Success {
			uninstallLog.Summary.SuccessCount++
		} else {
			uninstallLog.Summary.FailedCount++
		}
	}
	uninstallLog.Summary.FilesRemoved = cleanupResults.FilesRemoved
	uninstallLog.Summary.SpaceFreedBytes = cleanupResults.SpaceFreedBytes

	response := map[string]interface{}{
		"action":            "software_uninstall_result",
		"uninstallation_id": req.UninstallationID,
		"status":            status,
		"exit_code":         exitCode,
		"output":            output.String(),
		"error_output":      stderr,
		"operation_log":     uninstallLog,
		"cleanup_results":   cleanupResults,
		"started_at":        startedAt.UTC().Format(time.RFC3339),
		"completed_at":      completedAt.UTC().Format(time.RFC3339),
		"duration_ms":       completedAt.Sub(startedAt).Milliseconds(),
	}

	h.SendRaw(response)
	return response, nil
}

// cleanupMacOSPaths cleans up common macOS application paths.
func (h *Handler) cleanupMacOSPaths(appName string, logs *[]OperationLog, results *CleanupResults) {
	if appName == "" {
		return
	}

	home, _ := os.UserHomeDir()

	// Common cleanup paths on macOS
	pathPatterns := []string{
		filepath.Join(home, "Library", "Application Support", appName),
		filepath.Join(home, "Library", "Caches", appName),
		filepath.Join(home, "Library", "Preferences", appName),
		filepath.Join(home, "Library", "Saved Application State", appName+".savedState"),
		filepath.Join(home, "Library", "HTTPStorages", appName),
	}

	for _, path := range pathPatterns {
		h.removePathSafely(path, logs, results)
	}
}

// =============================================================================
// Homebrew Cask Uninstallation (macOS)
// =============================================================================

type uninstallCaskRequest struct {
	UninstallationID string                 `json:"uninstallation_id"`
	CaskName         string                 `json:"cask_name"`
	CleanupMode      string                 `json:"cleanup_mode"`
	CleanupInfo      map[string]interface{} `json:"cleanup_info,omitempty"` // Zap stanza from backend
	TimeoutSeconds   int                    `json:"timeout_seconds,omitempty"`
}

// handleUninstallCask handles Homebrew cask uninstallation on macOS.
func (h *Handler) handleUninstallCask(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if runtime.GOOS != "darwin" {
		return map[string]interface{}{
			"status": "failed",
			"error":  "Homebrew cask uninstallation is only available on macOS",
		}, nil
	}

	var req uninstallCaskRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Validate cask name
	if !homebrew.IsValidCaskName(req.CaskName) {
		return map[string]interface{}{
			"status": "failed",
			"error":  fmt.Sprintf("invalid cask name: %s", req.CaskName),
		}, nil
	}

	h.logger.Info("starting cask uninstallation",
		"uninstallation_id", req.UninstallationID,
		"cask_name", req.CaskName,
		"cleanup_mode", req.CleanupMode,
		"has_cleanup_info", req.CleanupInfo != nil,
	)

	// Set timeout
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Track this uninstallation
	runningUninstallations.Lock()
	runningUninstallations.m[req.UninstallationID] = &runningUninstallation{cancel: cancel}
	runningUninstallations.Unlock()
	defer func() {
		runningUninstallations.Lock()
		delete(runningUninstallations.m, req.UninstallationID)
		runningUninstallations.Unlock()
	}()

	startedAt := time.Now()
	var operationLogs []OperationLog
	cleanupResults := &CleanupResults{}
	var output strings.Builder

	// Get cask info if not provided
	if req.CleanupInfo == nil && req.CleanupMode == "complete" {
		info, err := homebrew.FetchCaskInfo(req.CaskName)
		if err == nil && info != nil {
			// We'll need to fetch full info with zap stanza
			fullInfo, _ := homebrew.FetchCaskInfoFull(req.CaskName)
			if fullInfo != nil {
				req.CleanupInfo = fullInfo
			}
		}
	}

	// Step 1: Stop processes / quit apps
	h.SendRaw(map[string]interface{}{
		"action":            "software_uninstall_progress",
		"uninstallation_id": req.UninstallationID,
		"status":            "uninstalling",
		"current_operation": "stopping_processes",
		"output":            "Stopping application processes...\n",
	})

	// Execute zap stanza operations
	if err := h.executeZapStanza(ctx, req.CleanupInfo, &operationLogs, cleanupResults, &output); err != nil {
		h.logger.Warn("zap stanza execution had errors", "error", err)
	}

	// Step 2: Remove the .app bundle
	h.SendRaw(map[string]interface{}{
		"action":            "software_uninstall_progress",
		"uninstallation_id": req.UninstallationID,
		"status":            "uninstalling",
		"current_operation": "removing_app",
		"output":            "Removing application bundle...\n",
	})

	// Find and remove the .app bundle
	appName := h.findAppBundleName(req.CaskName, req.CleanupInfo)
	if appName != "" {
		appPath := filepath.Join("/Applications", appName)
		h.removePathSafely(appPath, &operationLogs, cleanupResults)
	}

	// Step 3: Complete cleanup
	if req.CleanupMode == "complete" {
		h.SendRaw(map[string]interface{}{
			"action":            "software_uninstall_progress",
			"uninstallation_id": req.UninstallationID,
			"status":            "cleaning_up",
			"current_operation": "cleanup",
			"output":            "Performing complete cleanup...\n",
		})

		// Execute cleanup paths from zap stanza
		h.executeZapCleanup(ctx, req.CleanupInfo, &operationLogs, cleanupResults, &output)
	}

	// Determine status
	completedAt := time.Now()
	status := "completed"
	exitCode := 0
	if ctx.Err() == context.DeadlineExceeded {
		status = "timeout"
		exitCode = -1
	} else if ctx.Err() == context.Canceled {
		status = "cancelled"
		exitCode = -1
	}

	// Build operation log summary
	uninstallLog := UninstallLog{
		UninstallationID: req.UninstallationID,
		StartedAt:        startedAt,
		CompletedAt:      completedAt,
		CleanupMode:      req.CleanupMode,
		Operations:       operationLogs,
	}
	for _, op := range operationLogs {
		uninstallLog.Summary.TotalOperations++
		if op.Success {
			uninstallLog.Summary.SuccessCount++
		} else {
			uninstallLog.Summary.FailedCount++
		}
	}
	uninstallLog.Summary.FilesRemoved = cleanupResults.FilesRemoved
	uninstallLog.Summary.SpaceFreedBytes = cleanupResults.SpaceFreedBytes

	response := map[string]interface{}{
		"action":            "software_uninstall_result",
		"uninstallation_id": req.UninstallationID,
		"status":            status,
		"exit_code":         exitCode,
		"output":            output.String(),
		"operation_log":     uninstallLog,
		"cleanup_results":   cleanupResults,
		"started_at":        startedAt.UTC().Format(time.RFC3339),
		"completed_at":      completedAt.UTC().Format(time.RFC3339),
		"duration_ms":       completedAt.Sub(startedAt).Milliseconds(),
	}

	h.SendRaw(response)
	return response, nil
}

// executeZapStanza executes the zap stanza operations (quit, signal, launchctl, etc.)
func (h *Handler) executeZapStanza(ctx context.Context, cleanupInfo map[string]interface{}, logs *[]OperationLog, results *CleanupResults, output *strings.Builder) error {
	if cleanupInfo == nil {
		return nil
	}

	// Execute zap stanza using homebrew package
	zapResult, err := homebrew.ExecuteZapStanza(ctx, cleanupInfo)
	if err != nil {
		h.logger.Warn("zap stanza execution error", "error", err)
	}

	if zapResult != nil {
		// Convert zap operations to our log format
		for _, op := range zapResult.Operations {
			*logs = append(*logs, OperationLog{
				Timestamp:  op.Timestamp,
				Operation:  op.Operation,
				Command:    op.Command,
				Args:       op.Args,
				Stdout:     op.Stdout,
				Stderr:     op.Stderr,
				ExitCode:   op.ExitCode,
				DurationMs: op.DurationMs,
				Success:    op.Success,
				Error:      op.Error,
			})
			output.WriteString(fmt.Sprintf("[%s] %s: %s\n", op.Operation, op.Target, map[bool]string{true: "OK", false: "FAILED"}[op.Success]))
		}

		// Merge results
		results.PathsRemoved = append(results.PathsRemoved, zapResult.PathsRemoved...)
		results.ServicesUnloaded = append(results.ServicesUnloaded, zapResult.ServicesUnloaded...)
		results.ReceiptsForgotten = append(results.ReceiptsForgotten, zapResult.ReceiptsForgotten...)
	}

	return err
}

// executeZapCleanup executes the cleanup phase (trash/delete paths) from zap stanza.
func (h *Handler) executeZapCleanup(ctx context.Context, cleanupInfo map[string]interface{}, logs *[]OperationLog, results *CleanupResults, output *strings.Builder) {
	if cleanupInfo == nil {
		return
	}

	// Get trash and delete paths from zap stanza
	if zapData, ok := cleanupInfo["zap"]; ok {
		var zapItems []interface{}
		switch z := zapData.(type) {
		case []interface{}:
			zapItems = z
		case map[string]interface{}:
			zapItems = []interface{}{z}
		}

		for _, item := range zapItems {
			itemMap, ok := item.(map[string]interface{})
			if !ok {
				continue
			}

			// Handle trash paths
			if trashPaths, ok := itemMap["trash"]; ok {
				paths := toStringSlice(trashPaths)
				for _, path := range paths {
					expandedPath := expandPath(path)
					if !isProtectedPath(expandedPath) {
						h.removePathSafely(expandedPath, logs, results)
						output.WriteString(fmt.Sprintf("[trash] %s\n", expandedPath))
					}
				}
			}

			// Handle delete paths
			if deletePaths, ok := itemMap["delete"]; ok {
				paths := toStringSlice(deletePaths)
				for _, path := range paths {
					expandedPath := expandPath(path)
					if !isProtectedPath(expandedPath) {
						h.removePathSafely(expandedPath, logs, results)
						output.WriteString(fmt.Sprintf("[delete] %s\n", expandedPath))
					}
				}
			}
		}
	}
}

// toStringSlice converts various types to string slice.
func toStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case []string:
		return val
	}
	return nil
}

// findAppBundleName finds the .app bundle name from cask info.
func (h *Handler) findAppBundleName(caskName string, cleanupInfo map[string]interface{}) string {
	// Try to get from artifacts in cleanup info
	if artifacts, ok := cleanupInfo["artifacts"].([]interface{}); ok {
		for _, artifact := range artifacts {
			if artifactMap, ok := artifact.(map[string]interface{}); ok {
				if apps, ok := artifactMap["app"].([]interface{}); ok && len(apps) > 0 {
					if appName, ok := apps[0].(string); ok {
						return appName
					}
				}
			}
		}
	}

	// Fallback: try common naming patterns
	// "visual-studio-code" -> "Visual Studio Code.app"
	parts := strings.Split(caskName, "-")
	for i := range parts {
		parts[i] = strings.Title(parts[i])
	}
	return strings.Join(parts, " ") + ".app"
}

// =============================================================================
// DEB Uninstallation (Linux - Debian/Ubuntu)
// =============================================================================

type uninstallDEBRequest struct {
	UninstallationID string `json:"uninstallation_id"`
	PackageName      string `json:"package_name"`
	CleanupMode      string `json:"cleanup_mode"`
	TimeoutSeconds   int    `json:"timeout_seconds,omitempty"`
}

// handleUninstallDEB handles DEB package uninstallation on Debian-based Linux.
func (h *Handler) handleUninstallDEB(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if runtime.GOOS != "linux" {
		return map[string]interface{}{
			"status": "failed",
			"error":  "DEB uninstallation is only available on Linux",
		}, nil
	}

	var req uninstallDEBRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("starting DEB uninstallation",
		"uninstallation_id", req.UninstallationID,
		"package_name", req.PackageName,
		"cleanup_mode", req.CleanupMode,
	)

	// Set timeout
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Track this uninstallation
	runningUninstallations.Lock()
	runningUninstallations.m[req.UninstallationID] = &runningUninstallation{cancel: cancel}
	runningUninstallations.Unlock()
	defer func() {
		runningUninstallations.Lock()
		delete(runningUninstallations.m, req.UninstallationID)
		runningUninstallations.Unlock()
	}()

	startedAt := time.Now()
	var operationLogs []OperationLog
	cleanupResults := &CleanupResults{}

	// Send progress
	h.SendRaw(map[string]interface{}{
		"action":            "software_uninstall_progress",
		"uninstallation_id": req.UninstallationID,
		"status":            "uninstalling",
		"output":            fmt.Sprintf("Uninstalling %s via apt...\n", req.PackageName),
	})

	// Determine command based on cleanup mode
	var args []string
	if req.CleanupMode == "complete" {
		// apt remove --purge removes config files too
		args = []string{"remove", "--purge", "-y", req.PackageName}
	} else {
		args = []string{"remove", "-y", req.PackageName}
	}

	stdout, stderr, exitCode, _ := h.executeWithLogging(
		ctx,
		"apt_remove",
		"apt-get",
		args,
		&operationLogs,
	)

	// Run autoremove if complete cleanup
	if req.CleanupMode == "complete" && exitCode == 0 {
		h.executeWithLogging(ctx, "apt_autoremove", "apt-get", []string{"autoremove", "-y"}, &operationLogs)

		// Clean up user config directories
		h.cleanupLinuxPaths(req.PackageName, &operationLogs, cleanupResults)
	}

	// Determine status
	completedAt := time.Now()
	status := "completed"
	if ctx.Err() == context.DeadlineExceeded {
		status = "timeout"
	} else if ctx.Err() == context.Canceled {
		status = "cancelled"
	} else if exitCode != 0 {
		status = "failed"
	}

	// Build operation log summary
	uninstallLog := UninstallLog{
		UninstallationID: req.UninstallationID,
		StartedAt:        startedAt,
		CompletedAt:      completedAt,
		CleanupMode:      req.CleanupMode,
		Operations:       operationLogs,
	}
	for _, op := range operationLogs {
		uninstallLog.Summary.TotalOperations++
		if op.Success {
			uninstallLog.Summary.SuccessCount++
		} else {
			uninstallLog.Summary.FailedCount++
		}
	}
	uninstallLog.Summary.FilesRemoved = cleanupResults.FilesRemoved
	uninstallLog.Summary.SpaceFreedBytes = cleanupResults.SpaceFreedBytes

	response := map[string]interface{}{
		"action":            "software_uninstall_result",
		"uninstallation_id": req.UninstallationID,
		"status":            status,
		"exit_code":         exitCode,
		"output":            stdout,
		"error_output":      stderr,
		"operation_log":     uninstallLog,
		"cleanup_results":   cleanupResults,
		"started_at":        startedAt.UTC().Format(time.RFC3339),
		"completed_at":      completedAt.UTC().Format(time.RFC3339),
		"duration_ms":       completedAt.Sub(startedAt).Milliseconds(),
	}

	h.SendRaw(response)
	return response, nil
}

// =============================================================================
// RPM Uninstallation (Linux - RHEL/Fedora/CentOS)
// =============================================================================

type uninstallRPMRequest struct {
	UninstallationID string `json:"uninstallation_id"`
	PackageName      string `json:"package_name"`
	CleanupMode      string `json:"cleanup_mode"`
	TimeoutSeconds   int    `json:"timeout_seconds,omitempty"`
}

// handleUninstallRPM handles RPM package uninstallation on RHEL-based Linux.
func (h *Handler) handleUninstallRPM(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if runtime.GOOS != "linux" {
		return map[string]interface{}{
			"status": "failed",
			"error":  "RPM uninstallation is only available on Linux",
		}, nil
	}

	var req uninstallRPMRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("starting RPM uninstallation",
		"uninstallation_id", req.UninstallationID,
		"package_name", req.PackageName,
		"cleanup_mode", req.CleanupMode,
	)

	// Set timeout
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Track this uninstallation
	runningUninstallations.Lock()
	runningUninstallations.m[req.UninstallationID] = &runningUninstallation{cancel: cancel}
	runningUninstallations.Unlock()
	defer func() {
		runningUninstallations.Lock()
		delete(runningUninstallations.m, req.UninstallationID)
		runningUninstallations.Unlock()
	}()

	startedAt := time.Now()
	var operationLogs []OperationLog
	cleanupResults := &CleanupResults{}

	// Send progress
	h.SendRaw(map[string]interface{}{
		"action":            "software_uninstall_progress",
		"uninstallation_id": req.UninstallationID,
		"status":            "uninstalling",
		"output":            fmt.Sprintf("Uninstalling %s...\n", req.PackageName),
	})

	// Detect package manager (dnf, yum, or zypper)
	pkgManager := detectRPMPackageManager()

	var stdout, stderr string
	var exitCode int

	switch pkgManager {
	case "dnf":
		args := []string{"remove", "-y", req.PackageName}
		stdout, stderr, exitCode, _ = h.executeWithLogging(ctx, "dnf_remove", "dnf", args, &operationLogs)
		if req.CleanupMode == "complete" && exitCode == 0 {
			h.executeWithLogging(ctx, "dnf_autoremove", "dnf", []string{"autoremove", "-y"}, &operationLogs)
		}
	case "yum":
		args := []string{"remove", "-y", req.PackageName}
		stdout, stderr, exitCode, _ = h.executeWithLogging(ctx, "yum_remove", "yum", args, &operationLogs)
		if req.CleanupMode == "complete" && exitCode == 0 {
			h.executeWithLogging(ctx, "yum_autoremove", "yum", []string{"autoremove", "-y"}, &operationLogs)
		}
	case "zypper":
		args := []string{"remove", "-y", req.PackageName}
		stdout, stderr, exitCode, _ = h.executeWithLogging(ctx, "zypper_remove", "zypper", args, &operationLogs)
	default:
		return map[string]interface{}{
			"status": "failed",
			"error":  "no supported RPM package manager found (dnf, yum, zypper)",
		}, nil
	}

	// Clean up user directories
	if req.CleanupMode == "complete" && exitCode == 0 {
		h.cleanupLinuxPaths(req.PackageName, &operationLogs, cleanupResults)
	}

	// Determine status
	completedAt := time.Now()
	status := "completed"
	if ctx.Err() == context.DeadlineExceeded {
		status = "timeout"
	} else if ctx.Err() == context.Canceled {
		status = "cancelled"
	} else if exitCode != 0 {
		status = "failed"
	}

	// Build operation log summary
	uninstallLog := UninstallLog{
		UninstallationID: req.UninstallationID,
		StartedAt:        startedAt,
		CompletedAt:      completedAt,
		CleanupMode:      req.CleanupMode,
		Operations:       operationLogs,
	}
	for _, op := range operationLogs {
		uninstallLog.Summary.TotalOperations++
		if op.Success {
			uninstallLog.Summary.SuccessCount++
		} else {
			uninstallLog.Summary.FailedCount++
		}
	}
	uninstallLog.Summary.FilesRemoved = cleanupResults.FilesRemoved
	uninstallLog.Summary.SpaceFreedBytes = cleanupResults.SpaceFreedBytes

	response := map[string]interface{}{
		"action":            "software_uninstall_result",
		"uninstallation_id": req.UninstallationID,
		"status":            status,
		"exit_code":         exitCode,
		"output":            stdout,
		"error_output":      stderr,
		"operation_log":     uninstallLog,
		"cleanup_results":   cleanupResults,
		"started_at":        startedAt.UTC().Format(time.RFC3339),
		"completed_at":      completedAt.UTC().Format(time.RFC3339),
		"duration_ms":       completedAt.Sub(startedAt).Milliseconds(),
	}

	h.SendRaw(response)
	return response, nil
}

// detectRPMPackageManager detects which RPM package manager is available.
func detectRPMPackageManager() string {
	managers := []string{"dnf", "yum", "zypper"}
	for _, mgr := range managers {
		if _, err := exec.LookPath(mgr); err == nil {
			return mgr
		}
	}
	return ""
}

// cleanupLinuxPaths cleans up common Linux user directories.
func (h *Handler) cleanupLinuxPaths(appName string, logs *[]OperationLog, results *CleanupResults) {
	if appName == "" {
		return
	}

	home, _ := os.UserHomeDir()

	// Common cleanup paths on Linux
	pathPatterns := []string{
		filepath.Join(home, ".config", appName),
		filepath.Join(home, ".local", "share", appName),
		filepath.Join(home, ".cache", appName),
		filepath.Join(home, "."+appName),
	}

	for _, path := range pathPatterns {
		h.removePathSafely(path, logs, results)
	}
}

// =============================================================================
// Retry Logic
// =============================================================================

// executeWithRetry executes an operation with retry logic.
func (h *Handler) executeWithRetry(
	ctx context.Context,
	uninstallationID string,
	config RetryConfig,
	operation func(ctx context.Context) (stdout string, stderr string, exitCode int, err error),
) (string, string, int, error) {
	var lastStdout, lastStderr string
	var lastExitCode int
	var lastErr error

	delay := config.InitialDelay
	if delay == 0 {
		delay = 5 * time.Second
	}

	maxAttempts := config.MaxAttempts
	if maxAttempts == 0 {
		maxAttempts = 3
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		lastStdout, lastStderr, lastExitCode, lastErr = operation(ctx)

		// Check if successful
		if lastExitCode == 0 {
			return lastStdout, lastStderr, lastExitCode, nil
		}

		// Check if this exit code should not trigger a retry
		if !shouldRetryExitCode(lastExitCode, config.RetryOnExitCodes) {
			h.logger.Info("exit code not in retry list, stopping",
				"exit_code", lastExitCode,
				"attempt", attempt,
			)
			return lastStdout, lastStderr, lastExitCode, lastErr
		}

		// Don't retry on last attempt
		if attempt >= maxAttempts {
			break
		}

		// Send progress update about retry
		h.SendRaw(map[string]interface{}{
			"action":            "software_uninstall_progress",
			"uninstallation_id": uninstallationID,
			"status":            "retrying",
			"attempt":           attempt,
			"max_attempts":      maxAttempts,
			"next_retry_delay":  delay.Seconds(),
			"output":            fmt.Sprintf("Attempt %d/%d failed (exit code %d), retrying in %v...\n", attempt, maxAttempts, lastExitCode, delay),
		})

		h.logger.Info("operation failed, retrying",
			"attempt", attempt,
			"max_attempts", maxAttempts,
			"exit_code", lastExitCode,
			"delay", delay,
		)

		// Wait for delay or context cancellation
		select {
		case <-time.After(delay):
			// Calculate next delay with exponential backoff
			backoffFactor := config.BackoffFactor
			if backoffFactor == 0 {
				backoffFactor = 2.0
			}
			delay = time.Duration(float64(delay) * backoffFactor)
			maxDelay := config.MaxDelay
			if maxDelay == 0 {
				maxDelay = 60 * time.Second
			}
			if delay > maxDelay {
				delay = maxDelay
			}
		case <-ctx.Done():
			return lastStdout, lastStderr, -1, ctx.Err()
		}
	}

	return lastStdout, lastStderr, lastExitCode, lastErr
}

// shouldRetryExitCode checks if an exit code should trigger a retry.
func shouldRetryExitCode(exitCode int, retryOnCodes []int) bool {
	// If no specific codes are set, retry on any non-zero exit
	if len(retryOnCodes) == 0 {
		return exitCode != 0
	}

	for _, code := range retryOnCodes {
		if exitCode == code {
			return true
		}
	}
	return false
}

// =============================================================================
// Snapshot Creation
// =============================================================================

// CreateSnapshotRequest represents a request to create a pre-uninstall snapshot.
type CreateSnapshotRequest struct {
	UninstallationID string `json:"uninstallation_id"`
	InstallationType string `json:"installation_type"`
	PackageID        string `json:"package_id"`
	AppName          string `json:"app_name,omitempty"`
	IncludeConfig    bool   `json:"include_config"`
}

// handleCreateUninstallSnapshot creates a snapshot before uninstallation.
func (h *Handler) handleCreateUninstallSnapshot(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req CreateSnapshotRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("creating uninstall snapshot",
		"uninstallation_id", req.UninstallationID,
		"installation_type", req.InstallationType,
		"package_id", req.PackageID,
	)

	snapshot := &UninstallSnapshot{
		ID:               fmt.Sprintf("snap_%d", time.Now().UnixNano()),
		UninstallationID: req.UninstallationID,
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		PackageInfo:      make(map[string]interface{}),
	}

	// Create snapshot based on installation type
	switch req.InstallationType {
	case "winget", "msi":
		h.createWindowsSnapshot(ctx, req, snapshot)
	case "homebrew_cask", "pkg":
		h.createMacOSSnapshot(ctx, req, snapshot)
	case "deb", "rpm":
		h.createLinuxSnapshot(ctx, req, snapshot)
	}

	return map[string]interface{}{
		"action":   "create_snapshot_result",
		"status":   "success",
		"snapshot": snapshot,
	}, nil
}

// createWindowsSnapshot creates a snapshot for Windows.
func (h *Handler) createWindowsSnapshot(ctx context.Context, req CreateSnapshotRequest, snapshot *UninstallSnapshot) {
	// Export relevant registry keys
	if req.IncludeConfig {
		regExportPath := filepath.Join(os.TempDir(), fmt.Sprintf("snapshot_%s.reg", snapshot.ID))

		// Try to find and export registry keys
		regPaths := []string{
			fmt.Sprintf(`HKLM\SOFTWARE\%s`, req.AppName),
			fmt.Sprintf(`HKCU\SOFTWARE\%s`, req.AppName),
		}

		for _, regPath := range regPaths {
			cmd := exec.CommandContext(ctx, "reg", "export", regPath, regExportPath, "/y")
			if err := cmd.Run(); err == nil {
				snapshot.RegistryBackup = regExportPath
				break
			}
		}
	}

	// Store winget reinstall command
	if req.InstallationType == "winget" {
		snapshot.InstallCommand = fmt.Sprintf("winget install --id %s --accept-source-agreements --accept-package-agreements", req.PackageID)
	}

	snapshot.PackageInfo["installation_type"] = req.InstallationType
	snapshot.PackageInfo["package_id"] = req.PackageID
}

// createMacOSSnapshot creates a snapshot for macOS.
func (h *Handler) createMacOSSnapshot(ctx context.Context, req CreateSnapshotRequest, snapshot *UninstallSnapshot) {
	// Find app bundle path
	appPaths := []string{
		filepath.Join("/Applications", req.AppName+".app"),
		filepath.Join(os.Getenv("HOME"), "Applications", req.AppName+".app"),
	}

	for _, appPath := range appPaths {
		if _, err := os.Stat(appPath); err == nil {
			snapshot.AppBundlePath = appPath
			break
		}
	}

	// List config files that would be removed
	if req.IncludeConfig {
		home, _ := os.UserHomeDir()
		configPaths := []string{
			filepath.Join(home, "Library", "Application Support", req.AppName),
			filepath.Join(home, "Library", "Preferences", req.AppName),
			filepath.Join(home, "Library", "Caches", req.AppName),
		}

		for _, path := range configPaths {
			if _, err := os.Stat(path); err == nil {
				snapshot.ConfigFiles = append(snapshot.ConfigFiles, path)
			}
		}
	}

	// Store homebrew reinstall command
	if req.InstallationType == "homebrew_cask" {
		snapshot.InstallCommand = fmt.Sprintf("brew install --cask %s", req.PackageID)
	}

	snapshot.PackageInfo["installation_type"] = req.InstallationType
	snapshot.PackageInfo["package_id"] = req.PackageID
}

// createLinuxSnapshot creates a snapshot for Linux.
func (h *Handler) createLinuxSnapshot(ctx context.Context, req CreateSnapshotRequest, snapshot *UninstallSnapshot) {
	// List config files that would be removed
	if req.IncludeConfig {
		home, _ := os.UserHomeDir()
		configPaths := []string{
			filepath.Join(home, ".config", req.PackageID),
			filepath.Join(home, ".local", "share", req.PackageID),
			filepath.Join("/etc", req.PackageID),
		}

		for _, path := range configPaths {
			if _, err := os.Stat(path); err == nil {
				snapshot.ConfigFiles = append(snapshot.ConfigFiles, path)
			}
		}
	}

	// Store reinstall command
	if req.InstallationType == "deb" {
		snapshot.InstallCommand = fmt.Sprintf("apt-get install -y %s", req.PackageID)
	} else if req.InstallationType == "rpm" {
		pkgMgr := detectRPMPackageManager()
		snapshot.InstallCommand = fmt.Sprintf("%s install -y %s", pkgMgr, req.PackageID)
	}

	snapshot.PackageInfo["installation_type"] = req.InstallationType
	snapshot.PackageInfo["package_id"] = req.PackageID
}

// =============================================================================
// Thorough Cleanup Functions
// =============================================================================

// cleanupWindowsThorough performs thorough cleanup on Windows.
func (h *Handler) cleanupWindowsThorough(appName string, publisherName string, logs *[]OperationLog, results *CleanupResults) {
	if appName == "" {
		return
	}

	// Normalize names
	normalizedName := strings.ReplaceAll(appName, " ", "")
	normalizedPublisher := strings.ReplaceAll(publisherName, " ", "")

	// Standard cleanup paths
	pathPatterns := []string{
		filepath.Join(os.Getenv("LOCALAPPDATA"), appName),
		filepath.Join(os.Getenv("APPDATA"), appName),
		filepath.Join(os.Getenv("PROGRAMDATA"), appName),
		filepath.Join(os.Getenv("LOCALAPPDATA"), normalizedName),
		filepath.Join(os.Getenv("APPDATA"), normalizedName),
	}

	for _, path := range pathPatterns {
		if path != "" {
			h.removePathSafely(path, logs, results)
		}
	}

	// Clean up scheduled tasks
	h.cleanupWindowsScheduledTasks(appName, logs)

	// Clean up firewall rules
	h.cleanupWindowsFirewallRules(appName, logs)

	// Clean up services
	h.cleanupWindowsServices(appName, logs)

	// Clean up registry (if publisher is known)
	if publisherName != "" {
		h.cleanupWindowsRegistry(publisherName, appName, logs)
	}
}

// cleanupWindowsScheduledTasks removes scheduled tasks for an app.
func (h *Handler) cleanupWindowsScheduledTasks(appName string, logs *[]OperationLog) {
	// List scheduled tasks
	cmd := exec.Command("schtasks", "/Query", "/FO", "CSV", "/NH")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	lines := strings.Split(string(output), "\n")
	appNameLower := strings.ToLower(appName)

	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) >= 1 {
			taskName := strings.Trim(parts[0], "\"")
			if strings.Contains(strings.ToLower(taskName), appNameLower) {
				// Delete the task
				h.executeWithLogging(
					context.Background(),
					"delete_scheduled_task",
					"schtasks",
					[]string{"/Delete", "/TN", taskName, "/F"},
					logs,
				)
			}
		}
	}
}

// cleanupWindowsFirewallRules removes firewall rules for an app.
func (h *Handler) cleanupWindowsFirewallRules(appName string, logs *[]OperationLog) {
	// List and delete firewall rules containing app name
	h.executeWithLogging(
		context.Background(),
		"delete_firewall_rules",
		"netsh",
		[]string{"advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=all dir=in program=*%s*", appName)},
		logs,
	)

	h.executeWithLogging(
		context.Background(),
		"delete_firewall_rules",
		"netsh",
		[]string{"advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=all dir=out program=*%s*", appName)},
		logs,
	)
}

// cleanupWindowsServices stops and deletes services for an app.
func (h *Handler) cleanupWindowsServices(appName string, logs *[]OperationLog) {
	// Query services
	cmd := exec.Command("sc", "query", "state=", "all")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	appNameLower := strings.ToLower(appName)
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		if strings.Contains(line, "SERVICE_NAME:") {
			serviceName := strings.TrimSpace(strings.TrimPrefix(line, "SERVICE_NAME:"))
			if strings.Contains(strings.ToLower(serviceName), appNameLower) {
				// Stop the service
				h.executeWithLogging(
					context.Background(),
					"stop_service",
					"sc",
					[]string{"stop", serviceName},
					logs,
				)

				// Delete the service
				h.executeWithLogging(
					context.Background(),
					"delete_service",
					"sc",
					[]string{"delete", serviceName},
					logs,
				)
			}
		}
	}
}

// cleanupWindowsRegistry removes registry keys for an app.
func (h *Handler) cleanupWindowsRegistry(publisherName, appName string, logs *[]OperationLog) {
	regPaths := []string{
		fmt.Sprintf(`HKLM\SOFTWARE\%s\%s`, publisherName, appName),
		fmt.Sprintf(`HKCU\SOFTWARE\%s\%s`, publisherName, appName),
		fmt.Sprintf(`HKLM\SOFTWARE\%s`, appName),
		fmt.Sprintf(`HKCU\SOFTWARE\%s`, appName),
	}

	for _, regPath := range regPaths {
		h.executeWithLogging(
			context.Background(),
			"delete_registry",
			"reg",
			[]string{"delete", regPath, "/f"},
			logs,
		)
	}
}

// cleanupLinuxThorough performs thorough cleanup on Linux.
func (h *Handler) cleanupLinuxThorough(packageName string, logs *[]OperationLog, results *CleanupResults) {
	if packageName == "" {
		return
	}

	home, _ := os.UserHomeDir()

	// User directories
	pathPatterns := []string{
		filepath.Join(home, ".config", packageName),
		filepath.Join(home, ".local", "share", packageName),
		filepath.Join(home, ".cache", packageName),
		filepath.Join(home, "."+packageName),
	}

	for _, path := range pathPatterns {
		h.removePathSafely(path, logs, results)
	}

	// System directories (requires root)
	systemPaths := []string{
		filepath.Join("/var/lib", packageName),
		filepath.Join("/var/log", packageName),
	}

	for _, path := range systemPaths {
		h.removePathSafely(path, logs, results)
	}

	// User systemd units
	userSystemdPath := filepath.Join(home, ".config", "systemd", "user")
	if entries, err := os.ReadDir(userSystemdPath); err == nil {
		for _, entry := range entries {
			if strings.Contains(strings.ToLower(entry.Name()), strings.ToLower(packageName)) {
				// Stop and disable the service
				h.executeWithLogging(
					context.Background(),
					"systemctl_user_stop",
					"systemctl",
					[]string{"--user", "stop", entry.Name()},
					logs,
				)
				h.executeWithLogging(
					context.Background(),
					"systemctl_user_disable",
					"systemctl",
					[]string{"--user", "disable", entry.Name()},
					logs,
				)
				// Remove the unit file
				h.removePathSafely(filepath.Join(userSystemdPath, entry.Name()), logs, results)
			}
		}
	}

	// Desktop files
	desktopPath := filepath.Join(home, ".local", "share", "applications")
	if entries, err := os.ReadDir(desktopPath); err == nil {
		for _, entry := range entries {
			if strings.Contains(strings.ToLower(entry.Name()), strings.ToLower(packageName)) {
				h.removePathSafely(filepath.Join(desktopPath, entry.Name()), logs, results)
			}
		}
	}

	// Clean up residual configs (packages in 'rc' state)
	h.executeWithLogging(
		context.Background(),
		"dpkg_purge_residual",
		"sh",
		[]string{"-c", "dpkg -l | grep ^rc | awk '{print $2}' | xargs -r dpkg -P"},
		logs,
	)
}

// cleanupMacOSThorough performs thorough cleanup on macOS.
func (h *Handler) cleanupMacOSThorough(appName string, bundleID string, logs *[]OperationLog, results *CleanupResults) {
	if appName == "" && bundleID == "" {
		return
	}

	home, _ := os.UserHomeDir()

	// Standard Library paths
	libraryPaths := []string{
		"Application Support",
		"Caches",
		"Preferences",
		"Saved Application State",
		"HTTPStorages",
		"Logs",
		"Containers",
		"Group Containers",
	}

	for _, subPath := range libraryPaths {
		if appName != "" {
			h.removePathSafely(filepath.Join(home, "Library", subPath, appName), logs, results)
		}
		if bundleID != "" {
			h.removePathSafely(filepath.Join(home, "Library", subPath, bundleID), logs, results)
		}
	}

	// Login items
	h.cleanupMacOSLoginItems(appName, bundleID, logs)

	// System extensions
	if bundleID != "" {
		h.executeWithLogging(
			context.Background(),
			"systemextensionsctl_uninstall",
			"systemextensionsctl",
			[]string{"uninstall", bundleID},
			logs,
		)
	}
}

// cleanupMacOSLoginItems removes login items for an app.
func (h *Handler) cleanupMacOSLoginItems(appName, bundleID string, logs *[]OperationLog) {
	home, _ := os.UserHomeDir()

	// Check BackgroundItems folder
	backgroundItemsPath := filepath.Join(home, "Library", "Application Support", "com.apple.backgroundtaskmanagementagent", "backgrounditems.btm")

	// Use osascript to remove login items
	if appName != "" {
		script := fmt.Sprintf(`tell application "System Events" to delete login item "%s"`, appName)
		h.executeWithLogging(
			context.Background(),
			"remove_login_item",
			"osascript",
			[]string{"-e", script},
			logs,
		)
	}

	_ = backgroundItemsPath
}
