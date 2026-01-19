// Package handler provides software uninstallation handlers.
// All handlers delegate to the service layer for proper MVC separation.
package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/homebrew"
	"github.com/slimrmm/slimrmm-agent/internal/services/models"
)

// =============================================================================
// Handler Registration
// =============================================================================

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

	// Register snapshot handler
	h.handlers["create_uninstall_snapshot"] = h.handleCreateUninstallSnapshot
	h.handlers["batch_kill_processes"] = h.handleBatchKillProcesses
}

// =============================================================================
// Helper Functions (used by other handlers)
// =============================================================================

// expandPath expands environment variables and home directory in paths.
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

// detectRPMPackageManager detects the available RPM package manager.
func detectRPMPackageManager() string {
	managers := []string{"dnf", "yum", "zypper"}
	for _, mgr := range managers {
		if _, err := exec.LookPath(mgr); err == nil {
			return mgr
		}
	}
	return ""
}

// =============================================================================
// Snapshot Types and Handlers
// =============================================================================

// CreateSnapshotRequest represents a request to create a pre-uninstall snapshot.
type CreateSnapshotRequest struct {
	UninstallationID string `json:"uninstallation_id"`
	InstallationType string `json:"installation_type"`
	PackageID        string `json:"package_id"`
	AppName          string `json:"app_name"`
	IncludeConfig    bool   `json:"include_config"`
}

// UninstallSnapshot represents a snapshot taken before uninstallation.
type UninstallSnapshot struct {
	ID               string                 `json:"id"`
	UninstallationID string                 `json:"uninstallation_id"`
	CreatedAt        time.Time              `json:"created_at"`
	ExpiresAt        time.Time              `json:"expires_at"`
	AppBundlePath    string                 `json:"app_bundle_path,omitempty"`
	ConfigFiles      []string               `json:"config_files,omitempty"`
	RegistryBackup   string                 `json:"registry_backup,omitempty"`
	InstallCommand   string                 `json:"install_command,omitempty"`
	PackageInfo      map[string]interface{} `json:"package_info,omitempty"`
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

	// Store brew reinstall command
	if req.InstallationType == "homebrew_cask" {
		snapshot.InstallCommand = fmt.Sprintf("brew install --cask %s", req.PackageID)
	}

	snapshot.PackageInfo["installation_type"] = req.InstallationType
	snapshot.PackageInfo["package_id"] = req.PackageID
}

// createLinuxSnapshot creates a snapshot for Linux.
func (h *Handler) createLinuxSnapshot(ctx context.Context, req CreateSnapshotRequest, snapshot *UninstallSnapshot) {
	// List config files
	if req.IncludeConfig {
		home, _ := os.UserHomeDir()
		configPaths := []string{
			filepath.Join(home, ".config", req.AppName),
			filepath.Join(home, ".local/share", req.AppName),
			filepath.Join("/etc", req.AppName),
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
		if pkgMgr != "" {
			snapshot.InstallCommand = fmt.Sprintf("%s install -y %s", pkgMgr, req.PackageID)
		}
	}

	snapshot.PackageInfo["installation_type"] = req.InstallationType
	snapshot.PackageInfo["package_id"] = req.PackageID
}

// =============================================================================
// Request Types
// =============================================================================

// uninstallSoftwareRequest represents a winget uninstallation request.
type uninstallSoftwareRequest struct {
	UninstallationID string `json:"uninstallation_id"`
	WingetPackageID  string `json:"winget_package_id"`
	SoftwareName     string `json:"software_name,omitempty"`
	CleanupMode      string `json:"cleanup_mode"`
	TimeoutSeconds   int    `json:"timeout_seconds,omitempty"`
}

// uninstallMSIRequest represents an MSI uninstallation request.
type uninstallMSIRequest struct {
	UninstallationID string `json:"uninstallation_id"`
	MSIProductCode   string `json:"msi_product_code"`
	SoftwareName     string `json:"software_name,omitempty"`
	CleanupMode      string `json:"cleanup_mode"`
	CleanupPaths     []string `json:"cleanup_paths,omitempty"`
	TimeoutSeconds   int    `json:"timeout_seconds,omitempty"`
}

// uninstallPKGRequest represents a PKG uninstallation request.
type uninstallPKGRequest struct {
	UninstallationID string `json:"uninstallation_id"`
	PKGReceiptID     string `json:"pkg_receipt_id"`
	SoftwareName     string `json:"software_name,omitempty"`
	CleanupMode      string `json:"cleanup_mode"`
	TimeoutSeconds   int    `json:"timeout_seconds,omitempty"`
}

// uninstallCaskRequest represents a Homebrew cask uninstallation request.
type uninstallCaskRequest struct {
	UninstallationID string                  `json:"uninstallation_id"`
	CaskName         string                  `json:"cask_name"`
	CleanupMode      string                  `json:"cleanup_mode"`
	CaskCleanup      *models.CaskCleanup     `json:"cask_cleanup,omitempty"`
	TimeoutSeconds   int                     `json:"timeout_seconds,omitempty"`
}

// uninstallDEBRequest represents a DEB uninstallation request.
type uninstallDEBRequest struct {
	UninstallationID string   `json:"uninstallation_id"`
	PackageName      string   `json:"package_name"`
	CleanupMode      string   `json:"cleanup_mode"`
	CleanupPaths     []string `json:"cleanup_paths,omitempty"`
	TimeoutSeconds   int      `json:"timeout_seconds,omitempty"`
}

// uninstallRPMRequest represents an RPM uninstallation request.
type uninstallRPMRequest struct {
	UninstallationID string   `json:"uninstallation_id"`
	PackageName      string   `json:"package_name"`
	CleanupMode      string   `json:"cleanup_mode"`
	CleanupPaths     []string `json:"cleanup_paths,omitempty"`
	TimeoutSeconds   int      `json:"timeout_seconds,omitempty"`
}

// =============================================================================
// Handlers - All delegate to service layer
// =============================================================================

// handleUninstallSoftware handles software uninstallation via winget on Windows.
// Delegates to the service layer for proper MVC separation.
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

	h.logger.Info("starting winget uninstallation via service layer",
		"uninstallation_id", req.UninstallationID,
		"package_id", req.WingetPackageID,
		"cleanup_mode", req.CleanupMode,
	)

	// Convert to service request
	serviceReq := &models.UninstallRequest{
		UninstallationID: req.UninstallationID,
		InstallationType: models.InstallationTypeWinget,
		PackageID:        req.WingetPackageID,
		PackageName:      req.SoftwareName,
		CleanupMode:      models.CleanupMode(req.CleanupMode),
		TimeoutSeconds:   req.TimeoutSeconds,
	}

	// Delegate to service layer
	result, err := h.softwareServices.Uninstallation.Uninstall(ctx, serviceReq)
	if err != nil {
		response := map[string]interface{}{
			"action":            "software_uninstall_result",
			"uninstallation_id": req.UninstallationID,
			"status":            "failed",
			"error":             err.Error(),
		}
		h.SendRaw(response)
		return response, nil
	}

	// Build response from service result
	response := map[string]interface{}{
		"action":            "software_uninstall_result",
		"uninstallation_id": result.UninstallationID,
		"status":            string(result.Status),
		"exit_code":         result.ExitCode,
		"output":            result.Output,
		"error":             result.Error,
		"cleanup_results":   result.CleanupResults,
		"started_at":        result.StartedAt.UTC().Format(time.RFC3339),
		"completed_at":      result.CompletedAt.UTC().Format(time.RFC3339),
		"duration_ms":       int64(result.Duration * 1000),
	}

	h.SendRaw(response)
	h.logger.Info("winget uninstallation completed via service layer",
		"uninstallation_id", result.UninstallationID,
		"status", result.Status,
		"exit_code", result.ExitCode,
		"duration", result.Duration,
	)

	return response, nil
}

// handleUninstallMSI handles MSI uninstallation on Windows.
// Delegates to the service layer for proper MVC separation.
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

	h.logger.Info("starting MSI uninstallation via service layer",
		"uninstallation_id", req.UninstallationID,
		"product_code", req.MSIProductCode,
		"cleanup_mode", req.CleanupMode,
	)

	// Convert to service request
	serviceReq := &models.UninstallRequest{
		UninstallationID: req.UninstallationID,
		InstallationType: models.InstallationTypeMSI,
		ProductCode:      req.MSIProductCode,
		PackageName:      req.SoftwareName,
		CleanupMode:      models.CleanupMode(req.CleanupMode),
		CleanupPaths:     req.CleanupPaths,
		TimeoutSeconds:   req.TimeoutSeconds,
	}

	// Delegate to service layer
	result, err := h.softwareServices.Uninstallation.Uninstall(ctx, serviceReq)
	if err != nil {
		response := map[string]interface{}{
			"action":            "software_uninstall_result",
			"uninstallation_id": req.UninstallationID,
			"status":            "failed",
			"error":             err.Error(),
		}
		h.SendRaw(response)
		return response, nil
	}

	// Build response from service result
	response := map[string]interface{}{
		"action":            "software_uninstall_result",
		"uninstallation_id": result.UninstallationID,
		"status":            string(result.Status),
		"exit_code":         result.ExitCode,
		"output":            result.Output,
		"error":             result.Error,
		"cleanup_results":   result.CleanupResults,
		"started_at":        result.StartedAt.UTC().Format(time.RFC3339),
		"completed_at":      result.CompletedAt.UTC().Format(time.RFC3339),
		"duration_ms":       int64(result.Duration * 1000),
	}

	h.SendRaw(response)
	h.logger.Info("MSI uninstallation completed via service layer",
		"uninstallation_id", result.UninstallationID,
		"status", result.Status,
		"exit_code", result.ExitCode,
		"duration", result.Duration,
	)

	return response, nil
}

// handleUninstallPKG handles PKG uninstallation on macOS.
// Delegates to the service layer for proper MVC separation.
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

	h.logger.Info("starting PKG uninstallation via service layer",
		"uninstallation_id", req.UninstallationID,
		"pkg_receipt_id", req.PKGReceiptID,
		"cleanup_mode", req.CleanupMode,
	)

	// Convert to service request
	serviceReq := &models.UninstallRequest{
		UninstallationID: req.UninstallationID,
		InstallationType: models.InstallationTypePKG,
		PackageID:        req.PKGReceiptID,
		PackageName:      req.SoftwareName,
		CleanupMode:      models.CleanupMode(req.CleanupMode),
		TimeoutSeconds:   req.TimeoutSeconds,
	}

	// Delegate to service layer
	result, err := h.softwareServices.Uninstallation.Uninstall(ctx, serviceReq)
	if err != nil {
		response := map[string]interface{}{
			"action":            "software_uninstall_result",
			"uninstallation_id": req.UninstallationID,
			"status":            "failed",
			"error":             err.Error(),
		}
		h.SendRaw(response)
		return response, nil
	}

	// Build response from service result
	response := map[string]interface{}{
		"action":            "software_uninstall_result",
		"uninstallation_id": result.UninstallationID,
		"status":            string(result.Status),
		"exit_code":         result.ExitCode,
		"output":            result.Output,
		"error":             result.Error,
		"cleanup_results":   result.CleanupResults,
		"started_at":        result.StartedAt.UTC().Format(time.RFC3339),
		"completed_at":      result.CompletedAt.UTC().Format(time.RFC3339),
		"duration_ms":       int64(result.Duration * 1000),
	}

	h.SendRaw(response)
	h.logger.Info("PKG uninstallation completed via service layer",
		"uninstallation_id", result.UninstallationID,
		"status", result.Status,
		"exit_code", result.ExitCode,
		"duration", result.Duration,
	)

	return response, nil
}

// handleUninstallCask handles Homebrew cask uninstallation on macOS.
// Delegates to the service layer for proper MVC separation.
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
		response := map[string]interface{}{
			"action":            "software_uninstall_result",
			"uninstallation_id": req.UninstallationID,
			"status":            "failed",
			"error":             fmt.Sprintf("invalid cask name: %s", req.CaskName),
		}
		h.SendRaw(response)
		return response, nil
	}

	h.logger.Info("starting cask uninstallation via service layer",
		"uninstallation_id", req.UninstallationID,
		"cask_name", req.CaskName,
		"cleanup_mode", req.CleanupMode,
	)

	// Convert to service request
	serviceReq := &models.UninstallRequest{
		UninstallationID: req.UninstallationID,
		InstallationType: models.InstallationTypeCask,
		CaskName:         req.CaskName,
		PackageID:        req.CaskName,
		CleanupMode:      models.CleanupMode(req.CleanupMode),
		CaskCleanup:      req.CaskCleanup,
		TimeoutSeconds:   req.TimeoutSeconds,
	}

	// Delegate to service layer
	result, err := h.softwareServices.Uninstallation.Uninstall(ctx, serviceReq)
	if err != nil {
		response := map[string]interface{}{
			"action":            "software_uninstall_result",
			"uninstallation_id": req.UninstallationID,
			"status":            "failed",
			"error":             err.Error(),
		}
		h.SendRaw(response)
		return response, nil
	}

	// Build response from service result
	response := map[string]interface{}{
		"action":            "software_uninstall_result",
		"uninstallation_id": result.UninstallationID,
		"status":            string(result.Status),
		"exit_code":         result.ExitCode,
		"output":            result.Output,
		"error":             result.Error,
		"cleanup_results":   result.CleanupResults,
		"cask_name":         req.CaskName,
		"started_at":        result.StartedAt.UTC().Format(time.RFC3339),
		"completed_at":      result.CompletedAt.UTC().Format(time.RFC3339),
		"duration_ms":       int64(result.Duration * 1000),
	}

	h.SendRaw(response)
	h.logger.Info("cask uninstallation completed via service layer",
		"uninstallation_id", result.UninstallationID,
		"status", result.Status,
		"exit_code", result.ExitCode,
		"duration", result.Duration,
	)

	return response, nil
}

// handleUninstallDEB handles DEB package uninstallation on Linux.
// Delegates to the service layer for proper MVC separation.
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

	h.logger.Info("starting DEB uninstallation via service layer",
		"uninstallation_id", req.UninstallationID,
		"package_name", req.PackageName,
		"cleanup_mode", req.CleanupMode,
	)

	// Convert to service request
	serviceReq := &models.UninstallRequest{
		UninstallationID: req.UninstallationID,
		InstallationType: models.InstallationTypeDEB,
		DebPackageName:   req.PackageName,
		PackageID:        req.PackageName,
		CleanupMode:      models.CleanupMode(req.CleanupMode),
		CleanupPaths:     req.CleanupPaths,
		TimeoutSeconds:   req.TimeoutSeconds,
	}

	// Delegate to service layer
	result, err := h.softwareServices.Uninstallation.Uninstall(ctx, serviceReq)
	if err != nil {
		response := map[string]interface{}{
			"action":            "software_uninstall_result",
			"uninstallation_id": req.UninstallationID,
			"status":            "failed",
			"error":             err.Error(),
		}
		h.SendRaw(response)
		return response, nil
	}

	// Build response from service result
	response := map[string]interface{}{
		"action":            "software_uninstall_result",
		"uninstallation_id": result.UninstallationID,
		"status":            string(result.Status),
		"exit_code":         result.ExitCode,
		"output":            result.Output,
		"error":             result.Error,
		"cleanup_results":   result.CleanupResults,
		"started_at":        result.StartedAt.UTC().Format(time.RFC3339),
		"completed_at":      result.CompletedAt.UTC().Format(time.RFC3339),
		"duration_ms":       int64(result.Duration * 1000),
	}

	h.SendRaw(response)
	h.logger.Info("DEB uninstallation completed via service layer",
		"uninstallation_id", result.UninstallationID,
		"status", result.Status,
		"exit_code", result.ExitCode,
		"duration", result.Duration,
	)

	return response, nil
}

// handleUninstallRPM handles RPM package uninstallation on Linux.
// Delegates to the service layer for proper MVC separation.
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

	h.logger.Info("starting RPM uninstallation via service layer",
		"uninstallation_id", req.UninstallationID,
		"package_name", req.PackageName,
		"cleanup_mode", req.CleanupMode,
	)

	// Convert to service request
	serviceReq := &models.UninstallRequest{
		UninstallationID: req.UninstallationID,
		InstallationType: models.InstallationTypeRPM,
		RpmPackageName:   req.PackageName,
		PackageID:        req.PackageName,
		CleanupMode:      models.CleanupMode(req.CleanupMode),
		CleanupPaths:     req.CleanupPaths,
		TimeoutSeconds:   req.TimeoutSeconds,
	}

	// Delegate to service layer
	result, err := h.softwareServices.Uninstallation.Uninstall(ctx, serviceReq)
	if err != nil {
		response := map[string]interface{}{
			"action":            "software_uninstall_result",
			"uninstallation_id": req.UninstallationID,
			"status":            "failed",
			"error":             err.Error(),
		}
		h.SendRaw(response)
		return response, nil
	}

	// Build response from service result
	response := map[string]interface{}{
		"action":            "software_uninstall_result",
		"uninstallation_id": result.UninstallationID,
		"status":            string(result.Status),
		"exit_code":         result.ExitCode,
		"output":            result.Output,
		"error":             result.Error,
		"cleanup_results":   result.CleanupResults,
		"started_at":        result.StartedAt.UTC().Format(time.RFC3339),
		"completed_at":      result.CompletedAt.UTC().Format(time.RFC3339),
		"duration_ms":       int64(result.Duration * 1000),
	}

	h.SendRaw(response)
	h.logger.Info("RPM uninstallation completed via service layer",
		"uninstallation_id", result.UninstallationID,
		"status", result.Status,
		"exit_code", result.ExitCode,
		"duration", result.Duration,
	)

	return response, nil
}

// handleCancelSoftwareUninstall handles cancellation of a running uninstallation.
func (h *Handler) handleCancelSoftwareUninstall(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req struct {
		UninstallationID string `json:"uninstallation_id"`
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("cancelling uninstallation via service layer",
		"uninstallation_id", req.UninstallationID,
	)

	if err := h.softwareServices.Uninstallation.CancelUninstallation(ctx, req.UninstallationID); err != nil {
		// Check if the error is "not found" - this may mean it already completed
		if strings.Contains(err.Error(), "not found") {
			return map[string]interface{}{
				"action":            "software_uninstall_cancel_result",
				"uninstallation_id": req.UninstallationID,
				"status":            "not_found",
				"message":           "Uninstallation not found or already completed",
			}, nil
		}
		return map[string]interface{}{
			"action":            "software_uninstall_cancel_result",
			"uninstallation_id": req.UninstallationID,
			"status":            "error",
			"error":             err.Error(),
		}, nil
	}

	return map[string]interface{}{
		"action":            "software_uninstall_cancel_result",
		"uninstallation_id": req.UninstallationID,
		"status":            "cancelled",
	}, nil
}
