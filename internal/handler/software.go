// Package handler provides software installation handlers.
package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/homebrew"
	agenthttp "github.com/slimrmm/slimrmm-agent/internal/http"
	"github.com/slimrmm/slimrmm-agent/internal/services/filesystem"
	"github.com/slimrmm/slimrmm-agent/internal/services/models"
)

// runningInstallation tracks a running installation process
type runningInstallation struct {
	cancel context.CancelFunc
}

// runningInstallations tracks all running installations by ID
var runningInstallations = struct {
	sync.RWMutex
	m map[string]*runningInstallation
}{m: make(map[string]*runningInstallation)}

// registerSoftwareHandlers registers software installation handlers.
func (h *Handler) registerSoftwareHandlers() {
	h.handlers["install_software"] = h.handleInstallSoftware
	h.handlers["download_and_install_msi"] = h.handleDownloadAndInstallMSI
	h.handlers["download_and_install_pkg"] = h.handleDownloadAndInstallPKG
	h.handlers["download_and_install_cask"] = h.handleDownloadAndInstallCask
	h.handlers["download_and_install_deb"] = h.handleDownloadAndInstallDEB
	h.handlers["download_and_install_rpm"] = h.handleDownloadAndInstallRPM
	h.handlers["cancel_software_install"] = h.handleCancelSoftwareInstall
}

// cancelSoftwareInstallRequest represents a cancel installation request.
type cancelSoftwareInstallRequest struct {
	InstallationID string `json:"installation_id"`
}

// handleCancelSoftwareInstall handles cancellation of a running software installation.
func (h *Handler) handleCancelSoftwareInstall(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req cancelSoftwareInstallRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("received cancel request for installation", "installation_id", req.InstallationID)

	runningInstallations.RLock()
	installation, exists := runningInstallations.m[req.InstallationID]
	runningInstallations.RUnlock()

	if !exists {
		h.logger.Warn("installation not found or already completed", "installation_id", req.InstallationID)
		return map[string]interface{}{
			"status":          "not_found",
			"installation_id": req.InstallationID,
			"message":         "installation not found or already completed",
		}, nil
	}

	// Cancel the installation context
	installation.cancel()

	h.logger.Info("cancelled installation", "installation_id", req.InstallationID)

	// Send cancellation result
	response := map[string]interface{}{
		"action":          "software_install_result",
		"installation_id": req.InstallationID,
		"status":          "cancelled",
		"output":          "Installation cancelled by user request",
	}
	h.SendRaw(response)

	return map[string]interface{}{
		"status":          "cancelled",
		"installation_id": req.InstallationID,
	}, nil
}

// installSoftwareRequest represents a software installation request.
type installSoftwareRequest struct {
	InstallationID    string `json:"installation_id"`
	InstallationType  string `json:"installation_type"` // "winget" or "msi"
	WingetPackageID   string `json:"winget_package_id,omitempty"`
	WingetPackageName string `json:"winget_package_name,omitempty"`
	Silent            bool   `json:"silent"`
	TimeoutSeconds    int    `json:"timeout_seconds,omitempty"`
}

// downloadAndInstallMSIRequest represents an MSI download and install request.
type downloadAndInstallMSIRequest struct {
	InstallationID string `json:"installation_id"`
	DownloadURL    string `json:"download_url"`
	DownloadToken  string `json:"download_token,omitempty"`
	ExpectedHash   string `json:"expected_hash"` // SHA256 hash
	Filename       string `json:"filename"`
	SilentArgs     string `json:"silent_args,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

// handleInstallSoftware handles software installation via winget.
// Delegates to the service layer for proper MVC separation.
func (h *Handler) handleInstallSoftware(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if runtime.GOOS != "windows" {
		return map[string]interface{}{
			"status": "failed",
			"error":  "software installation is only available on Windows",
		}, nil
	}

	var req installSoftwareRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if req.InstallationType != "winget" {
		return map[string]interface{}{
			"status": "failed",
			"error":  "only winget installations are supported via this handler",
		}, nil
	}

	h.logger.Info("starting software installation via service layer",
		"installation_id", req.InstallationID,
		"installation_type", req.InstallationType,
		"package_id", req.WingetPackageID,
	)

	// Convert to service request
	serviceReq := &models.InstallRequest{
		InstallationID:   req.InstallationID,
		InstallationType: models.InstallationTypeWinget,
		PackageID:        req.WingetPackageID,
		PackageName:      req.WingetPackageName,
		Silent:           req.Silent,
		TimeoutSeconds:   req.TimeoutSeconds,
	}

	// Delegate to service layer
	result, err := h.softwareServices.Installation.Install(ctx, serviceReq)
	if err != nil {
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           err.Error(),
		}
		h.SendRaw(response)
		return response, nil
	}

	// Build response from service result
	response := map[string]interface{}{
		"action":          "software_install_result",
		"installation_id": result.InstallationID,
		"status":          string(result.Status),
		"exit_code":       result.ExitCode,
		"output":          result.Output,
		"error":           result.Error,
		"started_at":      result.StartedAt.UTC().Format(time.RFC3339),
		"completed_at":    result.CompletedAt.UTC().Format(time.RFC3339),
		"duration_ms":     int64(result.Duration * 1000),
	}

	h.SendRaw(response)
	h.logger.Info("software installation completed via service layer",
		"installation_id", result.InstallationID,
		"status", result.Status,
		"exit_code", result.ExitCode,
		"duration", result.Duration,
	)

	return response, nil
}

// handleDownloadAndInstallMSI handles MSI package download and installation.
func (h *Handler) handleDownloadAndInstallMSI(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if runtime.GOOS != "windows" {
		return map[string]interface{}{
			"status": "failed",
			"error":  "MSI installation is only available on Windows",
		}, nil
	}

	var req downloadAndInstallMSIRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("starting MSI download and install via service layer",
		"installation_id", req.InstallationID,
		"filename", req.Filename,
	)

	// Normalize hash format - remove "sha256:" prefix if present
	expectedHash := req.ExpectedHash
	if strings.HasPrefix(expectedHash, "sha256:") {
		expectedHash = strings.TrimPrefix(expectedHash, "sha256:")
	}

	// Convert to service request
	serviceReq := &models.InstallRequest{
		InstallationID:   req.InstallationID,
		InstallationType: models.InstallationTypeMSI,
		DownloadURL:      req.DownloadURL,
		DownloadToken:    req.DownloadToken,
		ExpectedHash:     expectedHash,
		Filename:         req.Filename,
		Silent:           true,
		SilentArgs:       req.SilentArgs,
		TimeoutSeconds:   req.TimeoutSeconds,
	}

	// Delegate to service layer
	result, err := h.softwareServices.Installation.Install(ctx, serviceReq)
	if err != nil {
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           err.Error(),
		}
		h.SendRaw(response)
		return response, nil
	}

	// Build response from service result
	response := map[string]interface{}{
		"action":          "software_install_result",
		"installation_id": result.InstallationID,
		"status":          string(result.Status),
		"exit_code":       result.ExitCode,
		"output":          result.Output,
		"error":           result.Error,
		"started_at":      result.StartedAt.UTC().Format(time.RFC3339),
		"completed_at":    result.CompletedAt.UTC().Format(time.RFC3339),
		"duration_ms":     int64(result.Duration * 1000),
	}

	// Check for reboot required (exit code 3010)
	if result.ExitCode == 3010 {
		response["reboot_required"] = true
	}

	h.SendRaw(response)
	h.logger.Info("MSI installation completed via service layer",
		"installation_id", result.InstallationID,
		"status", result.Status,
		"exit_code", result.ExitCode,
		"duration", result.Duration,
	)

	return response, nil
}

// downloadFile downloads a file from URL to the specified path.
// Uses the internal HTTP client for proper abstraction.
func (h *Handler) downloadFile(ctx context.Context, url, token, destPath, installationID string) error {
	h.logger.Info("starting file download",
		"installation_id", installationID,
		"url", url,
		"dest", destPath,
	)

	// Create progress callback that sends WebSocket updates
	progressCallback := func(progress int, bytesTransferred, totalBytes int64) {
		h.SendRaw(map[string]interface{}{
			"action":           "software_install_progress",
			"installation_id":  installationID,
			"status":           "downloading",
			"progress_percent": progress,
		})
	}

	// Build download options
	opts := []agenthttp.DownloadOption{
		agenthttp.WithDownloadTimeout(10 * time.Minute),
		agenthttp.WithDownloadProgress(progressCallback, 10),
	}

	if token != "" {
		opts = append(opts, agenthttp.WithAuthToken(token))
	}

	// Use HTTP client for download
	client := agenthttp.GetDefault()
	if err := client.DownloadToFile(ctx, url, destPath, opts...); err != nil {
		h.logger.Info("download failed", "error", err)
		return fmt.Errorf("failed to download: %w", err)
	}

	h.logger.Info("download completed",
		"installation_id", installationID,
	)

	return nil
}

// calculateFileHash calculates SHA256 hash of a file using filesystem service.
func calculateFileHash(path string) (string, error) {
	fs := filesystem.GetDefault()
	f, err := fs.OpenRead(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// parseArgs splits a string into arguments (simple implementation).
func parseArgs(args string) []string {
	var result []string
	var current string
	inQuote := false

	for _, r := range args {
		switch {
		case r == '"':
			inQuote = !inQuote
		case r == ' ' && !inQuote:
			if current != "" {
				result = append(result, current)
				current = ""
			}
		default:
			current += string(r)
		}
	}
	if current != "" {
		result = append(result, current)
	}

	return result
}

// sanitizeMsiArgs removes /i flag from MSI arguments since we add it ourselves.
// This prevents duplicate /i flags when the backend sends "/i /qn /norestart".
func sanitizeMsiArgs(args string) string {
	// Parse args, filter out /i, rejoin
	parsed := parseArgs(args)
	var filtered []string
	for _, arg := range parsed {
		// Skip /i or -i (case insensitive)
		lower := strings.ToLower(arg)
		if lower == "/i" || lower == "-i" {
			continue
		}
		filtered = append(filtered, arg)
	}
	return strings.Join(filtered, " ")
}

// downloadAndInstallPKGRequest represents a PKG package download and install request.
type downloadAndInstallPKGRequest struct {
	InstallationID string `json:"installation_id"`
	DownloadURL    string `json:"download_url"`
	DownloadToken  string `json:"download_token,omitempty"`
	ExpectedHash   string `json:"expected_hash,omitempty"`
	Filename       string `json:"filename"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

// handleDownloadAndInstallPKG handles PKG package download and installation on macOS.
// Delegates to the service layer for proper MVC separation.
func (h *Handler) handleDownloadAndInstallPKG(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if runtime.GOOS != "darwin" {
		return map[string]interface{}{
			"status": "failed",
			"error":  "PKG installation is only available on macOS",
		}, nil
	}

	var req downloadAndInstallPKGRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("starting PKG installation via service layer",
		"installation_id", req.InstallationID,
		"filename", req.Filename,
	)

	// Normalize hash format - remove "sha256:" prefix if present
	expectedHash := req.ExpectedHash
	if strings.HasPrefix(expectedHash, "sha256:") {
		expectedHash = strings.TrimPrefix(expectedHash, "sha256:")
	}

	// Convert to service request
	serviceReq := &models.InstallRequest{
		InstallationID:   req.InstallationID,
		InstallationType: models.InstallationTypePKG,
		DownloadURL:      req.DownloadURL,
		DownloadToken:    req.DownloadToken,
		ExpectedHash:     expectedHash,
		Filename:         req.Filename,
		TimeoutSeconds:   req.TimeoutSeconds,
	}

	// Delegate to service layer
	result, err := h.softwareServices.Installation.Install(ctx, serviceReq)
	if err != nil {
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           err.Error(),
		}
		h.SendRaw(response)
		return response, nil
	}

	// Build response from service result
	response := map[string]interface{}{
		"action":          "software_install_result",
		"installation_id": result.InstallationID,
		"status":          string(result.Status),
		"exit_code":       result.ExitCode,
		"output":          result.Output,
		"error":           result.Error,
		"started_at":      result.StartedAt.UTC().Format(time.RFC3339),
		"completed_at":    result.CompletedAt.UTC().Format(time.RFC3339),
		"duration_ms":     int64(result.Duration * 1000),
	}

	h.SendRaw(response)
	h.logger.Info("PKG installation completed via service layer",
		"installation_id", result.InstallationID,
		"status", result.Status,
		"exit_code", result.ExitCode,
		"duration", result.Duration,
	)

	return response, nil
}

// downloadAndInstallCaskRequest represents a Homebrew cask installation request.
type downloadAndInstallCaskRequest struct {
	InstallationID string `json:"installation_id"`
	CaskName       string `json:"cask_name"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

// handleDownloadAndInstallCask handles Homebrew cask installation.
// Delegates to the service layer for proper MVC separation.
func (h *Handler) handleDownloadAndInstallCask(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if runtime.GOOS != "darwin" {
		return map[string]interface{}{
			"status": "failed",
			"error":  "Homebrew cask installation is only available on macOS",
		}, nil
	}

	var req downloadAndInstallCaskRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Validate cask name
	if !homebrew.IsValidCaskName(req.CaskName) {
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           fmt.Sprintf("invalid cask name: %s", req.CaskName),
		}
		h.SendRaw(response)
		return response, nil
	}

	h.logger.Info("starting cask installation via service layer",
		"installation_id", req.InstallationID,
		"cask_name", req.CaskName,
	)

	// Convert to service request
	serviceReq := &models.InstallRequest{
		InstallationID:   req.InstallationID,
		InstallationType: models.InstallationTypeCask,
		CaskName:         req.CaskName,
		PackageID:        req.CaskName,
		TimeoutSeconds:   req.TimeoutSeconds,
	}

	// Delegate to service layer
	result, err := h.softwareServices.Installation.Install(ctx, serviceReq)
	if err != nil {
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           err.Error(),
		}
		h.SendRaw(response)
		return response, nil
	}

	// Build response from service result
	response := map[string]interface{}{
		"action":          "software_install_result",
		"installation_id": result.InstallationID,
		"status":          string(result.Status),
		"exit_code":       result.ExitCode,
		"output":          result.Output,
		"error":           result.Error,
		"cask_name":       req.CaskName,
		"started_at":      result.StartedAt.UTC().Format(time.RFC3339),
		"completed_at":    result.CompletedAt.UTC().Format(time.RFC3339),
		"duration_ms":     int64(result.Duration * 1000),
	}

	h.SendRaw(response)
	h.logger.Info("cask installation completed via service layer",
		"installation_id", result.InstallationID,
		"status", result.Status,
		"exit_code", result.ExitCode,
		"duration", result.Duration,
	)

	return response, nil
}

// downloadAndInstallDEBRequest represents a DEB package download and install request.
type downloadAndInstallDEBRequest struct {
	InstallationID string `json:"installation_id"`
	DownloadURL    string `json:"download_url"`
	DownloadToken  string `json:"download_token,omitempty"`
	ExpectedHash   string `json:"expected_hash,omitempty"`
	Filename       string `json:"filename"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

// handleDownloadAndInstallDEB handles DEB package download and installation on Debian/Ubuntu.
// Delegates to the service layer for proper MVC separation.
func (h *Handler) handleDownloadAndInstallDEB(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if runtime.GOOS != "linux" {
		return map[string]interface{}{
			"status": "failed",
			"error":  "DEB installation is only available on Linux",
		}, nil
	}

	var req downloadAndInstallDEBRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("starting DEB installation via service layer",
		"installation_id", req.InstallationID,
		"filename", req.Filename,
	)

	// Normalize hash format - remove "sha256:" prefix if present
	expectedHash := req.ExpectedHash
	if strings.HasPrefix(expectedHash, "sha256:") {
		expectedHash = strings.TrimPrefix(expectedHash, "sha256:")
	}

	// Convert to service request
	serviceReq := &models.InstallRequest{
		InstallationID:   req.InstallationID,
		InstallationType: models.InstallationTypeDEB,
		DownloadURL:      req.DownloadURL,
		DownloadToken:    req.DownloadToken,
		ExpectedHash:     expectedHash,
		Filename:         req.Filename,
		TimeoutSeconds:   req.TimeoutSeconds,
	}

	// Delegate to service layer
	result, err := h.softwareServices.Installation.Install(ctx, serviceReq)
	if err != nil {
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           err.Error(),
		}
		h.SendRaw(response)
		return response, nil
	}

	// Build response from service result
	response := map[string]interface{}{
		"action":          "software_install_result",
		"installation_id": result.InstallationID,
		"status":          string(result.Status),
		"exit_code":       result.ExitCode,
		"output":          result.Output,
		"error":           result.Error,
		"started_at":      result.StartedAt.UTC().Format(time.RFC3339),
		"completed_at":    result.CompletedAt.UTC().Format(time.RFC3339),
		"duration_ms":     int64(result.Duration * 1000),
	}

	h.SendRaw(response)
	h.logger.Info("DEB installation completed via service layer",
		"installation_id", result.InstallationID,
		"status", result.Status,
		"exit_code", result.ExitCode,
		"duration", result.Duration,
	)

	return response, nil
}

// downloadAndInstallRPMRequest represents an RPM package download and install request.
type downloadAndInstallRPMRequest struct {
	InstallationID string `json:"installation_id"`
	DownloadURL    string `json:"download_url"`
	DownloadToken  string `json:"download_token,omitempty"`
	ExpectedHash   string `json:"expected_hash,omitempty"`
	Filename       string `json:"filename"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

// handleDownloadAndInstallRPM handles RPM package download and installation on RHEL/CentOS/Fedora/SUSE.
// Delegates to the service layer for proper MVC separation.
func (h *Handler) handleDownloadAndInstallRPM(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if runtime.GOOS != "linux" {
		return map[string]interface{}{
			"status": "failed",
			"error":  "RPM installation is only available on Linux",
		}, nil
	}

	var req downloadAndInstallRPMRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("starting RPM installation via service layer",
		"installation_id", req.InstallationID,
		"filename", req.Filename,
	)

	// Normalize hash format - remove "sha256:" prefix if present
	expectedHash := req.ExpectedHash
	if strings.HasPrefix(expectedHash, "sha256:") {
		expectedHash = strings.TrimPrefix(expectedHash, "sha256:")
	}

	// Convert to service request
	serviceReq := &models.InstallRequest{
		InstallationID:   req.InstallationID,
		InstallationType: models.InstallationTypeRPM,
		DownloadURL:      req.DownloadURL,
		DownloadToken:    req.DownloadToken,
		ExpectedHash:     expectedHash,
		Filename:         req.Filename,
		TimeoutSeconds:   req.TimeoutSeconds,
	}

	// Delegate to service layer
	result, err := h.softwareServices.Installation.Install(ctx, serviceReq)
	if err != nil {
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           err.Error(),
		}
		h.SendRaw(response)
		return response, nil
	}

	// Build response from service result
	response := map[string]interface{}{
		"action":          "software_install_result",
		"installation_id": result.InstallationID,
		"status":          string(result.Status),
		"exit_code":       result.ExitCode,
		"output":          result.Output,
		"error":           result.Error,
		"started_at":      result.StartedAt.UTC().Format(time.RFC3339),
		"completed_at":    result.CompletedAt.UTC().Format(time.RFC3339),
		"duration_ms":     int64(result.Duration * 1000),
	}

	h.SendRaw(response)
	h.logger.Info("RPM installation completed via service layer",
		"installation_id", result.InstallationID,
		"status", result.Status,
		"exit_code", result.ExitCode,
		"duration", result.Duration,
	)

	return response, nil
}
