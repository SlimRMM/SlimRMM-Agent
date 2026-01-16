// Package handler provides software installation handlers.
package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/helper"
	"github.com/slimrmm/slimrmm-agent/internal/winget"
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
	InstallationID   string `json:"installation_id"`
	InstallationType string `json:"installation_type"` // "winget" or "msi"
	WingetPackageID  string `json:"winget_package_id,omitempty"`
	WingetVersion    string `json:"winget_version,omitempty"`
	InstallScope     string `json:"install_scope,omitempty"` // "machine" or "user"
	Silent           bool   `json:"silent"`
	TimeoutSeconds   int    `json:"timeout_seconds,omitempty"`
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

	h.logger.Info("starting software installation",
		"installation_id", req.InstallationID,
		"installation_type", req.InstallationType,
		"winget_package_id", req.WingetPackageID,
	)

	// Set timeout
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Track this installation so it can be cancelled
	runningInstallations.Lock()
	runningInstallations.m[req.InstallationID] = &runningInstallation{cancel: cancel}
	runningInstallations.Unlock()
	defer func() {
		runningInstallations.Lock()
		delete(runningInstallations.m, req.InstallationID)
		runningInstallations.Unlock()
	}()

	// Send progress update
	h.SendRaw(map[string]interface{}{
		"action":          "software_install_progress",
		"installation_id": req.InstallationID,
		"status":          "installing",
		"output":          fmt.Sprintf("Installing %s...", req.WingetPackageID),
	})

	if req.InstallationType != "winget" {
		return map[string]interface{}{
			"status": "failed",
			"error":  "only winget installations are supported via this handler",
		}, nil
	}

	// Check if winget is available
	wingetClient := winget.GetDefault()
	if !wingetClient.IsAvailable() {
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           "winget is not available on this system",
		}
		h.SendRaw(response)
		return response, nil
	}

	startedAt := time.Now()
	wingetPath := wingetClient.GetBinaryPath()

	// Build winget install command
	scope := req.InstallScope
	if scope == "" {
		scope = "machine"
	}

	// Try user context first via helper if available
	var output string
	var exitCode int
	var installContext string

	helperClient, helperErr := helper.GetManager().Acquire()
	if helperErr == nil {
		defer helper.GetManager().Release()

		h.logger.Info("trying winget install in user context", "package_id", req.WingetPackageID)
		h.SendRaw(map[string]interface{}{
			"action":          "software_install_progress",
			"installation_id": req.InstallationID,
			"status":          "installing",
			"output":          "Trying user context installation...\n",
		})

		// Execute via helper (user context) using the proper install function
		result, err := helperClient.InstallWingetPackage(wingetPath, req.WingetPackageID, req.WingetVersion, scope, req.Silent)
		if err == nil && result != nil && result.Success {
			output = result.Output
			exitCode = result.ExitCode
			installContext = "user"
			h.logger.Info("winget install succeeded in user context", "package_id", req.WingetPackageID)
		} else {
			// Log the failure reason
			errMsg := "unknown error"
			if err != nil {
				errMsg = err.Error()
			} else if result != nil {
				errMsg = result.Error
				output = result.Output // Keep output for debugging
			}
			h.logger.Info("user context failed, trying system context", "package_id", req.WingetPackageID, "error", errMsg)
			installContext = "system"
		}
	} else {
		h.logger.Info("helper not available, using system context", "error", helperErr)
		installContext = "system"
	}

	// System context installation
	if installContext == "system" {
		h.SendRaw(map[string]interface{}{
			"action":          "software_install_progress",
			"installation_id": req.InstallationID,
			"status":          "installing",
			"output":          "Installing in system context...\n",
		})

		args := []string{
			"install",
			"--id", req.WingetPackageID,
			"--scope", scope,
			"--accept-source-agreements",
			"--accept-package-agreements",
		}
		if req.Silent {
			args = append(args, "--silent")
		}
		if req.WingetVersion != "" && req.WingetVersion != "latest" {
			args = append(args, "--version", req.WingetVersion)
		}

		cmd := exec.CommandContext(ctx, wingetPath, args...)
		outputBytes, err := cmd.CombinedOutput()
		output = string(outputBytes)

		if err != nil {
			if exitError, ok := err.(*exec.ExitError); ok {
				exitCode = exitError.ExitCode()
			} else {
				exitCode = -1
			}
		}
	}

	// Determine success
	completedAt := time.Now()
	status := "completed"
	if ctx.Err() == context.Canceled {
		status = "cancelled"
		output = "Installation cancelled by user request"
	} else if exitCode != 0 {
		status = "failed"
	}

	response := map[string]interface{}{
		"action":          "software_install_result",
		"installation_id": req.InstallationID,
		"status":          status,
		"exit_code":       exitCode,
		"output":          output,
		"context":         installContext,
		"started_at":      startedAt.UTC().Format(time.RFC3339),
		"completed_at":    completedAt.UTC().Format(time.RFC3339),
		"duration_ms":     completedAt.Sub(startedAt).Milliseconds(),
	}

	h.SendRaw(response)
	h.logger.Info("software installation completed",
		"installation_id", req.InstallationID,
		"status", status,
		"exit_code", exitCode,
		"duration_ms", completedAt.Sub(startedAt).Milliseconds(),
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

	h.logger.Info("starting MSI download and install",
		"installation_id", req.InstallationID,
		"filename", req.Filename,
	)

	// Set timeout
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Track this installation so it can be cancelled
	runningInstallations.Lock()
	runningInstallations.m[req.InstallationID] = &runningInstallation{cancel: cancel}
	runningInstallations.Unlock()
	defer func() {
		runningInstallations.Lock()
		delete(runningInstallations.m, req.InstallationID)
		runningInstallations.Unlock()
	}()

	startedAt := time.Now()

	// Create temp directory for download
	tempDir, err := os.MkdirTemp("", "slimrmm-msi-*")
	if err != nil {
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           fmt.Sprintf("failed to create temp directory: %v", err),
		}
		h.SendRaw(response)
		return response, nil
	}
	defer os.RemoveAll(tempDir)

	msiPath := filepath.Join(tempDir, req.Filename)

	// Send progress: downloading
	h.SendRaw(map[string]interface{}{
		"action":           "software_install_progress",
		"installation_id":  req.InstallationID,
		"status":           "downloading",
		"progress_percent": 0,
	})

	// Download the MSI file
	err = h.downloadFile(ctx, req.DownloadURL, req.DownloadToken, msiPath, req.InstallationID)
	if err != nil {
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           fmt.Sprintf("failed to download MSI: %v", err),
		}
		h.SendRaw(response)
		return response, nil
	}

	// Verify hash
	if req.ExpectedHash != "" {
		calculatedHash, err := calculateFileHash(msiPath)
		if err != nil {
			response := map[string]interface{}{
				"action":          "software_install_result",
				"installation_id": req.InstallationID,
				"status":          "failed",
				"error":           fmt.Sprintf("failed to calculate file hash: %v", err),
			}
			h.SendRaw(response)
			return response, nil
		}

		if calculatedHash != req.ExpectedHash {
			response := map[string]interface{}{
				"action":          "software_install_result",
				"installation_id": req.InstallationID,
				"status":          "failed",
				"error":           fmt.Sprintf("hash mismatch: expected %s, got %s", req.ExpectedHash, calculatedHash),
			}
			h.SendRaw(response)
			return response, nil
		}

		h.logger.Info("MSI hash verified", "installation_id", req.InstallationID)
	}

	// Send progress: installing
	h.SendRaw(map[string]interface{}{
		"action":          "software_install_progress",
		"installation_id": req.InstallationID,
		"status":          "installing",
		"output":          "Installing MSI package...",
	})

	// Build msiexec command
	logPath := filepath.Join(tempDir, "install.log")
	silentArgs := req.SilentArgs
	if silentArgs == "" {
		silentArgs = "/quiet /norestart"
	}

	args := []string{"/i", msiPath}
	args = append(args, parseArgs(silentArgs)...)
	args = append(args, "/log", logPath)

	cmd := exec.CommandContext(ctx, "msiexec", args...)
	outputBytes, err := cmd.CombinedOutput()
	output := string(outputBytes)

	// Read log file if it exists
	var logContent string
	if logBytes, err := os.ReadFile(logPath); err == nil {
		logContent = string(logBytes)
	}

	// Determine exit code
	var exitCode int
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = -1
		}
	}

	// Determine success (msiexec returns 0 for success, 3010 for success with reboot required)
	completedAt := time.Now()
	status := "completed"
	if ctx.Err() == context.Canceled {
		status = "cancelled"
		output = "Installation cancelled by user request"
	} else if exitCode != 0 && exitCode != 3010 {
		status = "failed"
	}

	response := map[string]interface{}{
		"action":          "software_install_result",
		"installation_id": req.InstallationID,
		"status":          status,
		"exit_code":       exitCode,
		"output":          output,
		"msi_log":         logContent,
		"started_at":      startedAt.UTC().Format(time.RFC3339),
		"completed_at":    completedAt.UTC().Format(time.RFC3339),
		"duration_ms":     completedAt.Sub(startedAt).Milliseconds(),
	}

	if exitCode == 3010 {
		response["reboot_required"] = true
	}

	h.SendRaw(response)
	h.logger.Info("MSI installation completed",
		"installation_id", req.InstallationID,
		"status", status,
		"exit_code", exitCode,
		"duration_ms", completedAt.Sub(startedAt).Milliseconds(),
	)

	return response, nil
}

// downloadFile downloads a file from URL to the specified path.
func (h *Handler) downloadFile(ctx context.Context, url, token, destPath, installationID string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{
		Timeout: 10 * time.Minute,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	// Create destination file
	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	// Copy with progress
	totalSize := resp.ContentLength
	var downloaded int64
	lastProgress := 0

	buf := make([]byte, 32*1024) // 32KB buffer
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			_, writeErr := out.Write(buf[:n])
			if writeErr != nil {
				return fmt.Errorf("failed to write file: %w", writeErr)
			}
			downloaded += int64(n)

			// Send progress updates every 10%
			if totalSize > 0 {
				progress := int(float64(downloaded) / float64(totalSize) * 100)
				if progress >= lastProgress+10 {
					lastProgress = progress
					h.SendRaw(map[string]interface{}{
						"action":           "software_install_progress",
						"installation_id":  installationID,
						"status":           "downloading",
						"progress_percent": progress,
					})
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read response: %w", err)
		}
	}

	return nil
}

// calculateFileHash calculates SHA256 hash of a file.
func calculateFileHash(path string) (string, error) {
	f, err := os.Open(path)
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
