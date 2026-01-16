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

	// Always use helper (user context) for winget installations.
	// The --scope parameter determines WHERE software is installed (machine=all users, user=current user),
	// but winget.exe must run in user context because:
	// 1. SYSTEM context lacks DLL dependencies (STATUS_DLL_NOT_FOUND / 0xC0000135)
	// 2. winget is a Windows Store app that requires user environment
	// 3. The helper runs silently without UAC prompts
	var output string
	var exitCode int
	var installContext string

	helperClient, helperErr := helper.GetManager().Acquire()
	if helperErr == nil {
		defer helper.GetManager().Release()

		h.logger.Info("installing via helper", "package_id", req.WingetPackageID, "scope", scope)
		h.SendRaw(map[string]interface{}{
			"action":          "software_install_progress",
			"installation_id": req.InstallationID,
			"status":          "installing",
			"output":          fmt.Sprintf("Installing %s (scope: %s)...\n", req.WingetPackageID, scope),
		})

		// Execute via helper - scope parameter controls machine vs user installation
		result, err := helperClient.InstallWingetPackage(wingetPath, req.WingetPackageID, req.WingetVersion, scope, req.Silent)
		if err == nil && result != nil && result.Success {
			output = result.Output
			exitCode = result.ExitCode
			installContext = "helper"
			h.logger.Info("winget install succeeded via helper", "package_id", req.WingetPackageID, "scope", scope)
		} else {
			// Log the failure reason
			errMsg := "unknown error"
			if err != nil {
				errMsg = err.Error()
			} else if result != nil {
				errMsg = result.Error
				output = result.Output // Keep output for debugging
				exitCode = result.ExitCode
			}
			h.logger.Warn("helper install failed", "package_id", req.WingetPackageID, "error", errMsg, "exit_code", exitCode)
			// Don't fall back to system context - it will fail with DLL errors
			// Just report the failure
			installContext = "helper"
		}
	} else {
		h.logger.Warn("helper not available, trying system context (may fail)", "error", helperErr)
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

		// Use PowerShell to run winget - this ensures proper environment setup
		// Direct winget execution from SYSTEM service context often fails with
		// STATUS_DLL_NOT_FOUND (0xC0000135) due to missing dependencies in PATH
		output, exitCode = runWingetViaPowerShell(ctx, wingetPath, req.WingetPackageID, req.WingetVersion, scope, req.Silent, h.logger)
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

// runWingetViaPowerShell executes winget install through PowerShell.
// This is necessary because running winget.exe directly from a SYSTEM service
// context often fails with STATUS_DLL_NOT_FOUND (0xC0000135) due to missing
// dependencies in the process environment. PowerShell properly initializes
// the Windows environment and can run winget successfully.
func runWingetViaPowerShell(ctx context.Context, wingetPath, packageID, version, scope string, silent bool, logger interface{ Info(msg string, args ...any) }) (string, int) {
	// Build PowerShell script that runs winget with proper environment
	versionArg := ""
	if version != "" && version != "latest" {
		versionArg = fmt.Sprintf("'--version', '%s',", version)
	}

	silentArg := ""
	if silent {
		silentArg = "'--silent',"
	}

	// PowerShell script to run winget
	// Using Start-Process with -Wait to properly capture exit code
	script := fmt.Sprintf(`
$ErrorActionPreference = 'Continue'
$env:WINGET_DISABLE_INTERACTIVITY = '1'

# Try to find winget if path doesn't work directly
$wingetPath = '%s'
if (-not (Test-Path $wingetPath)) {
    # Search in WindowsApps
    $dirs = Get-ChildItem 'C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*' -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending
    foreach ($dir in $dirs) {
        $path = Join-Path $dir.FullName 'winget.exe'
        if (Test-Path $path) {
            $wingetPath = $path
            break
        }
    }
}

if (-not (Test-Path $wingetPath)) {
    Write-Host "ERROR: winget.exe not found"
    exit 1
}

Write-Host "Using winget at: $wingetPath"

# Build arguments
$args = @(
    'install',
    '--id', '%s',
    '--scope', '%s',
    '--accept-source-agreements',
    '--accept-package-agreements',
    %s
    %s
    '--disable-interactivity'
)

# Remove empty args
$args = $args | Where-Object { $_ -ne '' }

Write-Host "Running: winget $($args -join ' ')"

# Run winget and capture output
$pinfo = New-Object System.Diagnostics.ProcessStartInfo
$pinfo.FileName = $wingetPath
$pinfo.Arguments = $args -join ' '
$pinfo.RedirectStandardOutput = $true
$pinfo.RedirectStandardError = $true
$pinfo.UseShellExecute = $false
$pinfo.CreateNoWindow = $true

$process = New-Object System.Diagnostics.Process
$process.StartInfo = $pinfo

try {
    $process.Start() | Out-Null
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    Write-Host $stdout
    if ($stderr) { Write-Host "STDERR: $stderr" }

    exit $process.ExitCode
} catch {
    Write-Host "ERROR: $_"
    exit 1
}
`, wingetPath, packageID, scope, versionArg, silentArg)

	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", script,
	)

	outputBytes, err := cmd.CombinedOutput()
	output := string(outputBytes)

	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = -1
		}
	}

	if logger != nil {
		logger.Info("winget via PowerShell completed",
			"package_id", packageID,
			"exit_code", exitCode,
			"output_length", len(output),
		)
	}

	return output, exitCode
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
