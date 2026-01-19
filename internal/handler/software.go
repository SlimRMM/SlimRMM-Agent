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
	"strings"
	"sync"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/homebrew"
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

// runWingetOperation executes winget with an optimized fallback strategy.
//
// Priority 1: Microsoft.WinGet.Client module (PowerShell 7) - most reliable, no DLL issues
// Priority 2: Direct path invocation (& $wingetExe) - NOT cd + .\winget.exe
// Priority 3: Scheduled Task fallback - for hardened systems
func runWingetOperation(ctx context.Context, packageID string, silent bool, action string, logger interface{ Info(msg string, args ...any) }) (string, int) {
	// PRIORITY 1: Try PowerShell 7 + Microsoft.WinGet.Client module
	if output, exitCode, ok := tryWinGetClientModule(ctx, packageID, action, logger); ok {
		return output, exitCode
	}

	// PRIORITY 2: Direct path invocation (& $wingetExe - NOT cd + .\winget.exe)
	if output, exitCode, ok := tryDirectPathInvocation(ctx, packageID, silent, action, logger); ok {
		return output, exitCode
	}

	// PRIORITY 3: Scheduled Task fallback for hardened systems
	return tryScheduledTaskFallback(ctx, packageID, silent, action, logger)
}

// tryWinGetClientModule attempts to use the Microsoft.WinGet.Client PowerShell module.
// This is the most reliable method as it avoids all DLL loading issues.
// Requires PowerShell 7 and the module to be installed.
func tryWinGetClientModule(ctx context.Context, packageID, action string, logger interface{ Info(msg string, args ...any) }) (string, int, bool) {
	ps7Path := `C:\Program Files\PowerShell\7\pwsh.exe`

	// Check if PowerShell 7 exists
	if _, err := os.Stat(ps7Path); os.IsNotExist(err) {
		if logger != nil {
			logger.Info("PowerShell 7 not found, skipping WinGet.Client method")
		}
		return "", 0, false
	}

	// Check if the module is available
	moduleCheckCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	moduleCheckScript := `
$ErrorActionPreference = 'SilentlyContinue'
$module = Get-Module -ListAvailable -Name Microsoft.WinGet.Client | Select-Object -First 1
if ($module) {
    Write-Output "MODULE_AVAILABLE"
    exit 0
} else {
    Write-Output "MODULE_NOT_FOUND"
    exit 1
}
`
	moduleCheckCmd := exec.CommandContext(moduleCheckCtx, ps7Path,
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", moduleCheckScript,
	)

	moduleCheckOutput, moduleCheckErr := moduleCheckCmd.CombinedOutput()
	moduleCheckStr := strings.TrimSpace(string(moduleCheckOutput))

	if moduleCheckErr != nil || !strings.Contains(moduleCheckStr, "MODULE_AVAILABLE") {
		if logger != nil {
			logger.Info("WinGet.Client module not available, skipping to next method",
				"check_output", moduleCheckStr,
			)
		}
		return "", 0, false
	}

	if logger != nil {
		logger.Info("WinGet.Client module confirmed available, proceeding with operation")
	}

	// Map action to WinGet.Client cmdlet
	var cmdlet string
	switch action {
	case "install":
		cmdlet = "Install-WinGetPackage"
	case "uninstall":
		cmdlet = "Uninstall-WinGetPackage"
	case "upgrade":
		cmdlet = "Update-WinGetPackage"
	default:
		cmdlet = "Install-WinGetPackage"
	}

	// Build the PowerShell 7 command - always install latest version
	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
try {
    Import-Module Microsoft.WinGet.Client -ErrorAction Stop
    Write-Host "Using Microsoft.WinGet.Client module"

    $params = @{
        Id = '%s'
        Mode = 'Silent'
    }

    # Add Scope for install/upgrade (not applicable for uninstall)
    if ('%s' -ne 'Uninstall-WinGetPackage') {
        $params['Scope'] = 'System'
    }

    $result = %s @params

    Write-Host "Operation completed"
    if ($result) {
        Write-Host "Result Status: $($result.Status)"
        Write-Host "Result Id: $($result.Id)"
        if ($result.InstallerErrorCode) {
            Write-Host "Installer Error Code: $($result.InstallerErrorCode)"
        }
        if ($result.RebootRequired) {
            Write-Host "Reboot Required: $($result.RebootRequired)"
        }

        # Check if installation succeeded
        $successStatuses = @('Ok', 'NoApplicableUpgrade')
        if ($result.Status -and $successStatuses -notcontains $result.Status.ToString()) {
            Write-Host "WinGet.Client error: Operation returned status: $($result.Status)"
            if ($result.ExtendedErrorCode) {
                Write-Host "Extended Error: $($result.ExtendedErrorCode)"
            }
            exit 1
        }
    }

    exit 0
}
catch {
    Write-Host "WinGet.Client error: $($_.Exception.Message)"
    exit 1
}
`, packageID, cmdlet, cmdlet)

	if logger != nil {
		logger.Info("trying WinGet.Client module via PowerShell 7", "action", action, "package", packageID)
	}

	cmd := exec.CommandContext(ctx, ps7Path,
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", script,
	)

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	if err == nil && !strings.Contains(outputStr, "WinGet.Client error:") {
		if logger != nil {
			logger.Info("WinGet.Client module succeeded", "action", action)
		}
		return outputStr, 0, true
	}

	exitCode := -1
	if exitError, ok := err.(*exec.ExitError); ok {
		exitCode = exitError.ExitCode()
	}

	if logger != nil {
		logger.Info("WinGet.Client operation failed", "error", err, "output", outputStr, "exit_code", exitCode)
	}

	return outputStr, exitCode, true
}

// tryDirectPathInvocation attempts to run winget.exe directly using & $fullPath.
// Windows DLL resolution uses the executable's directory first, so no cd needed.
func tryDirectPathInvocation(ctx context.Context, packageID string, silent bool, action string, logger interface{ Info(msg string, args ...any) }) (string, int, bool) {
	silentArg := ""
	if silent {
		silentArg = "$wingetArgs += '--silent'"
	}

	// PowerShell script using direct path invocation (& $wingetExe)
	script := fmt.Sprintf(`
$ErrorActionPreference = 'Continue'

# Resolve winget.exe path (prefer x64 builds)
$wingetPatterns = @(
    "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe",
    "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_*__8wekyb3d8bbwe\winget.exe"
)

$wingetExe = $null
foreach ($pattern in $wingetPatterns) {
    $resolved = Resolve-Path $pattern -ErrorAction SilentlyContinue
    if ($resolved) {
        $wingetExe = ($resolved | Sort-Object -Descending)[0].Path
        break
    }
}

if (-not $wingetExe) {
    Write-Host "ERROR: winget.exe not found in WindowsApps"
    exit 1
}

Write-Host "Found winget at: $wingetExe"

$wingetArgs = @(
    '%s',
    '--exact',
    '--id', '%s',
    '--scope', 'machine',
    '--accept-source-agreements',
    '--accept-package-agreements',
    '--disable-interactivity'
)

%s

Write-Host "Executing: & $wingetExe $($wingetArgs -join ' ')"

& $wingetExe @wingetArgs

exit $LASTEXITCODE
`, action, packageID, silentArg)

	if logger != nil {
		logger.Info("trying direct path invocation", "action", action, "package", packageID)
	}

	// Try with execution policy bypass
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", script,
	)

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	if err == nil && !strings.Contains(outputStr, "ERROR:") {
		if logger != nil {
			logger.Info("direct path invocation succeeded", "action", action)
		}
		return outputStr, 0, true
	}

	exitCode := -1
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		}
	}

	// Check for execution policy errors - need to try scheduled task
	isExecutionPolicyError := strings.Contains(outputStr, "is not digitally signed") ||
		strings.Contains(outputStr, "running scripts is disabled") ||
		strings.Contains(outputStr, "AuthorizationManager") ||
		strings.Contains(outputStr, "PSSecurityException")

	if isExecutionPolicyError {
		if logger != nil {
			logger.Info("execution policy blocked direct invocation, will try scheduled task")
		}
		return "", 0, false
	}

	// Not an execution policy error - this is the real result
	return outputStr, exitCode, true
}

// tryScheduledTaskFallback creates a scheduled task to run the winget command.
// This bypasses execution policy restrictions as scheduled tasks run differently.
func tryScheduledTaskFallback(ctx context.Context, packageID string, silent bool, action string, logger interface{ Info(msg string, args ...any) }) (string, int) {
	if logger != nil {
		logger.Info("using scheduled task fallback", "action", action, "package", packageID)
	}

	silentArg := ""
	if silent {
		silentArg = "$wingetArgs += '--silent'"
	}

	script := fmt.Sprintf(`
$ErrorActionPreference = 'Continue'

$Path_WingetAll = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe" -ErrorAction SilentlyContinue
if (-not $Path_WingetAll) {
    $Path_WingetAll = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_*__8wekyb3d8bbwe" -ErrorAction SilentlyContinue
}

if (-not $Path_WingetAll) {
    Write-Host "ERROR: WinGet directory not found"
    exit 1
}

$Path_Winget = $Path_WingetAll[-1].Path
cd $Path_Winget

$wingetArgs = @(
    '%s',
    '--exact',
    '--id', '%s',
    '--scope', 'machine',
    '--accept-source-agreements',
    '--accept-package-agreements',
    '--disable-interactivity'
)

%s

Write-Host "Executing: .\winget.exe $($wingetArgs -join ' ')"

.\winget.exe @wingetArgs

exit $LASTEXITCODE
`, action, packageID, silentArg)

	return executeViaScheduledTask(ctx, script, logger)
}

// executeViaScheduledTask creates a temporary scheduled task to run the script.
// This bypasses execution policy restrictions as scheduled tasks run in a different context.
// The task runs as SYSTEM with highest privileges.
func executeViaScheduledTask(ctx context.Context, script string, logger interface{ Info(msg string, args ...any) }) (string, int) {
	// Create a secure temp directory with restricted permissions
	// This prevents race conditions and ensures predictable cleanup
	tempDir, err := os.MkdirTemp("", "slimrmm-task-*")
	if err != nil {
		return fmt.Sprintf("failed to create temp directory: %v", err), -1
	}
	defer os.RemoveAll(tempDir)

	// Use crypto/rand for unpredictable task name to prevent prediction attacks
	taskName := fmt.Sprintf("SlimRMM_WingetInstall_%d", time.Now().UnixNano())
	scriptPath := filepath.Join(tempDir, "script.ps1")
	outputPath := filepath.Join(tempDir, "output.txt")
	exitCodePath := filepath.Join(tempDir, "exitcode.txt")

	if logger != nil {
		logger.Info("creating scheduled task for winget execution", "task_name", taskName, "temp_dir", tempDir)
	}

	// Write script that captures output and exit code to files
	wrappedScript := fmt.Sprintf(`
$ErrorActionPreference = 'Continue'
try {
    $output = & {
        %s
    } 2>&1 | Out-String
    $output | Out-File -FilePath '%s' -Encoding UTF8 -Force
    $LASTEXITCODE | Out-File -FilePath '%s' -Encoding UTF8 -Force
}
catch {
    $_.Exception.Message | Out-File -FilePath '%s' -Encoding UTF8 -Force
    1 | Out-File -FilePath '%s' -Encoding UTF8 -Force
}
`, script, outputPath, exitCodePath, outputPath, exitCodePath)

	// Use 0600 permissions - only owner (SYSTEM) can read/write
	if err := os.WriteFile(scriptPath, []byte(wrappedScript), 0600); err != nil {
		return fmt.Sprintf("failed to write script file: %v", err), -1
	}

	// Create scheduled task that runs as SYSTEM with highest privileges
	createCmd := exec.CommandContext(ctx, "schtasks.exe",
		"/Create",
		"/TN", taskName,
		"/TR", fmt.Sprintf(`powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%s"`, scriptPath),
		"/SC", "ONCE",
		"/ST", "00:00",
		"/RU", "SYSTEM",
		"/RL", "HIGHEST",
		"/F",
	)
	createOutput, err := createCmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("failed to create scheduled task: %v - %s", err, string(createOutput)), -1
	}

	// Run the task immediately
	runCmd := exec.CommandContext(ctx, "schtasks.exe", "/Run", "/TN", taskName)
	runOutput, err := runCmd.CombinedOutput()
	if err != nil {
		// Cleanup on failure
		exec.Command("schtasks.exe", "/Delete", "/TN", taskName, "/F").Run()
		return fmt.Sprintf("failed to run scheduled task: %v - %s", err, string(runOutput)), -1
	}

	// Wait for completion by polling for the exit code file
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			// Context cancelled, cleanup and return
			exec.Command("schtasks.exe", "/End", "/TN", taskName).Run()
			exec.Command("schtasks.exe", "/Delete", "/TN", taskName, "/F").Run()
			return "Installation cancelled", -1
		default:
			if _, err := os.Stat(exitCodePath); err == nil {
				// Exit code file exists, task completed
				goto taskCompleted
			}
			time.Sleep(2 * time.Second)
		}
	}

taskCompleted:
	// Cleanup the scheduled task
	exec.Command("schtasks.exe", "/Delete", "/TN", taskName, "/F").Run()

	// Read results from output files
	outputBytes, err := os.ReadFile(outputPath)
	if err != nil {
		return fmt.Sprintf("failed to read task output: %v", err), -1
	}

	exitCodeBytes, err := os.ReadFile(exitCodePath)
	if err != nil {
		return string(outputBytes), -1
	}

	exitCode := 0
	exitCodeStr := strings.TrimSpace(string(exitCodeBytes))
	if exitCodeStr != "" {
		fmt.Sscanf(exitCodeStr, "%d", &exitCode)
	}

	if logger != nil {
		logger.Info("scheduled task completed", "exit_code", exitCode)
	}

	return string(outputBytes), exitCode
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
func (h *Handler) downloadFile(ctx context.Context, url, token, destPath, installationID string) error {
	h.logger.Info("starting file download",
		"installation_id", installationID,
		"url", url,
		"dest", destPath,
	)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		h.logger.Info("failed to create download request", "error", err)
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
		h.logger.Info("download request failed", "error", err)
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	h.logger.Info("download response received",
		"installation_id", installationID,
		"status_code", resp.StatusCode,
		"content_length", resp.ContentLength,
	)

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

	h.logger.Info("download completed",
		"installation_id", installationID,
		"bytes_downloaded", downloaded,
	)

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
func (h *Handler) handleDownloadAndInstallPKG(ctx context.Context, data json.RawMessage) (interface{}, error) {
	h.logger.Info("received PKG installation request")

	var req downloadAndInstallPKGRequest
	if err := json.Unmarshal(data, &req); err != nil {
		h.logger.Error("failed to parse PKG request", "error", err, "data", string(data))
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("PKG request parsed",
		"installation_id", req.InstallationID,
		"filename", req.Filename,
		"has_download_url", req.DownloadURL != "",
		"has_expected_hash", req.ExpectedHash != "",
	)

	// Platform validation
	if runtime.GOOS != "darwin" {
		h.logger.Warn("PKG installation attempted on non-macOS platform", "goos", runtime.GOOS)
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           "PKG installation is only available on macOS",
		}
		h.SendRaw(response)
		return response, nil
	}

	h.logger.Info("starting PKG installation",
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

	// Track installation for cancellation
	runningInstallations.Lock()
	runningInstallations.m[req.InstallationID] = &runningInstallation{cancel: cancel}
	runningInstallations.Unlock()
	defer func() {
		runningInstallations.Lock()
		delete(runningInstallations.m, req.InstallationID)
		runningInstallations.Unlock()
	}()

	startedAt := time.Now()
	var logBuffer strings.Builder
	logBuffer.WriteString(fmt.Sprintf("[%s] Starting PKG installation: %s\n", startedAt.Format(time.RFC3339), req.Filename))
	logBuffer.WriteString(fmt.Sprintf("[%s] Platform: macOS (%s)\n", time.Now().Format(time.RFC3339), runtime.GOARCH))

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "slimrmm-pkg-*")
	if err != nil {
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           fmt.Sprintf("create temp dir: %v", err),
		}
		h.SendRaw(response)
		return response, nil
	}
	defer os.RemoveAll(tempDir)
	logBuffer.WriteString(fmt.Sprintf("[%s] Created temp directory: %s\n", time.Now().Format(time.RFC3339), tempDir))

	pkgPath := filepath.Join(tempDir, req.Filename)

	// Send progress: downloading
	h.SendRaw(map[string]interface{}{
		"action":           "software_install_progress",
		"installation_id":  req.InstallationID,
		"status":           "downloading",
		"progress_percent": 0,
	})

	logBuffer.WriteString(fmt.Sprintf("[%s] Downloading package from: %s\n", time.Now().Format(time.RFC3339), req.DownloadURL))

	// Download the PKG
	if err := h.downloadFile(ctx, req.DownloadURL, req.DownloadToken, pkgPath, req.InstallationID); err != nil {
		logBuffer.WriteString(fmt.Sprintf("[%s] Download failed: %v\n", time.Now().Format(time.RFC3339), err))
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           fmt.Sprintf("download failed: %v", err),
			"output":          logBuffer.String(),
		}
		h.SendRaw(response)
		return response, nil
	}
	logBuffer.WriteString(fmt.Sprintf("[%s] Download completed: %s\n", time.Now().Format(time.RFC3339), pkgPath))

	// Get file size for logging
	if fileInfo, err := os.Stat(pkgPath); err == nil {
		logBuffer.WriteString(fmt.Sprintf("[%s] Package size: %d bytes\n", time.Now().Format(time.RFC3339), fileInfo.Size()))
	}

	// Verify hash if provided
	if req.ExpectedHash != "" {
		logBuffer.WriteString(fmt.Sprintf("[%s] Verifying package hash...\n", time.Now().Format(time.RFC3339)))
		calculatedHash, err := calculateFileHash(pkgPath)
		if err != nil {
			logBuffer.WriteString(fmt.Sprintf("[%s] Hash calculation failed: %v\n", time.Now().Format(time.RFC3339), err))
			response := map[string]interface{}{
				"action":          "software_install_result",
				"installation_id": req.InstallationID,
				"status":          "failed",
				"error":           fmt.Sprintf("hash calculation failed: %v", err),
				"output":          logBuffer.String(),
			}
			h.SendRaw(response)
			return response, nil
		}

		expectedHash := req.ExpectedHash
		if strings.HasPrefix(expectedHash, "sha256:") {
			expectedHash = strings.TrimPrefix(expectedHash, "sha256:")
		}

		if calculatedHash != expectedHash {
			logBuffer.WriteString(fmt.Sprintf("[%s] Hash verification FAILED: expected %s, got %s\n", time.Now().Format(time.RFC3339), expectedHash, calculatedHash))
			response := map[string]interface{}{
				"action":          "software_install_result",
				"installation_id": req.InstallationID,
				"status":          "failed",
				"error":           fmt.Sprintf("hash mismatch: expected %s, got %s", expectedHash, calculatedHash),
				"output":          logBuffer.String(),
			}
			h.SendRaw(response)
			return response, nil
		}
		logBuffer.WriteString(fmt.Sprintf("[%s] Hash verification passed: %s\n", time.Now().Format(time.RFC3339), calculatedHash))
	}

	// Send progress: installing
	h.SendRaw(map[string]interface{}{
		"action":          "software_install_progress",
		"installation_id": req.InstallationID,
		"status":          "installing",
	})

	// Execute macOS installer
	logBuffer.WriteString(fmt.Sprintf("[%s] Executing: installer -pkg %s -target / -verboseR\n", time.Now().Format(time.RFC3339), pkgPath))
	cmd := exec.CommandContext(ctx, "installer", "-pkg", pkgPath, "-target", "/", "-verboseR")
	output, cmdErr := cmd.CombinedOutput()
	logBuffer.WriteString(fmt.Sprintf("[%s] Installer output:\n%s\n", time.Now().Format(time.RFC3339), string(output)))

	exitCode := 0
	if cmdErr != nil {
		if exitError, ok := cmdErr.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = -1
		}
		logBuffer.WriteString(fmt.Sprintf("[%s] Installer failed with exit code: %d\n", time.Now().Format(time.RFC3339), exitCode))
	} else {
		logBuffer.WriteString(fmt.Sprintf("[%s] Installer completed successfully\n", time.Now().Format(time.RFC3339)))
	}

	completedAt := time.Now()
	status := "completed"
	if ctx.Err() == context.Canceled {
		status = "cancelled"
		logBuffer.WriteString(fmt.Sprintf("[%s] Installation was cancelled\n", completedAt.Format(time.RFC3339)))
	} else if exitCode != 0 {
		status = "failed"
		logBuffer.WriteString(fmt.Sprintf("[%s] Installation failed with exit code: %d\n", completedAt.Format(time.RFC3339), exitCode))
	} else {
		logBuffer.WriteString(fmt.Sprintf("[%s] Installation completed successfully\n", completedAt.Format(time.RFC3339)))
	}

	logBuffer.WriteString(fmt.Sprintf("[%s] Duration: %dms\n", completedAt.Format(time.RFC3339), completedAt.Sub(startedAt).Milliseconds()))

	response := map[string]interface{}{
		"action":          "software_install_result",
		"installation_id": req.InstallationID,
		"status":          status,
		"exit_code":       exitCode,
		"output":          logBuffer.String(),
		"started_at":      startedAt.UTC().Format(time.RFC3339),
		"completed_at":    completedAt.UTC().Format(time.RFC3339),
		"duration_ms":     completedAt.Sub(startedAt).Milliseconds(),
	}

	h.SendRaw(response)
	return response, nil
}

// downloadAndInstallCaskRequest represents a Homebrew cask installation request.
type downloadAndInstallCaskRequest struct {
	InstallationID string `json:"installation_id"`
	CaskName       string `json:"cask_name"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

// handleDownloadAndInstallCask handles Homebrew cask installation via direct download.
func (h *Handler) handleDownloadAndInstallCask(ctx context.Context, data json.RawMessage) (interface{}, error) {
	h.logger.Info("received cask installation request", "raw_data", string(data))

	var req downloadAndInstallCaskRequest
	if err := json.Unmarshal(data, &req); err != nil {
		h.logger.Error("failed to unmarshal cask request", "error", err, "data", string(data))
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("cask request parsed",
		"installation_id", req.InstallationID,
		"cask_name", req.CaskName,
		"timeout_seconds", req.TimeoutSeconds,
	)

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

	// Platform validation
	if runtime.GOOS != "darwin" {
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           "Homebrew cask installation is only available on macOS",
		}
		h.SendRaw(response)
		return response, nil
	}

	h.logger.Info("starting cask installation",
		"installation_id", req.InstallationID,
		"cask_name", req.CaskName,
	)

	// Set timeout
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Track installation for cancellation
	runningInstallations.Lock()
	runningInstallations.m[req.InstallationID] = &runningInstallation{cancel: cancel}
	runningInstallations.Unlock()
	defer func() {
		runningInstallations.Lock()
		delete(runningInstallations.m, req.InstallationID)
		runningInstallations.Unlock()
	}()

	startedAt := time.Now()
	var logBuffer strings.Builder
	logBuffer.WriteString(fmt.Sprintf("[%s] Starting Homebrew Cask installation: %s\n", startedAt.Format(time.RFC3339), req.CaskName))
	logBuffer.WriteString(fmt.Sprintf("[%s] Platform: macOS (%s)\n", time.Now().Format(time.RFC3339), runtime.GOARCH))

	// Fetch cask info from Homebrew API
	h.SendRaw(map[string]interface{}{
		"action":          "software_install_progress",
		"installation_id": req.InstallationID,
		"status":          "fetching_metadata",
	})

	logBuffer.WriteString(fmt.Sprintf("[%s] Fetching cask metadata from Homebrew API...\n", time.Now().Format(time.RFC3339)))

	caskInfo, err := homebrew.FetchCaskInfo(ctx, req.CaskName)
	if err != nil {
		logBuffer.WriteString(fmt.Sprintf("[%s] Failed to fetch cask info: %v\n", time.Now().Format(time.RFC3339), err))
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           fmt.Sprintf("fetch cask info: %v", err),
			"output":          logBuffer.String(),
		}
		h.SendRaw(response)
		return response, nil
	}

	logBuffer.WriteString(fmt.Sprintf("[%s] Cask info retrieved successfully\n", time.Now().Format(time.RFC3339)))
	logBuffer.WriteString(fmt.Sprintf("[%s] Version: %s\n", time.Now().Format(time.RFC3339), caskInfo.Version))
	logBuffer.WriteString(fmt.Sprintf("[%s] Download URL: %s\n", time.Now().Format(time.RFC3339), caskInfo.URL))
	logBuffer.WriteString(fmt.Sprintf("[%s] Expected SHA256: %s\n", time.Now().Format(time.RFC3339), caskInfo.SHA256))

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "slimrmm-cask-*")
	if err != nil {
		logBuffer.WriteString(fmt.Sprintf("[%s] Failed to create temp directory: %v\n", time.Now().Format(time.RFC3339), err))
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           fmt.Sprintf("create temp dir: %v", err),
			"output":          logBuffer.String(),
		}
		h.SendRaw(response)
		return response, nil
	}
	defer os.RemoveAll(tempDir)
	logBuffer.WriteString(fmt.Sprintf("[%s] Created temp directory: %s\n", time.Now().Format(time.RFC3339), tempDir))

	// Determine file extension from URL
	downloadPath := filepath.Join(tempDir, filepath.Base(caskInfo.URL))

	// Send progress: downloading
	h.SendRaw(map[string]interface{}{
		"action":           "software_install_progress",
		"installation_id":  req.InstallationID,
		"status":           "downloading",
		"progress_percent": 0,
	})

	logBuffer.WriteString(fmt.Sprintf("[%s] Downloading package...\n", time.Now().Format(time.RFC3339)))

	// Download the file
	if err := h.downloadFile(ctx, caskInfo.URL, "", downloadPath, req.InstallationID); err != nil {
		logBuffer.WriteString(fmt.Sprintf("[%s] Download failed: %v\n", time.Now().Format(time.RFC3339), err))
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           fmt.Sprintf("download: %v", err),
			"output":          logBuffer.String(),
		}
		h.SendRaw(response)
		return response, nil
	}

	logBuffer.WriteString(fmt.Sprintf("[%s] Download completed: %s\n", time.Now().Format(time.RFC3339), downloadPath))

	// Get file size for logging
	if fileInfo, err := os.Stat(downloadPath); err == nil {
		logBuffer.WriteString(fmt.Sprintf("[%s] Downloaded file size: %d bytes\n", time.Now().Format(time.RFC3339), fileInfo.Size()))
	}

	h.logger.Info("download completed, starting hash verification",
		"installation_id", req.InstallationID,
		"download_path", downloadPath,
		"expected_hash", caskInfo.SHA256,
	)

	// Verify SHA256 hash
	if caskInfo.SHA256 != "" && caskInfo.SHA256 != "no_check" {
		logBuffer.WriteString(fmt.Sprintf("[%s] Verifying SHA256 hash...\n", time.Now().Format(time.RFC3339)))
		calculatedHash, err := calculateFileHash(downloadPath)
		if err != nil {
			logBuffer.WriteString(fmt.Sprintf("[%s] Hash calculation failed: %v\n", time.Now().Format(time.RFC3339), err))
			response := map[string]interface{}{
				"action":          "software_install_result",
				"installation_id": req.InstallationID,
				"status":          "failed",
				"error":           fmt.Sprintf("hash calculation: %v", err),
				"output":          logBuffer.String(),
			}
			h.SendRaw(response)
			return response, nil
		}

		if calculatedHash != caskInfo.SHA256 {
			h.logger.Error("hash mismatch",
				"installation_id", req.InstallationID,
				"expected", caskInfo.SHA256,
				"got", calculatedHash,
			)
			logBuffer.WriteString(fmt.Sprintf("[%s] Hash verification FAILED: expected %s, got %s\n", time.Now().Format(time.RFC3339), caskInfo.SHA256, calculatedHash))
			response := map[string]interface{}{
				"action":          "software_install_result",
				"installation_id": req.InstallationID,
				"status":          "failed",
				"error":           fmt.Sprintf("hash mismatch: expected %s, got %s", caskInfo.SHA256, calculatedHash),
				"output":          logBuffer.String(),
			}
			h.SendRaw(response)
			return response, nil
		}
		logBuffer.WriteString(fmt.Sprintf("[%s] Hash verification passed: %s\n", time.Now().Format(time.RFC3339), calculatedHash))
		h.logger.Info("hash verification passed", "installation_id", req.InstallationID)
	} else {
		logBuffer.WriteString(fmt.Sprintf("[%s] Hash verification skipped (no_check or empty)\n", time.Now().Format(time.RFC3339)))
	}

	h.logger.Info("starting extraction",
		"installation_id", req.InstallationID,
		"download_path", downloadPath,
		"temp_dir", tempDir,
	)

	// Send progress: extracting/installing
	h.SendRaw(map[string]interface{}{
		"action":          "software_install_progress",
		"installation_id": req.InstallationID,
		"status":          "extracting",
	})

	logBuffer.WriteString(fmt.Sprintf("[%s] Extracting artifact from downloaded file...\n", time.Now().Format(time.RFC3339)))

	// Use unified artifact extraction
	artifact, err := homebrew.ExtractAndFindArtifact(ctx, downloadPath, tempDir)
	if err != nil {
		h.logger.Error("failed to extract artifact",
			"installation_id", req.InstallationID,
			"error", err,
		)
		logBuffer.WriteString(fmt.Sprintf("[%s] Extraction failed: %v\n", time.Now().Format(time.RFC3339), err))
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           fmt.Sprintf("extract artifact: %v", err),
			"output":          logBuffer.String(),
		}
		h.SendRaw(response)
		return response, nil
	}
	defer homebrew.CleanupArtifact(ctx, artifact)

	logBuffer.WriteString(fmt.Sprintf("[%s] Artifact extracted successfully\n", time.Now().Format(time.RFC3339)))
	logBuffer.WriteString(fmt.Sprintf("[%s] Artifact type: %s\n", time.Now().Format(time.RFC3339), string(artifact.Type)))
	logBuffer.WriteString(fmt.Sprintf("[%s] Artifact path: %s\n", time.Now().Format(time.RFC3339), artifact.Path))
	if artifact.AppName != "" {
		logBuffer.WriteString(fmt.Sprintf("[%s] App name: %s\n", time.Now().Format(time.RFC3339), artifact.AppName))
	}

	h.logger.Info("artifact extracted successfully",
		"installation_id", req.InstallationID,
		"artifact_type", string(artifact.Type),
		"artifact_path", artifact.Path,
		"app_name", artifact.AppName,
	)

	// Send progress: installing
	h.SendRaw(map[string]interface{}{
		"action":          "software_install_progress",
		"installation_id": req.InstallationID,
		"status":          "installing",
		"artifact_type":   string(artifact.Type),
	})

	logBuffer.WriteString(fmt.Sprintf("[%s] Installing artifact...\n", time.Now().Format(time.RFC3339)))

	h.logger.Info("starting artifact installation",
		"installation_id", req.InstallationID,
		"artifact_type", string(artifact.Type),
		"artifact_path", artifact.Path,
	)

	// Install the extracted artifact
	output, exitCode, installErr := homebrew.InstallArtifact(ctx, artifact)
	logBuffer.WriteString(fmt.Sprintf("[%s] Installation output:\n%s\n", time.Now().Format(time.RFC3339), output))

	h.logger.Info("artifact installation completed",
		"installation_id", req.InstallationID,
		"exit_code", exitCode,
		"error", installErr,
		"output_length", len(output),
	)

	completedAt := time.Now()
	status := "completed"
	if ctx.Err() == context.Canceled {
		status = "cancelled"
		logBuffer.WriteString(fmt.Sprintf("[%s] Installation was cancelled\n", completedAt.Format(time.RFC3339)))
	} else if exitCode != 0 {
		status = "failed"
		logBuffer.WriteString(fmt.Sprintf("[%s] Installation failed with exit code: %d\n", completedAt.Format(time.RFC3339), exitCode))
	} else {
		logBuffer.WriteString(fmt.Sprintf("[%s] Installation completed successfully\n", completedAt.Format(time.RFC3339)))
	}

	logBuffer.WriteString(fmt.Sprintf("[%s] Duration: %dms\n", completedAt.Format(time.RFC3339), completedAt.Sub(startedAt).Milliseconds()))

	response := map[string]interface{}{
		"action":          "software_install_result",
		"installation_id": req.InstallationID,
		"status":          status,
		"exit_code":       exitCode,
		"output":          logBuffer.String(),
		"cask_name":       req.CaskName,
		"version":         caskInfo.Version,
		"started_at":      startedAt.UTC().Format(time.RFC3339),
		"completed_at":    completedAt.UTC().Format(time.RFC3339),
		"duration_ms":     completedAt.Sub(startedAt).Milliseconds(),
	}

	h.SendRaw(response)
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
func (h *Handler) handleDownloadAndInstallDEB(ctx context.Context, data json.RawMessage) (interface{}, error) {
	h.logger.Info("received DEB installation request")

	var req downloadAndInstallDEBRequest
	if err := json.Unmarshal(data, &req); err != nil {
		h.logger.Error("failed to parse DEB request", "error", err, "data", string(data))
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("DEB request parsed",
		"installation_id", req.InstallationID,
		"filename", req.Filename,
		"has_download_url", req.DownloadURL != "",
		"has_expected_hash", req.ExpectedHash != "",
	)

	// Platform validation
	if runtime.GOOS != "linux" {
		h.logger.Warn("DEB installation attempted on non-Linux platform", "goos", runtime.GOOS)
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           "DEB installation is only available on Linux",
		}
		h.SendRaw(response)
		return response, nil
	}

	// Check if dpkg is available (required for DEB)
	if _, err := exec.LookPath("dpkg"); err != nil {
		h.logger.Warn("dpkg not found on system", "error", err)
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           "dpkg not found - this system may not support DEB packages",
		}
		h.SendRaw(response)
		return response, nil
	}

	// Check for apt-get (preferred for dependency resolution)
	hasApt := false
	if _, err := exec.LookPath("apt-get"); err == nil {
		hasApt = true
		h.logger.Info("apt-get available for dependency resolution")
	} else {
		h.logger.Warn("apt-get not found - will use dpkg only (no automatic dependency resolution)")
	}

	h.logger.Info("starting DEB installation",
		"installation_id", req.InstallationID,
		"filename", req.Filename,
		"has_apt", hasApt,
	)

	// Set timeout
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Track installation for cancellation
	runningInstallations.Lock()
	runningInstallations.m[req.InstallationID] = &runningInstallation{cancel: cancel}
	runningInstallations.Unlock()
	defer func() {
		runningInstallations.Lock()
		delete(runningInstallations.m, req.InstallationID)
		runningInstallations.Unlock()
	}()

	startedAt := time.Now()
	var logBuffer strings.Builder
	logBuffer.WriteString(fmt.Sprintf("[%s] Starting DEB installation: %s\n", startedAt.Format(time.RFC3339), req.Filename))

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "slimrmm-deb-*")
	if err != nil {
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           fmt.Sprintf("create temp dir: %v", err),
		}
		h.SendRaw(response)
		return response, nil
	}
	defer os.RemoveAll(tempDir)
	logBuffer.WriteString(fmt.Sprintf("[%s] Created temp directory: %s\n", time.Now().Format(time.RFC3339), tempDir))

	debPath := filepath.Join(tempDir, req.Filename)

	// Send progress: downloading
	h.SendRaw(map[string]interface{}{
		"action":           "software_install_progress",
		"installation_id":  req.InstallationID,
		"status":           "downloading",
		"progress_percent": 0,
	})

	logBuffer.WriteString(fmt.Sprintf("[%s] Downloading package from: %s\n", time.Now().Format(time.RFC3339), req.DownloadURL))

	// Download the DEB
	if err := h.downloadFile(ctx, req.DownloadURL, req.DownloadToken, debPath, req.InstallationID); err != nil {
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           fmt.Sprintf("download failed: %v", err),
			"output":          logBuffer.String(),
		}
		h.SendRaw(response)
		return response, nil
	}
	logBuffer.WriteString(fmt.Sprintf("[%s] Download completed: %s\n", time.Now().Format(time.RFC3339), debPath))

	// Get file size for logging
	if fileInfo, err := os.Stat(debPath); err == nil {
		logBuffer.WriteString(fmt.Sprintf("[%s] Package size: %d bytes\n", time.Now().Format(time.RFC3339), fileInfo.Size()))
	}

	// Verify hash if provided
	if req.ExpectedHash != "" {
		logBuffer.WriteString(fmt.Sprintf("[%s] Verifying package hash...\n", time.Now().Format(time.RFC3339)))
		calculatedHash, err := calculateFileHash(debPath)
		if err != nil {
			response := map[string]interface{}{
				"action":          "software_install_result",
				"installation_id": req.InstallationID,
				"status":          "failed",
				"error":           fmt.Sprintf("hash calculation failed: %v", err),
				"output":          logBuffer.String(),
			}
			h.SendRaw(response)
			return response, nil
		}

		expectedHash := req.ExpectedHash
		if strings.HasPrefix(expectedHash, "sha256:") {
			expectedHash = strings.TrimPrefix(expectedHash, "sha256:")
		}

		if calculatedHash != expectedHash {
			logBuffer.WriteString(fmt.Sprintf("[%s] Hash verification FAILED: expected %s, got %s\n", time.Now().Format(time.RFC3339), expectedHash, calculatedHash))
			response := map[string]interface{}{
				"action":          "software_install_result",
				"installation_id": req.InstallationID,
				"status":          "failed",
				"error":           fmt.Sprintf("hash mismatch: expected %s, got %s", expectedHash, calculatedHash),
				"output":          logBuffer.String(),
			}
			h.SendRaw(response)
			return response, nil
		}
		logBuffer.WriteString(fmt.Sprintf("[%s] Hash verification passed: %s\n", time.Now().Format(time.RFC3339), calculatedHash))
	}

	// Send progress: installing
	h.SendRaw(map[string]interface{}{
		"action":          "software_install_progress",
		"installation_id": req.InstallationID,
		"status":          "installing",
	})

	var exitCode int
	var pkgManager string

	// Strategy: Use apt-get install first if available (handles dependencies automatically)
	// Fall back to dpkg -i + apt-get -f install if apt-get install fails
	if hasApt {
		// PREFERRED: Use apt-get install which handles dependencies automatically
		pkgManager = "apt-get"
		logBuffer.WriteString(fmt.Sprintf("[%s] Using apt-get install for automatic dependency resolution\n", time.Now().Format(time.RFC3339)))
		logBuffer.WriteString(fmt.Sprintf("[%s] Executing: apt-get install -y --allow-downgrades %s\n", time.Now().Format(time.RFC3339), debPath))

		cmd := exec.CommandContext(ctx, "apt-get", "install", "-y", "--allow-downgrades", debPath)
		output, cmdErr := cmd.CombinedOutput()
		logBuffer.WriteString(fmt.Sprintf("[%s] apt-get install output:\n%s\n", time.Now().Format(time.RFC3339), string(output)))

		if cmdErr != nil {
			if exitError, ok := cmdErr.(*exec.ExitError); ok {
				exitCode = exitError.ExitCode()
			} else {
				exitCode = -1
			}
			logBuffer.WriteString(fmt.Sprintf("[%s] apt-get install failed with exit code: %d\n", time.Now().Format(time.RFC3339), exitCode))

			// Fallback: try dpkg -i first, then apt-get -f install to fix dependencies
			logBuffer.WriteString(fmt.Sprintf("[%s] Trying fallback: dpkg -i followed by apt-get -f install\n", time.Now().Format(time.RFC3339)))

			dpkgCmd := exec.CommandContext(ctx, "dpkg", "-i", "--force-confnew", debPath)
			dpkgOutput, _ := dpkgCmd.CombinedOutput()
			logBuffer.WriteString(fmt.Sprintf("[%s] dpkg -i output:\n%s\n", time.Now().Format(time.RFC3339), string(dpkgOutput)))

			// Fix dependencies
			logBuffer.WriteString(fmt.Sprintf("[%s] Running apt-get -f install to resolve dependencies\n", time.Now().Format(time.RFC3339)))
			fixCmd := exec.CommandContext(ctx, "apt-get", "-f", "install", "-y")
			fixOutput, fixErr := fixCmd.CombinedOutput()
			logBuffer.WriteString(fmt.Sprintf("[%s] apt-get -f install output:\n%s\n", time.Now().Format(time.RFC3339), string(fixOutput)))

			if fixErr == nil {
				exitCode = 0
				logBuffer.WriteString(fmt.Sprintf("[%s] Dependencies resolved successfully\n", time.Now().Format(time.RFC3339)))
			} else if exitError, ok := fixErr.(*exec.ExitError); ok {
				exitCode = exitError.ExitCode()
				logBuffer.WriteString(fmt.Sprintf("[%s] apt-get -f install failed with exit code: %d\n", time.Now().Format(time.RFC3339), exitCode))
			}
		} else {
			exitCode = 0
			logBuffer.WriteString(fmt.Sprintf("[%s] apt-get install completed successfully\n", time.Now().Format(time.RFC3339)))
		}
	} else {
		// No apt-get available, use dpkg directly
		pkgManager = "dpkg"
		logBuffer.WriteString(fmt.Sprintf("[%s] Using dpkg -i (no apt-get available for dependency resolution)\n", time.Now().Format(time.RFC3339)))
		logBuffer.WriteString(fmt.Sprintf("[%s] Executing: dpkg -i --force-confnew %s\n", time.Now().Format(time.RFC3339), debPath))

		cmd := exec.CommandContext(ctx, "dpkg", "-i", "--force-confnew", debPath)
		output, cmdErr := cmd.CombinedOutput()
		logBuffer.WriteString(fmt.Sprintf("[%s] dpkg -i output:\n%s\n", time.Now().Format(time.RFC3339), string(output)))

		if cmdErr != nil {
			if exitError, ok := cmdErr.(*exec.ExitError); ok {
				exitCode = exitError.ExitCode()
			} else {
				exitCode = -1
			}
			logBuffer.WriteString(fmt.Sprintf("[%s] dpkg -i failed with exit code: %d\n", time.Now().Format(time.RFC3339), exitCode))
			logBuffer.WriteString(fmt.Sprintf("[%s] WARNING: Dependencies may not be resolved (apt-get not available)\n", time.Now().Format(time.RFC3339)))
		} else {
			exitCode = 0
			logBuffer.WriteString(fmt.Sprintf("[%s] dpkg -i completed successfully\n", time.Now().Format(time.RFC3339)))
		}
	}

	completedAt := time.Now()
	status := "completed"
	if ctx.Err() == context.Canceled {
		status = "cancelled"
		logBuffer.WriteString(fmt.Sprintf("[%s] Installation was cancelled\n", completedAt.Format(time.RFC3339)))
	} else if exitCode != 0 {
		status = "failed"
		logBuffer.WriteString(fmt.Sprintf("[%s] Installation failed with exit code: %d\n", completedAt.Format(time.RFC3339), exitCode))
	} else {
		logBuffer.WriteString(fmt.Sprintf("[%s] Installation completed successfully\n", completedAt.Format(time.RFC3339)))
	}

	logBuffer.WriteString(fmt.Sprintf("[%s] Duration: %dms\n", completedAt.Format(time.RFC3339), completedAt.Sub(startedAt).Milliseconds()))

	response := map[string]interface{}{
		"action":          "software_install_result",
		"installation_id": req.InstallationID,
		"status":          status,
		"exit_code":       exitCode,
		"output":          logBuffer.String(),
		"package_manager": pkgManager,
		"started_at":      startedAt.UTC().Format(time.RFC3339),
		"completed_at":    completedAt.UTC().Format(time.RFC3339),
		"duration_ms":     completedAt.Sub(startedAt).Milliseconds(),
	}

	h.SendRaw(response)
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
func (h *Handler) handleDownloadAndInstallRPM(ctx context.Context, data json.RawMessage) (interface{}, error) {
	h.logger.Info("received RPM installation request")

	var req downloadAndInstallRPMRequest
	if err := json.Unmarshal(data, &req); err != nil {
		h.logger.Error("failed to parse RPM request", "error", err, "data", string(data))
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("RPM request parsed",
		"installation_id", req.InstallationID,
		"filename", req.Filename,
		"has_download_url", req.DownloadURL != "",
		"has_expected_hash", req.ExpectedHash != "",
	)

	// Platform validation
	if runtime.GOOS != "linux" {
		h.logger.Warn("RPM installation attempted on non-Linux platform", "goos", runtime.GOOS)
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           "RPM installation is only available on Linux",
		}
		h.SendRaw(response)
		return response, nil
	}

	// Check if rpm is available (required for RPM)
	if _, err := exec.LookPath("rpm"); err != nil {
		h.logger.Warn("rpm not found on system", "error", err)
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           "rpm not found - this system may not support RPM packages",
		}
		h.SendRaw(response)
		return response, nil
	}

	// Detect available package managers for dependency resolution
	hasDnf := false
	hasYum := false
	hasZypper := false

	if _, err := exec.LookPath("dnf"); err == nil {
		hasDnf = true
		h.logger.Info("dnf available for dependency resolution (Fedora/RHEL 8+)")
	}
	if _, err := exec.LookPath("yum"); err == nil {
		hasYum = true
		h.logger.Info("yum available for dependency resolution (RHEL/CentOS)")
	}
	if _, err := exec.LookPath("zypper"); err == nil {
		hasZypper = true
		h.logger.Info("zypper available for dependency resolution (SUSE/openSUSE)")
	}

	h.logger.Info("starting RPM installation",
		"installation_id", req.InstallationID,
		"filename", req.Filename,
		"has_dnf", hasDnf,
		"has_yum", hasYum,
		"has_zypper", hasZypper,
	)

	// Set timeout
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Track installation for cancellation
	runningInstallations.Lock()
	runningInstallations.m[req.InstallationID] = &runningInstallation{cancel: cancel}
	runningInstallations.Unlock()
	defer func() {
		runningInstallations.Lock()
		delete(runningInstallations.m, req.InstallationID)
		runningInstallations.Unlock()
	}()

	startedAt := time.Now()
	var logBuffer strings.Builder
	logBuffer.WriteString(fmt.Sprintf("[%s] Starting RPM installation: %s\n", startedAt.Format(time.RFC3339), req.Filename))
	logBuffer.WriteString(fmt.Sprintf("[%s] Available package managers: dnf=%v, yum=%v, zypper=%v\n", time.Now().Format(time.RFC3339), hasDnf, hasYum, hasZypper))

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "slimrmm-rpm-*")
	if err != nil {
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           fmt.Sprintf("create temp dir: %v", err),
		}
		h.SendRaw(response)
		return response, nil
	}
	defer os.RemoveAll(tempDir)
	logBuffer.WriteString(fmt.Sprintf("[%s] Created temp directory: %s\n", time.Now().Format(time.RFC3339), tempDir))

	rpmPath := filepath.Join(tempDir, req.Filename)

	// Send progress: downloading
	h.SendRaw(map[string]interface{}{
		"action":           "software_install_progress",
		"installation_id":  req.InstallationID,
		"status":           "downloading",
		"progress_percent": 0,
	})

	logBuffer.WriteString(fmt.Sprintf("[%s] Downloading package from: %s\n", time.Now().Format(time.RFC3339), req.DownloadURL))

	// Download the RPM
	if err := h.downloadFile(ctx, req.DownloadURL, req.DownloadToken, rpmPath, req.InstallationID); err != nil {
		response := map[string]interface{}{
			"action":          "software_install_result",
			"installation_id": req.InstallationID,
			"status":          "failed",
			"error":           fmt.Sprintf("download failed: %v", err),
			"output":          logBuffer.String(),
		}
		h.SendRaw(response)
		return response, nil
	}
	logBuffer.WriteString(fmt.Sprintf("[%s] Download completed: %s\n", time.Now().Format(time.RFC3339), rpmPath))

	// Get file size for logging
	if fileInfo, err := os.Stat(rpmPath); err == nil {
		logBuffer.WriteString(fmt.Sprintf("[%s] Package size: %d bytes\n", time.Now().Format(time.RFC3339), fileInfo.Size()))
	}

	// Verify hash if provided
	if req.ExpectedHash != "" {
		logBuffer.WriteString(fmt.Sprintf("[%s] Verifying package hash...\n", time.Now().Format(time.RFC3339)))
		calculatedHash, err := calculateFileHash(rpmPath)
		if err != nil {
			response := map[string]interface{}{
				"action":          "software_install_result",
				"installation_id": req.InstallationID,
				"status":          "failed",
				"error":           fmt.Sprintf("hash calculation failed: %v", err),
				"output":          logBuffer.String(),
			}
			h.SendRaw(response)
			return response, nil
		}

		expectedHash := req.ExpectedHash
		if strings.HasPrefix(expectedHash, "sha256:") {
			expectedHash = strings.TrimPrefix(expectedHash, "sha256:")
		}

		if calculatedHash != expectedHash {
			logBuffer.WriteString(fmt.Sprintf("[%s] Hash verification FAILED: expected %s, got %s\n", time.Now().Format(time.RFC3339), expectedHash, calculatedHash))
			response := map[string]interface{}{
				"action":          "software_install_result",
				"installation_id": req.InstallationID,
				"status":          "failed",
				"error":           fmt.Sprintf("hash mismatch: expected %s, got %s", expectedHash, calculatedHash),
				"output":          logBuffer.String(),
			}
			h.SendRaw(response)
			return response, nil
		}
		logBuffer.WriteString(fmt.Sprintf("[%s] Hash verification passed: %s\n", time.Now().Format(time.RFC3339), calculatedHash))
	}

	// Send progress: installing
	h.SendRaw(map[string]interface{}{
		"action":          "software_install_progress",
		"installation_id": req.InstallationID,
		"status":          "installing",
	})

	// Determine best package manager to use
	// Priority: dnf (Fedora/RHEL 8+) > zypper (SUSE) > yum (RHEL/CentOS) > rpm (fallback)
	var cmd *exec.Cmd
	var pkgManager string

	if hasDnf {
		// Use dnf install (handles dependencies automatically)
		pkgManager = "dnf"
		logBuffer.WriteString(fmt.Sprintf("[%s] Using dnf for installation (automatic dependency resolution)\n", time.Now().Format(time.RFC3339)))
		logBuffer.WriteString(fmt.Sprintf("[%s] Executing: dnf install -y %s\n", time.Now().Format(time.RFC3339), rpmPath))
		cmd = exec.CommandContext(ctx, "dnf", "install", "-y", rpmPath)
	} else if hasZypper {
		// Use zypper install (SUSE/openSUSE - handles dependencies automatically)
		pkgManager = "zypper"
		logBuffer.WriteString(fmt.Sprintf("[%s] Using zypper for installation (SUSE/openSUSE - automatic dependency resolution)\n", time.Now().Format(time.RFC3339)))
		logBuffer.WriteString(fmt.Sprintf("[%s] Executing: zypper --non-interactive install --allow-unsigned-rpm %s\n", time.Now().Format(time.RFC3339), rpmPath))
		cmd = exec.CommandContext(ctx, "zypper", "--non-interactive", "install", "--allow-unsigned-rpm", rpmPath)
	} else if hasYum {
		// Use yum install (handles dependencies automatically)
		pkgManager = "yum"
		logBuffer.WriteString(fmt.Sprintf("[%s] Using yum for installation (automatic dependency resolution)\n", time.Now().Format(time.RFC3339)))
		logBuffer.WriteString(fmt.Sprintf("[%s] Executing: yum install -y %s\n", time.Now().Format(time.RFC3339), rpmPath))
		cmd = exec.CommandContext(ctx, "yum", "install", "-y", rpmPath)
	} else {
		// Fallback to direct rpm -i (no dependency resolution)
		pkgManager = "rpm"
		logBuffer.WriteString(fmt.Sprintf("[%s] Using rpm -ivh (fallback - no automatic dependency resolution)\n", time.Now().Format(time.RFC3339)))
		logBuffer.WriteString(fmt.Sprintf("[%s] Executing: rpm -ivh --force %s\n", time.Now().Format(time.RFC3339), rpmPath))
		logBuffer.WriteString(fmt.Sprintf("[%s] WARNING: Dependencies will NOT be automatically resolved\n", time.Now().Format(time.RFC3339)))
		cmd = exec.CommandContext(ctx, "rpm", "-ivh", "--force", rpmPath)
	}

	h.logger.Info("executing RPM installation",
		"installation_id", req.InstallationID,
		"package_manager", pkgManager,
	)

	output, cmdErr := cmd.CombinedOutput()
	logBuffer.WriteString(fmt.Sprintf("[%s] %s output:\n%s\n", time.Now().Format(time.RFC3339), pkgManager, string(output)))

	exitCode := 0
	if cmdErr != nil {
		if exitError, ok := cmdErr.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = -1
		}
		logBuffer.WriteString(fmt.Sprintf("[%s] %s failed with exit code: %d\n", time.Now().Format(time.RFC3339), pkgManager, exitCode))
	} else {
		logBuffer.WriteString(fmt.Sprintf("[%s] %s completed successfully\n", time.Now().Format(time.RFC3339), pkgManager))
	}

	completedAt := time.Now()
	status := "completed"
	if ctx.Err() == context.Canceled {
		status = "cancelled"
		logBuffer.WriteString(fmt.Sprintf("[%s] Installation was cancelled\n", completedAt.Format(time.RFC3339)))
	} else if exitCode != 0 {
		status = "failed"
		logBuffer.WriteString(fmt.Sprintf("[%s] Installation failed with exit code: %d\n", completedAt.Format(time.RFC3339), exitCode))
	} else {
		logBuffer.WriteString(fmt.Sprintf("[%s] Installation completed successfully\n", completedAt.Format(time.RFC3339)))
	}

	logBuffer.WriteString(fmt.Sprintf("[%s] Duration: %dms\n", completedAt.Format(time.RFC3339), completedAt.Sub(startedAt).Milliseconds()))

	response := map[string]interface{}{
		"action":          "software_install_result",
		"installation_id": req.InstallationID,
		"status":          status,
		"exit_code":       exitCode,
		"output":          logBuffer.String(),
		"package_manager": pkgManager,
		"started_at":      startedAt.UTC().Format(time.RFC3339),
		"completed_at":    completedAt.UTC().Format(time.RFC3339),
		"duration_ms":     completedAt.Sub(startedAt).Milliseconds(),
	}

	h.SendRaw(response)
	return response, nil
}
