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
// Always uses machine scope and runs in SYSTEM context with direct path execution.
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
		"package_id", req.WingetPackageID,
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

	startedAt := time.Now()

	// Send progress update - always machine scope
	h.SendRaw(map[string]interface{}{
		"action":          "software_install_progress",
		"installation_id": req.InstallationID,
		"status":          "installing",
		"output":          fmt.Sprintf("Installing %s (machine scope)...\n", req.WingetPackageID),
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

	// Execute via direct path method with fallbacks for hardened systems
	// NO HELPER NEEDED - runs directly in SYSTEM context with proper DLL loading
	output, exitCode := runWingetOperation(ctx, req.WingetPackageID, req.Silent, "install", h.logger)

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
		"context":         "system-direct",
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
	taskName := fmt.Sprintf("SlimRMM_WingetInstall_%d", time.Now().UnixNano())
	scriptPath := filepath.Join(os.TempDir(), taskName+".ps1")
	outputPath := filepath.Join(os.TempDir(), taskName+"_output.txt")
	exitCodePath := filepath.Join(os.TempDir(), taskName+"_exitcode.txt")

	if logger != nil {
		logger.Info("creating scheduled task for winget execution", "task_name", taskName)
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

	if err := os.WriteFile(scriptPath, []byte(wrappedScript), 0644); err != nil {
		return fmt.Sprintf("failed to write script file: %v", err), -1
	}
	defer os.Remove(scriptPath)
	defer os.Remove(outputPath)
	defer os.Remove(exitCodePath)

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
	// Track if installation succeeded - only cleanup on success
	installSuccess := false
	defer func() {
		if installSuccess {
			os.RemoveAll(tempDir)
		} else {
			h.logger.Info("keeping temp directory for debugging", "path", tempDir)
		}
	}()

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

		// Normalize hash format for comparison
		// Backend sends "sha256:{hash}", we calculate just "{hash}"
		expectedHash := req.ExpectedHash
		if strings.HasPrefix(expectedHash, "sha256:") {
			expectedHash = strings.TrimPrefix(expectedHash, "sha256:")
		}

		h.logger.Info("verifying MSI hash",
			"installation_id", req.InstallationID,
			"expected", expectedHash,
			"calculated", calculatedHash,
		)

		if calculatedHash != expectedHash {
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

	// Sanitize silentArgs - remove /i flag if present (we add it ourselves)
	silentArgs = sanitizeMsiArgs(silentArgs)

	args := []string{"/i", msiPath}
	args = append(args, parseArgs(silentArgs)...)
	args = append(args, "/log", logPath)

	h.logger.Info("starting msiexec",
		"installation_id", req.InstallationID,
		"command", "msiexec",
		"args", strings.Join(args, " "),
		"log_path", logPath,
	)

	cmd := exec.CommandContext(ctx, "msiexec", args...)
	outputBytes, err := cmd.CombinedOutput()
	output := string(outputBytes)

	h.logger.Info("msiexec finished",
		"installation_id", req.InstallationID,
		"error", err,
		"output_len", len(output),
	)

	// Read log file if it exists
	var logContent string
	if logBytes, readErr := os.ReadFile(logPath); readErr == nil {
		logContent = string(logBytes)
		h.logger.Info("MSI log file read", "installation_id", req.InstallationID, "log_size", len(logContent))
	} else {
		h.logger.Info("MSI log file not found or unreadable", "installation_id", req.InstallationID, "error", readErr)
	}

	// Determine exit code and status
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
	if ctx.Err() == context.DeadlineExceeded {
		status = "failed"
		output = fmt.Sprintf("Installation timed out after %d seconds. Check %s for details.", req.TimeoutSeconds, tempDir)
		h.logger.Info("MSI installation timed out", "installation_id", req.InstallationID, "temp_dir", tempDir)
	} else if ctx.Err() == context.Canceled {
		status = "cancelled"
		output = "Installation cancelled by user request"
	} else if exitCode != 0 && exitCode != 3010 {
		status = "failed"
	} else {
		installSuccess = true
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
