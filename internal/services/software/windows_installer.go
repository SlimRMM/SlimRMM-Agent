// Package software provides software installation and uninstallation services.
//go:build windows

package software

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/services/models"
	"github.com/slimrmm/slimrmm-agent/internal/winget"
)

// WingetInstaller implements PlatformInstaller for Winget on Windows.
type WingetInstaller struct {
	logger *slog.Logger
}

// NewWingetInstaller creates a new Winget installer.
func NewWingetInstaller(logger *slog.Logger) *WingetInstaller {
	return &WingetInstaller{logger: logger}
}

// CanHandle returns true if this installer can handle Winget installations.
func (i *WingetInstaller) CanHandle(installationType models.InstallationType) bool {
	return installationType == models.InstallationTypeWinget
}

// IsAvailable returns true if Winget is available.
func (i *WingetInstaller) IsAvailable() bool {
	client := winget.GetDefault()
	return client.IsAvailable()
}

// Install performs a Winget installation.
func (i *WingetInstaller) Install(ctx context.Context, req *models.InstallRequest) (*models.InstallResult, error) {
	startedAt := time.Now()

	// Validate package ID
	if !winget.IsValidPackageID(req.PackageID) {
		return &models.InstallResult{
			InstallationID: req.InstallationID,
			Status:         models.StatusFailed,
			Error:          fmt.Sprintf("invalid winget package ID: %s", req.PackageID),
			StartedAt:      startedAt,
			CompletedAt:    time.Now(),
		}, nil
	}

	i.logger.Info("installing via winget",
		"installation_id", req.InstallationID,
		"package_id", req.PackageID,
	)

	// Execute winget installation
	output, exitCode := runWingetInstall(ctx, req.PackageID, req.Silent, i.logger)

	status := models.StatusCompleted
	var errMsg string
	if exitCode != 0 {
		status = models.StatusFailed
		errMsg = fmt.Sprintf("winget install failed with exit code %d", exitCode)
	}

	return &models.InstallResult{
		InstallationID: req.InstallationID,
		Status:         status,
		ExitCode:       exitCode,
		Output:         output,
		Error:          errMsg,
		StartedAt:      startedAt,
		CompletedAt:    time.Now(),
	}, nil
}

// MSIInstaller implements PlatformInstaller for MSI packages on Windows.
type MSIInstaller struct {
	logger *slog.Logger
}

// NewMSIInstaller creates a new MSI installer.
func NewMSIInstaller(logger *slog.Logger) *MSIInstaller {
	return &MSIInstaller{logger: logger}
}

// CanHandle returns true if this installer can handle MSI installations.
func (i *MSIInstaller) CanHandle(installationType models.InstallationType) bool {
	return installationType == models.InstallationTypeMSI
}

// IsAvailable returns true (MSI is always available on Windows).
func (i *MSIInstaller) IsAvailable() bool {
	return true
}

// Install performs an MSI installation.
func (i *MSIInstaller) Install(ctx context.Context, req *models.InstallRequest) (*models.InstallResult, error) {
	startedAt := time.Now()

	if req.DownloadURL == "" {
		return &models.InstallResult{
			InstallationID: req.InstallationID,
			Status:         models.StatusFailed,
			Error:          "download_url is required for MSI installation",
			StartedAt:      startedAt,
			CompletedAt:    time.Now(),
		}, nil
	}

	i.logger.Info("downloading and installing MSI",
		"installation_id", req.InstallationID,
		"filename", req.Filename,
	)

	// Download the MSI file
	tempDir := os.TempDir()
	msiPath := filepath.Join(tempDir, req.Filename)

	if err := downloadFile(ctx, req.DownloadURL, req.DownloadToken, msiPath, i.logger); err != nil {
		return &models.InstallResult{
			InstallationID: req.InstallationID,
			Status:         models.StatusFailed,
			Error:          fmt.Sprintf("download failed: %v", err),
			StartedAt:      startedAt,
			CompletedAt:    time.Now(),
		}, nil
	}
	defer os.Remove(msiPath)

	// Verify hash if provided
	if req.ExpectedHash != "" {
		actualHash, err := calculateFileHash(msiPath)
		if err != nil {
			return &models.InstallResult{
				InstallationID: req.InstallationID,
				Status:         models.StatusFailed,
				Error:          fmt.Sprintf("hash calculation failed: %v", err),
				StartedAt:      startedAt,
				CompletedAt:    time.Now(),
			}, nil
		}

		if !strings.EqualFold(actualHash, req.ExpectedHash) {
			return &models.InstallResult{
				InstallationID: req.InstallationID,
				Status:         models.StatusFailed,
				Error:          fmt.Sprintf("hash mismatch: expected %s, got %s", req.ExpectedHash, actualHash),
				StartedAt:      startedAt,
				CompletedAt:    time.Now(),
			}, nil
		}
	}

	// Build msiexec arguments
	args := []string{"/i", msiPath}
	if req.Silent {
		args = append(args, "/quiet", "/norestart")
	}
	if req.SilentArgs != "" {
		// Parse additional arguments, avoiding duplicate /i flag
		extraArgs := strings.Fields(req.SilentArgs)
		for _, arg := range extraArgs {
			if strings.ToLower(arg) != "/i" {
				args = append(args, arg)
			}
		}
	}

	i.logger.Info("executing msiexec",
		"installation_id", req.InstallationID,
		"args", args,
	)

	// Execute msiexec
	cmd := exec.CommandContext(ctx, "msiexec.exe", args...)
	output, err := cmd.CombinedOutput()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	status := models.StatusCompleted
	var errMsg string
	if exitCode != 0 && exitCode != 3010 { // 3010 = reboot required, still success
		status = models.StatusFailed
		errMsg = fmt.Sprintf("msiexec failed with exit code %d", exitCode)
	}

	return &models.InstallResult{
		InstallationID: req.InstallationID,
		Status:         status,
		ExitCode:       exitCode,
		Output:         string(output),
		Error:          errMsg,
		StartedAt:      startedAt,
		CompletedAt:    time.Now(),
	}, nil
}

// runWingetInstall executes winget install and returns output and exit code.
func runWingetInstall(ctx context.Context, packageID string, silent bool, logger *slog.Logger) (string, int) {
	// Try multiple execution methods for hardened systems
	methods := []struct {
		name string
		fn   func(context.Context, string, bool, *slog.Logger) (string, int, error)
	}{
		{"WinGet.Client module", tryWinGetClientModule},
		{"direct path", tryDirectPath},
		{"scheduled task", tryScheduledTask},
	}

	for _, method := range methods {
		logger.Debug("trying winget install method", "method", method.name)
		output, exitCode, err := method.fn(ctx, packageID, silent, logger)
		if err == nil {
			return output, exitCode
		}
		logger.Debug("winget install method failed", "method", method.name, "error", err)
	}

	return "all winget execution methods failed", -1
}

// tryWinGetClientModule uses Microsoft.WinGet.Client PowerShell module.
func tryWinGetClientModule(ctx context.Context, packageID string, silent bool, logger *slog.Logger) (string, int, error) {
	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.WinGet.Client -ErrorAction Stop
Install-WinGetPackage -Id '%s' -Mode Silent -Scope System -Force
`, packageID)

	cmd := exec.CommandContext(ctx, "pwsh", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return string(output), exitErr.ExitCode(), nil
		}
		return string(output), -1, err
	}
	return string(output), 0, nil
}

// tryDirectPath uses direct winget.exe invocation.
func tryDirectPath(ctx context.Context, packageID string, silent bool, logger *slog.Logger) (string, int, error) {
	client := winget.GetDefault()
	binaryPath := client.GetBinaryPath()
	if binaryPath == "" {
		return "", -1, fmt.Errorf("winget binary not found")
	}

	args := []string{"install", "--id", packageID, "--scope", "machine", "--accept-package-agreements", "--accept-source-agreements"}
	if silent {
		args = append(args, "--silent")
	}

	cmd := exec.CommandContext(ctx, binaryPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return string(output), exitErr.ExitCode(), nil
		}
		return string(output), -1, err
	}
	return string(output), 0, nil
}

// tryScheduledTask uses a scheduled task for elevation.
func tryScheduledTask(ctx context.Context, packageID string, silent bool, logger *slog.Logger) (string, int, error) {
	// Create a temporary script
	tempDir := os.TempDir()
	scriptPath := filepath.Join(tempDir, fmt.Sprintf("winget_install_%d.ps1", time.Now().UnixNano()))
	outputPath := filepath.Join(tempDir, fmt.Sprintf("winget_output_%d.txt", time.Now().UnixNano()))

	scriptContent := fmt.Sprintf(`
$ErrorActionPreference = 'Continue'
$output = winget install --id '%s' --scope machine --accept-package-agreements --accept-source-agreements%s 2>&1
$output | Out-File -FilePath '%s' -Encoding UTF8
exit $LASTEXITCODE
`, packageID, func() string {
		if silent {
			return " --silent"
		}
		return ""
	}(), outputPath)

	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0600); err != nil {
		return "", -1, err
	}
	defer os.Remove(scriptPath)
	defer os.Remove(outputPath)

	// Create and run scheduled task
	taskName := fmt.Sprintf("WinGetInstall_%d", time.Now().UnixNano())

	createCmd := exec.CommandContext(ctx, "schtasks", "/create",
		"/tn", taskName,
		"/tr", fmt.Sprintf("powershell -ExecutionPolicy Bypass -File %s", scriptPath),
		"/sc", "once",
		"/st", "00:00",
		"/ru", "SYSTEM",
		"/f",
	)
	if _, err := createCmd.CombinedOutput(); err != nil {
		return "", -1, err
	}

	// Run the task
	runCmd := exec.CommandContext(ctx, "schtasks", "/run", "/tn", taskName)
	if _, err := runCmd.CombinedOutput(); err != nil {
		exec.Command("schtasks", "/delete", "/tn", taskName, "/f").Run()
		return "", -1, err
	}

	// Wait for completion
	time.Sleep(2 * time.Second)
	for i := 0; i < 60; i++ {
		select {
		case <-ctx.Done():
			exec.Command("schtasks", "/delete", "/tn", taskName, "/f").Run()
			return "", -1, ctx.Err()
		default:
		}

		queryCmd := exec.CommandContext(ctx, "schtasks", "/query", "/tn", taskName, "/fo", "csv", "/v")
		queryOutput, _ := queryCmd.CombinedOutput()
		if strings.Contains(string(queryOutput), "Ready") {
			break
		}
		time.Sleep(5 * time.Second)
	}

	// Delete the task
	exec.Command("schtasks", "/delete", "/tn", taskName, "/f").Run()

	// Read output
	outputBytes, err := os.ReadFile(outputPath)
	if err != nil {
		return "", -1, err
	}

	return string(outputBytes), 0, nil
}

// downloadFile downloads a file from URL with optional authentication.
func downloadFile(ctx context.Context, url, token, destPath string, logger *slog.Logger) error {
	logger.Info("downloading file", "url", url, "dest", destPath)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
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
