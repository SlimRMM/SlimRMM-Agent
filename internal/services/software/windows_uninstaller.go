// Package software provides software installation and uninstallation services.
//go:build windows

package software

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/services/models"
)

// WingetUninstaller implements PlatformUninstaller for Winget on Windows.
type WingetUninstaller struct {
	logger *slog.Logger
}

// NewWingetUninstaller creates a new Winget uninstaller.
func NewWingetUninstaller(logger *slog.Logger) *WingetUninstaller {
	return &WingetUninstaller{logger: logger}
}

// CanHandle returns true if this uninstaller can handle Winget uninstallations.
func (u *WingetUninstaller) CanHandle(installationType models.InstallationType) bool {
	return installationType == models.InstallationTypeWinget
}

// IsAvailable returns true if Winget is available.
func (u *WingetUninstaller) IsAvailable() bool {
	_, err := exec.LookPath("winget")
	return err == nil
}

// Uninstall performs a Winget uninstallation.
func (u *WingetUninstaller) Uninstall(ctx context.Context, req *models.UninstallRequest) (*models.UninstallResult, error) {
	startedAt := time.Now()

	if req.PackageID == "" {
		return &models.UninstallResult{
			UninstallationID: req.UninstallationID,
			Status:           models.UninstallStatusFailed,
			Error:            "package_id is required for Winget uninstallation",
			StartedAt:        startedAt,
			CompletedAt:      time.Now(),
		}, nil
	}

	u.logger.Info("uninstalling via winget",
		"uninstallation_id", req.UninstallationID,
		"package_id", req.PackageID,
	)

	// Execute winget uninstall
	args := []string{"uninstall", "--id", req.PackageID, "--silent", "--accept-source-agreements"}
	cmd := exec.CommandContext(ctx, "winget", args...)
	output, err := cmd.CombinedOutput()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	status := models.UninstallStatusCompleted
	var errMsg string
	if exitCode != 0 {
		status = models.UninstallStatusFailed
		errMsg = fmt.Sprintf("winget uninstall failed with exit code %d", exitCode)
	}

	return &models.UninstallResult{
		UninstallationID: req.UninstallationID,
		Status:           status,
		ExitCode:         exitCode,
		Output:           string(output),
		Error:            errMsg,
		StartedAt:        startedAt,
		CompletedAt:      time.Now(),
	}, nil
}

// Cleanup performs post-uninstall cleanup for Winget packages.
func (u *WingetUninstaller) Cleanup(ctx context.Context, req *models.UninstallRequest) (*models.CleanupResults, error) {
	results := &models.CleanupResults{
		PathsRemoved: []string{},
		PathsFailed:  []string{},
	}

	if req.PackageName == "" && req.PackageID == "" {
		return results, nil
	}

	appName := req.PackageName
	if appName == "" {
		appName = req.PackageID
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
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			if err := os.RemoveAll(path); err != nil {
				results.PathsFailed = append(results.PathsFailed, path)
			} else {
				results.PathsRemoved = append(results.PathsRemoved, path)
			}
		}
	}

	return results, nil
}

// MSIUninstaller implements PlatformUninstaller for MSI packages on Windows.
type MSIUninstaller struct {
	logger *slog.Logger
}

// NewMSIUninstaller creates a new MSI uninstaller.
func NewMSIUninstaller(logger *slog.Logger) *MSIUninstaller {
	return &MSIUninstaller{logger: logger}
}

// CanHandle returns true if this uninstaller can handle MSI uninstallations.
func (u *MSIUninstaller) CanHandle(installationType models.InstallationType) bool {
	return installationType == models.InstallationTypeMSI
}

// IsAvailable returns true (msiexec is always available on Windows).
func (u *MSIUninstaller) IsAvailable() bool {
	return true
}

// Uninstall performs an MSI uninstallation.
func (u *MSIUninstaller) Uninstall(ctx context.Context, req *models.UninstallRequest) (*models.UninstallResult, error) {
	startedAt := time.Now()

	productCode := req.ProductCode
	if productCode == "" {
		return &models.UninstallResult{
			UninstallationID: req.UninstallationID,
			Status:           models.UninstallStatusFailed,
			Error:            "product_code is required for MSI uninstallation",
			StartedAt:        startedAt,
			CompletedAt:      time.Now(),
		}, nil
	}

	// Validate product code format (should be a GUID)
	if !strings.HasPrefix(productCode, "{") || !strings.HasSuffix(productCode, "}") {
		return &models.UninstallResult{
			UninstallationID: req.UninstallationID,
			Status:           models.UninstallStatusFailed,
			Error:            "invalid MSI product code format, expected GUID like {12345678-...}",
			StartedAt:        startedAt,
			CompletedAt:      time.Now(),
		}, nil
	}

	u.logger.Info("uninstalling MSI package",
		"uninstallation_id", req.UninstallationID,
		"product_code", productCode,
	)

	// Execute msiexec /x
	args := []string{"/x", productCode, "/qn", "/norestart"}
	cmd := exec.CommandContext(ctx, "msiexec", args...)
	output, err := cmd.CombinedOutput()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	status := models.UninstallStatusCompleted
	var errMsg string
	if exitCode != 0 && exitCode != 3010 { // 3010 = reboot required
		status = models.UninstallStatusFailed
		errMsg = fmt.Sprintf("msiexec uninstall failed with exit code %d", exitCode)
	}

	return &models.UninstallResult{
		UninstallationID: req.UninstallationID,
		Status:           status,
		ExitCode:         exitCode,
		Output:           string(output),
		Error:            errMsg,
		StartedAt:        startedAt,
		CompletedAt:      time.Now(),
	}, nil
}

// Cleanup performs post-uninstall cleanup for MSI packages.
func (u *MSIUninstaller) Cleanup(ctx context.Context, req *models.UninstallRequest) (*models.CleanupResults, error) {
	results := &models.CleanupResults{
		PathsRemoved: []string{},
		PathsFailed:  []string{},
	}

	// Clean up custom paths if provided
	for _, path := range req.CleanupPaths {
		if path == "" {
			continue
		}
		if !isPathSafe(path) {
			u.logger.Warn("skipping unsafe cleanup path", "path", path)
			continue
		}
		if _, err := os.Stat(path); err == nil {
			if err := os.RemoveAll(path); err != nil {
				results.PathsFailed = append(results.PathsFailed, path)
			} else {
				results.PathsRemoved = append(results.PathsRemoved, path)
			}
		}
	}

	return results, nil
}

// isPathSafe checks if a path is safe to delete.
func isPathSafe(path string) bool {
	protectedPaths := []string{
		`C:\Windows`,
		`C:\Program Files\WindowsApps`,
		`C:\ProgramData\Microsoft`,
	}

	normalizedPath := strings.ToLower(filepath.Clean(path))
	for _, protected := range protectedPaths {
		if strings.HasPrefix(normalizedPath, strings.ToLower(protected)) {
			return false
		}
	}

	return true
}
