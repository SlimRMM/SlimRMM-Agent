// Package software provides software installation and uninstallation services.
//go:build linux

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

// DEBUninstaller implements PlatformUninstaller for DEB packages on Linux.
type DEBUninstaller struct {
	logger *slog.Logger
}

// NewDEBUninstaller creates a new DEB uninstaller.
func NewDEBUninstaller(logger *slog.Logger) *DEBUninstaller {
	return &DEBUninstaller{logger: logger}
}

// CanHandle returns true if this uninstaller can handle DEB uninstallations.
func (u *DEBUninstaller) CanHandle(installationType models.InstallationType) bool {
	return installationType == models.InstallationTypeDEB
}

// IsAvailable returns true if dpkg is available.
func (u *DEBUninstaller) IsAvailable() bool {
	_, err := exec.LookPath("dpkg")
	return err == nil
}

// Uninstall performs a DEB package uninstallation.
func (u *DEBUninstaller) Uninstall(ctx context.Context, req *models.UninstallRequest) (*models.UninstallResult, error) {
	startedAt := time.Now()

	packageName := req.DebPackageName
	if packageName == "" {
		packageName = req.PackageID
	}

	if packageName == "" {
		return &models.UninstallResult{
			UninstallationID: req.UninstallationID,
			Status:           models.UninstallStatusFailed,
			Error:            "deb_package_name or package_id is required for DEB uninstallation",
			StartedAt:        startedAt,
			CompletedAt:      time.Now(),
		}, nil
	}

	u.logger.Info("uninstalling DEB package",
		"uninstallation_id", req.UninstallationID,
		"package_name", packageName,
	)

	var output strings.Builder

	// Try apt-get remove first if available
	var cmd *exec.Cmd
	var pkgManager string

	if _, err := exec.LookPath("apt-get"); err == nil {
		pkgManager = "apt-get"
		cmd = exec.CommandContext(ctx, "apt-get", "remove", "-y", packageName)
	} else {
		pkgManager = "dpkg"
		cmd = exec.CommandContext(ctx, "dpkg", "-r", packageName)
	}

	cmdOutput, err := cmd.CombinedOutput()
	output.WriteString(fmt.Sprintf("%s output:\n%s\n", pkgManager, string(cmdOutput)))

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
		errMsg = fmt.Sprintf("%s remove failed with exit code %d", pkgManager, exitCode)
	}

	return &models.UninstallResult{
		UninstallationID: req.UninstallationID,
		Status:           status,
		ExitCode:         exitCode,
		Output:           output.String(),
		Error:            errMsg,
		StartedAt:        startedAt,
		CompletedAt:      time.Now(),
	}, nil
}

// Cleanup performs post-uninstall cleanup for DEB packages.
func (u *DEBUninstaller) Cleanup(ctx context.Context, req *models.UninstallRequest) (*models.CleanupResults, error) {
	results := &models.CleanupResults{
		PathsRemoved: []string{},
		PathsFailed:  []string{},
	}

	// Run apt-get autoremove if available
	if _, err := exec.LookPath("apt-get"); err == nil {
		cmd := exec.CommandContext(ctx, "apt-get", "autoremove", "-y")
		cmd.Run()
	}

	// Clean up configuration files if requested
	for _, path := range req.CleanupPaths {
		if path == "" || !u.isPathSafe(path) {
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

// isPathSafe checks if a path is safe to delete on Linux.
func (u *DEBUninstaller) isPathSafe(path string) bool {
	protectedPaths := []string{
		"/etc",
		"/usr",
		"/bin",
		"/sbin",
		"/lib",
		"/lib64",
		"/var",
		"/boot",
	}

	normalizedPath := filepath.Clean(path)
	for _, protected := range protectedPaths {
		if normalizedPath == protected || strings.HasPrefix(normalizedPath, protected+"/") {
			return false
		}
	}

	return true
}

// RPMUninstaller implements PlatformUninstaller for RPM packages on Linux.
type RPMUninstaller struct {
	logger *slog.Logger
}

// NewRPMUninstaller creates a new RPM uninstaller.
func NewRPMUninstaller(logger *slog.Logger) *RPMUninstaller {
	return &RPMUninstaller{logger: logger}
}

// CanHandle returns true if this uninstaller can handle RPM uninstallations.
func (u *RPMUninstaller) CanHandle(installationType models.InstallationType) bool {
	return installationType == models.InstallationTypeRPM
}

// IsAvailable returns true if rpm or dnf is available.
func (u *RPMUninstaller) IsAvailable() bool {
	_, rpmErr := exec.LookPath("rpm")
	_, dnfErr := exec.LookPath("dnf")
	return rpmErr == nil || dnfErr == nil
}

// Uninstall performs an RPM package uninstallation.
func (u *RPMUninstaller) Uninstall(ctx context.Context, req *models.UninstallRequest) (*models.UninstallResult, error) {
	startedAt := time.Now()

	packageName := req.RpmPackageName
	if packageName == "" {
		packageName = req.PackageID
	}

	if packageName == "" {
		return &models.UninstallResult{
			UninstallationID: req.UninstallationID,
			Status:           models.UninstallStatusFailed,
			Error:            "rpm_package_name or package_id is required for RPM uninstallation",
			StartedAt:        startedAt,
			CompletedAt:      time.Now(),
		}, nil
	}

	u.logger.Info("uninstalling RPM package",
		"uninstallation_id", req.UninstallationID,
		"package_name", packageName,
	)

	var output strings.Builder

	// Determine package manager: dnf > zypper > yum > rpm
	var cmd *exec.Cmd
	var pkgManager string

	if _, err := exec.LookPath("dnf"); err == nil {
		pkgManager = "dnf"
		cmd = exec.CommandContext(ctx, "dnf", "remove", "-y", packageName)
	} else if _, err := exec.LookPath("zypper"); err == nil {
		pkgManager = "zypper"
		cmd = exec.CommandContext(ctx, "zypper", "--non-interactive", "remove", packageName)
	} else if _, err := exec.LookPath("yum"); err == nil {
		pkgManager = "yum"
		cmd = exec.CommandContext(ctx, "yum", "remove", "-y", packageName)
	} else {
		pkgManager = "rpm"
		cmd = exec.CommandContext(ctx, "rpm", "-e", packageName)
	}

	cmdOutput, err := cmd.CombinedOutput()
	output.WriteString(fmt.Sprintf("%s output:\n%s\n", pkgManager, string(cmdOutput)))

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
		errMsg = fmt.Sprintf("%s remove failed with exit code %d", pkgManager, exitCode)
	}

	return &models.UninstallResult{
		UninstallationID: req.UninstallationID,
		Status:           status,
		ExitCode:         exitCode,
		Output:           output.String(),
		Error:            errMsg,
		StartedAt:        startedAt,
		CompletedAt:      time.Now(),
	}, nil
}

// Cleanup performs post-uninstall cleanup for RPM packages.
func (u *RPMUninstaller) Cleanup(ctx context.Context, req *models.UninstallRequest) (*models.CleanupResults, error) {
	results := &models.CleanupResults{
		PathsRemoved: []string{},
		PathsFailed:  []string{},
	}

	// Clean up configuration files if requested
	for _, path := range req.CleanupPaths {
		if path == "" || !u.isPathSafe(path) {
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

// isPathSafe checks if a path is safe to delete on Linux.
func (u *RPMUninstaller) isPathSafe(path string) bool {
	protectedPaths := []string{
		"/etc",
		"/usr",
		"/bin",
		"/sbin",
		"/lib",
		"/lib64",
		"/var",
		"/boot",
	}

	normalizedPath := filepath.Clean(path)
	for _, protected := range protectedPaths {
		if normalizedPath == protected || strings.HasPrefix(normalizedPath, protected+"/") {
			return false
		}
	}

	return true
}
