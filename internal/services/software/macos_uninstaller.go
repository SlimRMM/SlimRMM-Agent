// Package software provides software installation and uninstallation services.
//go:build darwin

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

	"github.com/slimrmm/slimrmm-agent/internal/homebrew"
	"github.com/slimrmm/slimrmm-agent/internal/services/models"
)

// PKGUninstaller implements PlatformUninstaller for PKG packages on macOS.
type PKGUninstaller struct {
	logger *slog.Logger
}

// NewPKGUninstaller creates a new PKG uninstaller.
func NewPKGUninstaller(logger *slog.Logger) *PKGUninstaller {
	return &PKGUninstaller{logger: logger}
}

// CanHandle returns true if this uninstaller can handle PKG uninstallations.
func (u *PKGUninstaller) CanHandle(installationType models.InstallationType) bool {
	return installationType == models.InstallationTypePKG
}

// IsAvailable returns true (pkgutil is always available on macOS).
func (u *PKGUninstaller) IsAvailable() bool {
	return true
}

// Uninstall performs a PKG uninstallation by forgetting the receipt and removing files.
func (u *PKGUninstaller) Uninstall(ctx context.Context, req *models.UninstallRequest) (*models.UninstallResult, error) {
	startedAt := time.Now()

	pkgID := req.PackageID
	if pkgID == "" {
		return &models.UninstallResult{
			UninstallationID: req.UninstallationID,
			Status:           models.UninstallStatusFailed,
			Error:            "package_id (pkg receipt ID) is required for PKG uninstallation",
			StartedAt:        startedAt,
			CompletedAt:      time.Now(),
		}, nil
	}

	u.logger.Info("uninstalling PKG package",
		"uninstallation_id", req.UninstallationID,
		"package_id", pkgID,
	)

	var output strings.Builder
	exitCode := 0

	// Get list of files installed by this package
	listCmd := exec.CommandContext(ctx, "pkgutil", "--files", pkgID)
	filesOutput, listErr := listCmd.CombinedOutput()
	output.WriteString(fmt.Sprintf("pkgutil --files %s:\n%s\n", pkgID, string(filesOutput)))

	if listErr == nil && len(filesOutput) > 0 {
		// Remove installed files (reverse order for directories)
		files := strings.Split(strings.TrimSpace(string(filesOutput)), "\n")
		for i := len(files) - 1; i >= 0; i-- {
			file := files[i]
			if file == "" {
				continue
			}
			fullPath := "/" + file
			if u.isPathSafe(fullPath) {
				if err := os.RemoveAll(fullPath); err != nil {
					u.logger.Debug("failed to remove file", "path", fullPath, "error", err)
				}
			}
		}
	}

	// Forget the package receipt
	forgetCmd := exec.CommandContext(ctx, "sudo", "pkgutil", "--forget", pkgID)
	forgetOutput, forgetErr := forgetCmd.CombinedOutput()
	output.WriteString(fmt.Sprintf("\npkgutil --forget %s:\n%s\n", pkgID, string(forgetOutput)))

	if forgetErr != nil {
		if exitErr, ok := forgetErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	status := models.UninstallStatusCompleted
	var errMsg string
	if exitCode != 0 {
		status = models.UninstallStatusFailed
		errMsg = fmt.Sprintf("pkgutil --forget failed with exit code %d", exitCode)
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

// isPathSafe checks if a path is safe to delete on macOS.
func (u *PKGUninstaller) isPathSafe(path string) bool {
	protectedPaths := []string{
		"/System",
		"/Library",
		"/usr",
		"/bin",
		"/sbin",
		"/private/var",
		"/cores",
	}

	normalizedPath := filepath.Clean(path)
	for _, protected := range protectedPaths {
		if strings.HasPrefix(normalizedPath, protected) {
			return false
		}
	}

	return true
}

// Cleanup performs post-uninstall cleanup for PKG packages.
func (u *PKGUninstaller) Cleanup(ctx context.Context, req *models.UninstallRequest) (*models.CleanupResults, error) {
	results := &models.CleanupResults{
		PathsRemoved: []string{},
		PathsFailed:  []string{},
	}

	// Clean up Application Support and Preferences
	appName := req.PackageName
	if appName == "" {
		return results, nil
	}

	homeDir, _ := os.UserHomeDir()
	cleanupPaths := []string{
		filepath.Join(homeDir, "Library", "Application Support", appName),
		filepath.Join(homeDir, "Library", "Preferences", appName),
		filepath.Join(homeDir, "Library", "Caches", appName),
	}

	for _, path := range cleanupPaths {
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

// CaskUninstaller implements PlatformUninstaller for Homebrew Cask on macOS.
type CaskUninstaller struct {
	logger *slog.Logger
}

// NewCaskUninstaller creates a new Cask uninstaller.
func NewCaskUninstaller(logger *slog.Logger) *CaskUninstaller {
	return &CaskUninstaller{logger: logger}
}

// CanHandle returns true if this uninstaller can handle Cask uninstallations.
func (u *CaskUninstaller) CanHandle(installationType models.InstallationType) bool {
	return installationType == models.InstallationTypeCask
}

// IsAvailable returns true if Homebrew is available.
func (u *CaskUninstaller) IsAvailable() bool {
	return isBrewAvailable()
}

// Uninstall performs a Homebrew cask uninstallation.
func (u *CaskUninstaller) Uninstall(ctx context.Context, req *models.UninstallRequest) (*models.UninstallResult, error) {
	startedAt := time.Now()

	caskName := req.CaskName
	if caskName == "" {
		caskName = req.PackageID
	}

	if caskName == "" {
		return &models.UninstallResult{
			UninstallationID: req.UninstallationID,
			Status:           models.UninstallStatusFailed,
			Error:            "cask_name or package_id is required for Cask uninstallation",
			StartedAt:        startedAt,
			CompletedAt:      time.Now(),
		}, nil
	}

	// Validate cask name
	if !homebrew.IsValidCaskName(caskName) {
		return &models.UninstallResult{
			UninstallationID: req.UninstallationID,
			Status:           models.UninstallStatusFailed,
			Error:            fmt.Sprintf("invalid cask name: %s", caskName),
			StartedAt:        startedAt,
			CompletedAt:      time.Now(),
		}, nil
	}

	u.logger.Info("uninstalling homebrew cask",
		"uninstallation_id", req.UninstallationID,
		"cask_name", caskName,
	)

	var output strings.Builder

	// Execute brew uninstall --cask
	cmd := exec.CommandContext(ctx, "brew", "uninstall", "--cask", caskName)
	cmd.Env = append(os.Environ(), "HOMEBREW_NO_AUTO_UPDATE=1")
	brewOutput, err := cmd.CombinedOutput()
	output.WriteString(string(brewOutput))

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
		errMsg = fmt.Sprintf("brew uninstall --cask failed with exit code %d", exitCode)
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

// Cleanup performs post-uninstall cleanup for Cask packages.
func (u *CaskUninstaller) Cleanup(ctx context.Context, req *models.UninstallRequest) (*models.CleanupResults, error) {
	results := &models.CleanupResults{
		PathsRemoved: []string{},
		PathsFailed:  []string{},
	}

	// Execute zap stanza cleanup if provided
	if req.CaskCleanup != nil && req.CaskCleanup.ZapStanza != nil {
		zap := req.CaskCleanup.ZapStanza

		// Remove trash paths
		for _, path := range zap.Trash {
			expandedPath := os.ExpandEnv(path)
			if _, err := os.Stat(expandedPath); err == nil {
				if err := os.RemoveAll(expandedPath); err != nil {
					results.PathsFailed = append(results.PathsFailed, expandedPath)
				} else {
					results.PathsRemoved = append(results.PathsRemoved, expandedPath)
				}
			}
		}

		// Remove delete paths
		for _, path := range zap.Delete {
			expandedPath := os.ExpandEnv(path)
			if _, err := os.Stat(expandedPath); err == nil {
				if err := os.RemoveAll(expandedPath); err != nil {
					results.PathsFailed = append(results.PathsFailed, expandedPath)
				} else {
					results.PathsRemoved = append(results.PathsRemoved, expandedPath)
				}
			}
		}
	}

	return results, nil
}
