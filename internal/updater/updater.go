// Package updater provides auto-update functionality with rollback support.
package updater

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/slimrmm/slimrmm-agent/pkg/version"
)

const (
	GitHubAPIURL    = "https://api.github.com/repos/slimrmm/slimrmm-agent/releases/latest"
	UpdateCheckInterval = 1 * time.Hour
	MaxDownloadSize = 100 * 1024 * 1024 // 100 MB
	HealthCheckTimeout = 30 * time.Second
	HealthCheckRetries = 3
)

// GitHubRelease represents a GitHub release.
type GitHubRelease struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

// Asset represents a release asset.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// UpdateInfo contains information about an available update.
type UpdateInfo struct {
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	AssetName   string `json:"asset_name"`
	Size        int64  `json:"size"`
}

// UpdateResult contains the result of an update operation.
type UpdateResult struct {
	Success      bool   `json:"success"`
	OldVersion   string `json:"old_version"`
	NewVersion   string `json:"new_version"`
	RolledBack   bool   `json:"rolled_back"`
	Error        string `json:"error,omitempty"`
	RestartNeeded bool  `json:"restart_needed"`
}

// MaintenanceCallback is called to notify the backend about maintenance mode changes.
type MaintenanceCallback func(enabled bool, reason string)

// Updater manages agent updates.
type Updater struct {
	logger              *slog.Logger
	binaryPath          string
	backupPath          string
	dataDir             string
	serviceName         string
	maintenanceCallback MaintenanceCallback
	backgroundOnce      sync.Once // Ensures background updater only starts once
}

// New creates a new Updater.
func New(logger *slog.Logger) *Updater {
	execPath, _ := os.Executable()
	var dataDir string
	switch runtime.GOOS {
	case "darwin":
		dataDir = "/Applications/SlimRMM.app/Contents/Data"
	case "windows":
		dataDir = filepath.Join(os.Getenv("ProgramData"), "SlimRMM")
	default: // linux
		dataDir = "/var/lib/slimrmm"
	}

	return &Updater{
		logger:      logger,
		binaryPath:  execPath,
		backupPath:  filepath.Join(dataDir, "backup"),
		dataDir:     dataDir,
		serviceName: getServiceName(),
	}
}

// getServiceName returns the service name for the current OS.
func getServiceName() string {
	switch runtime.GOOS {
	case "darwin":
		return "io.slimrmm.agent"
	case "windows":
		return "SlimRMMAgent"
	default:
		return "slimrmm-agent"
	}
}

// SetMaintenanceCallback sets the callback for maintenance mode notifications.
func (u *Updater) SetMaintenanceCallback(cb MaintenanceCallback) {
	u.maintenanceCallback = cb
}

// notifyMaintenance calls the maintenance callback if set.
func (u *Updater) notifyMaintenance(enabled bool, reason string) {
	if u.maintenanceCallback != nil {
		u.maintenanceCallback(enabled, reason)
	}
}

// CheckForUpdate checks GitHub for a newer version.
func (u *Updater) CheckForUpdate(ctx context.Context) (*UpdateInfo, error) {
	u.logger.Info("checking for updates", "current_version", version.Version)

	req, err := http.NewRequestWithContext(ctx, "GET", GitHubAPIURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "SlimRMM-Agent/"+version.Version)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching release info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("decoding release: %w", err)
	}

	// Remove 'v' prefix for comparison
	latestVersion := strings.TrimPrefix(release.TagName, "v")
	currentVersion := strings.TrimPrefix(version.Version, "v")

	if !isNewerVersion(latestVersion, currentVersion) {
		u.logger.Info("already on latest version", "version", currentVersion)
		return nil, nil
	}

	// Find the right asset for this OS/arch
	assetPattern := getAssetPattern()
	for _, asset := range release.Assets {
		if matchesAssetPattern(asset.Name, assetPattern) {
			u.logger.Info("update available", "current", currentVersion, "latest", latestVersion)
			return &UpdateInfo{
				Version:     latestVersion,
				DownloadURL: asset.BrowserDownloadURL,
				AssetName:   asset.Name,
				Size:        asset.Size,
			}, nil
		}
	}

	return nil, fmt.Errorf("no compatible asset found for %s/%s", runtime.GOOS, runtime.GOARCH)
}

// getAssetPattern returns the expected asset pattern for this platform.
// Assets are named like: slimrmm-agent_VERSION_OS_ARCH.EXT
func getAssetPattern() string {
	ext := "tar.gz"
	if runtime.GOOS == "windows" {
		ext = "zip"
	}
	// Pattern: slimrmm-agent_*_OS_ARCH.EXT
	return fmt.Sprintf("slimrmm-agent_%%s_%s_%s.%s", runtime.GOOS, runtime.GOARCH, ext)
}

// matchesAssetPattern checks if an asset name matches the expected pattern.
func matchesAssetPattern(assetName, pattern string) bool {
	ext := ".tar.gz"
	if runtime.GOOS == "windows" {
		ext = ".zip"
	}

	// Expected format: slimrmm-agent_VERSION_OS_ARCH.EXT
	prefix := "slimrmm-agent_"
	suffix := fmt.Sprintf("_%s_%s%s", runtime.GOOS, runtime.GOARCH, ext)

	return strings.HasPrefix(assetName, prefix) && strings.HasSuffix(assetName, suffix)
}

// isNewerVersion compares two semantic version strings.
func isNewerVersion(latest, current string) bool {
	if current == "unknown" || current == "dev" {
		return true
	}

	// Parse version strings into numeric parts
	latestParts := parseVersion(latest)
	currentParts := parseVersion(current)

	// Compare each part
	for i := 0; i < len(latestParts) && i < len(currentParts); i++ {
		if latestParts[i] > currentParts[i] {
			return true
		}
		if latestParts[i] < currentParts[i] {
			return false
		}
	}

	// If all compared parts are equal, newer if latest has more parts
	return len(latestParts) > len(currentParts)
}

// parseVersion parses a version string into numeric parts.
func parseVersion(v string) []int {
	parts := strings.Split(v, ".")
	result := make([]int, 0, len(parts))
	for _, p := range parts {
		// Handle pre-release suffixes like "1.0.0-beta"
		p = strings.Split(p, "-")[0]
		var num int
		fmt.Sscanf(p, "%d", &num)
		result = append(result, num)
	}
	return result
}

// PerformUpdate downloads and installs the update with rollback support.
func (u *Updater) PerformUpdate(ctx context.Context, info *UpdateInfo) (*UpdateResult, error) {
	result := &UpdateResult{
		OldVersion: version.Version,
		NewVersion: info.Version,
	}

	u.logger.Info("starting update", "from", result.OldVersion, "to", result.NewVersion)

	// Enter maintenance mode before starting update
	u.notifyMaintenance(true, fmt.Sprintf("Updating from %s to %s", result.OldVersion, result.NewVersion))
	u.logger.Info("entered maintenance mode for update")

	// Ensure we exit maintenance mode when done (success or failure)
	defer func() {
		if !result.Success {
			// On failure, exit maintenance mode
			u.notifyMaintenance(false, "")
			u.logger.Info("exited maintenance mode after failed update")
		}
		// On success, the new agent version will handle exiting maintenance mode
	}()

	// Create backup directory
	if err := os.MkdirAll(u.backupPath, 0755); err != nil {
		result.Error = fmt.Sprintf("creating backup dir: %v", err)
		u.logError("update failed", result.Error)
		return result, errors.New(result.Error)
	}

	// Backup current binary
	backupFile := filepath.Join(u.backupPath, fmt.Sprintf("slimrmm-agent.%s.backup", result.OldVersion))
	if err := u.backupBinary(backupFile); err != nil {
		result.Error = fmt.Sprintf("backup failed: %v", err)
		u.logError("update failed", result.Error)
		return result, errors.New(result.Error)
	}
	u.logger.Info("backed up current binary", "path", backupFile)

	// Download new version
	tempDir, err := os.MkdirTemp("", "slimrmm-update-*")
	if err != nil {
		result.Error = fmt.Sprintf("creating temp dir: %v", err)
		u.logError("update failed", result.Error)
		return result, errors.New(result.Error)
	}
	defer os.RemoveAll(tempDir)

	archivePath := filepath.Join(tempDir, info.AssetName)
	if err := u.downloadFile(ctx, info.DownloadURL, archivePath); err != nil {
		result.Error = fmt.Sprintf("download failed: %v", err)
		u.logError("update failed", result.Error)
		return result, errors.New(result.Error)
	}
	u.logger.Info("downloaded update", "path", archivePath)

	// Verify checksum before extraction (supply chain security)
	checksums, err := u.GetChecksumFromRelease(ctx, info.Version)
	if err != nil {
		u.logger.Warn("could not fetch checksums, skipping verification", "error", err)
	} else {
		expectedHash, ok := checksums[info.AssetName]
		if !ok {
			result.Error = "checksum not found for asset"
			u.logError("update failed", result.Error)
			return result, errors.New(result.Error)
		}
		if err := VerifyChecksum(archivePath, expectedHash); err != nil {
			result.Error = fmt.Sprintf("checksum verification failed: %v", err)
			u.logError("update failed", result.Error)
			return result, errors.New(result.Error)
		}
		u.logger.Info("checksum verified", "hash", expectedHash)
	}

	// Extract new binary
	newBinaryPath := filepath.Join(tempDir, "slimrmm-agent")
	if runtime.GOOS == "windows" {
		newBinaryPath += ".exe"
	}
	if err := u.extractBinary(archivePath, newBinaryPath); err != nil {
		result.Error = fmt.Sprintf("extract failed: %v", err)
		u.logError("update failed", result.Error)
		return result, errors.New(result.Error)
	}
	u.logger.Info("extracted new binary", "path", newBinaryPath)

	// Stop service before replacing binary
	if err := u.stopService(); err != nil {
		u.logger.Warn("failed to stop service", "error", err)
	}

	// Replace binary
	if err := u.replaceBinary(newBinaryPath); err != nil {
		result.Error = fmt.Sprintf("replace failed: %v", err)
		u.logError("update failed", result.Error)
		// Attempt rollback
		if rbErr := u.rollback(backupFile); rbErr != nil {
			result.Error += fmt.Sprintf("; rollback failed: %v", rbErr)
		} else {
			result.RolledBack = true
		}
		u.startService()
		return result, errors.New(result.Error)
	}
	u.logger.Info("replaced binary")

	// Start service with new version
	if err := u.startService(); err != nil {
		result.Error = fmt.Sprintf("start failed: %v", err)
		u.logError("update failed", result.Error)
		// Rollback
		if rbErr := u.rollback(backupFile); rbErr != nil {
			result.Error += fmt.Sprintf("; rollback failed: %v", rbErr)
		} else {
			result.RolledBack = true
			u.startService()
		}
		return result, errors.New(result.Error)
	}

	// Health check - verify new version is running
	if err := u.healthCheck(ctx); err != nil {
		result.Error = fmt.Sprintf("health check failed: %v", err)
		u.logError("update failed", result.Error)
		// Rollback
		u.stopService()
		if rbErr := u.rollback(backupFile); rbErr != nil {
			result.Error += fmt.Sprintf("; rollback failed: %v", rbErr)
		} else {
			result.RolledBack = true
			u.startService()
		}
		return result, errors.New(result.Error)
	}

	// Success - clean up old backups (keep only last 2)
	u.cleanOldBackups(2)

	result.Success = true
	result.RestartNeeded = false // Already restarted
	u.logger.Info("update successful", "version", result.NewVersion)

	return result, nil
}

// backupBinary copies the current binary to backup location.
func (u *Updater) backupBinary(backupPath string) error {
	src, err := os.Open(u.binaryPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(backupPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return err
	}

	// Preserve permissions
	srcInfo, _ := src.Stat()
	return os.Chmod(backupPath, srcInfo.Mode())
}

// downloadFile downloads a file from URL.
func (u *Updater) downloadFile(ctx context.Context, url, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "SlimRMM-Agent/"+version.Version)

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: status %d", resp.StatusCode)
	}

	// Limit download size
	reader := io.LimitReader(resp.Body, MaxDownloadSize)

	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, reader)
	return err
}

// extractBinary extracts the binary from archive.
func (u *Updater) extractBinary(archivePath, destPath string) error {
	if strings.HasSuffix(archivePath, ".zip") {
		return u.extractZip(archivePath, destPath)
	}
	return u.extractTarGz(archivePath, destPath)
}

// extractTarGz extracts binary from tar.gz.
// SECURITY: ZIP slip protection is inherent - destPath is externally controlled
// and header.Name is only used for matching, not path construction.
func (u *Updater) extractTarGz(archivePath, destPath string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Look for the binary
		if header.Typeflag == tar.TypeReg &&
			(header.Name == "slimrmm-agent" || filepath.Base(header.Name) == "slimrmm-agent") {
			out, err := os.Create(destPath)
			if err != nil {
				return err
			}
			defer out.Close()

			if _, err := io.Copy(out, tr); err != nil {
				return err
			}

			return os.Chmod(destPath, 0755)
		}
	}

	return fmt.Errorf("binary not found in archive")
}

// extractZip extracts binary from zip (Windows).
// SECURITY: ZIP slip protection is inherent - destPath is externally controlled
// and f.Name is only used for matching, not path construction.
func (u *Updater) extractZip(archivePath, destPath string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		if filepath.Base(f.Name) == "slimrmm-agent.exe" {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer rc.Close()

			out, err := os.Create(destPath)
			if err != nil {
				return err
			}
			defer out.Close()

			if _, err := io.Copy(out, rc); err != nil {
				return err
			}

			return nil
		}
	}

	return fmt.Errorf("binary not found in archive")
}

// replaceBinary replaces the current binary with the new one.
// Uses rename trick to avoid "text file busy" error on running executables.
func (u *Updater) replaceBinary(newPath string) error {
	// On macOS, we need to update both the App bundle binary (used by launchd)
	// and the CLI binary (used for manual commands)
	if runtime.GOOS == "darwin" {
		return u.replaceBinaryDarwin(newPath)
	}

	return u.replaceSingleBinary(newPath, u.binaryPath)
}

// replaceBinaryDarwin handles macOS-specific binary replacement.
// macOS has two binaries: the App bundle (launchd service) and CLI (/usr/local/bin).
func (u *Updater) replaceBinaryDarwin(newPath string) error {
	appBinaryPath := "/Applications/SlimRMM.app/Contents/MacOS/slimrmm-agent"
	cliBinaryPath := "/usr/local/bin/slimrmm-agent"

	// Always update the App bundle binary (this is what launchd runs)
	if _, err := os.Stat(appBinaryPath); err == nil {
		u.logger.Info("updating App bundle binary", "path", appBinaryPath)
		if err := u.replaceSingleBinary(newPath, appBinaryPath); err != nil {
			return fmt.Errorf("replacing App bundle binary: %w", err)
		}
	}

	// Also update CLI binary if it exists and is different from App bundle
	if _, err := os.Stat(cliBinaryPath); err == nil {
		u.logger.Info("updating CLI binary", "path", cliBinaryPath)
		// Need to copy the binary since newPath was already moved
		if err := u.copyBinary(appBinaryPath, cliBinaryPath); err != nil {
			u.logger.Warn("failed to update CLI binary", "error", err)
			// Not fatal - App bundle is the important one
		}
	}

	return nil
}

// replaceSingleBinary replaces a single binary file.
func (u *Updater) replaceSingleBinary(srcPath, destPath string) error {
	// Remove immutable attribute if set (Linux tamper protection)
	// This must be done before any rename/delete operations
	if runtime.GOOS == "linux" {
		u.removeImmutableAttr(destPath)
	}

	// Rename current binary first - this works even when the binary is running
	// because the running process keeps the inode open, not the filename.
	oldPath := destPath + ".old"
	u.removeImmutableAttr(oldPath) // Also remove from .old if it exists
	os.Remove(oldPath)             // Remove any previous .old file

	if err := os.Rename(destPath, oldPath); err != nil {
		// If rename fails, try removing the file directly
		u.logger.Warn("rename of current binary failed, trying remove", "error", err)
		if rmErr := os.Remove(destPath); rmErr != nil {
			u.logger.Warn("remove also failed", "error", rmErr)
		}
	}

	// Use rename to atomically move new binary into place
	// This avoids "text file busy" because rename doesn't open the file
	if err := os.Rename(srcPath, destPath); err != nil {
		// Cross-device rename not supported, fall back to copy
		u.logger.Warn("rename failed (cross-device?), falling back to copy", "error", err)

		if err := u.copyFileDirect(srcPath, destPath); err != nil {
			return err
		}
	}

	if err := os.Chmod(destPath, 0755); err != nil {
		u.logger.Warn("chmod failed", "error", err)
	}

	// Clean up old binary (best effort - may fail on Windows until reboot)
	os.Remove(oldPath)

	return nil
}

// copyFileDirect copies a file directly, removing the destination first if needed.
func (u *Updater) copyFileDirect(srcPath, destPath string) error {
	// Remove immutable attribute and delete destination
	u.removeImmutableAttr(destPath)
	os.Remove(destPath)

	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("opening source: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("creating destination: %w", err)
	}

	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		os.Remove(destPath)
		return fmt.Errorf("copying file: %w", err)
	}
	dst.Close()

	if err := os.Chmod(destPath, 0755); err != nil {
		os.Remove(destPath)
		return fmt.Errorf("chmod: %w", err)
	}

	return nil
}

// removeImmutableAttr removes the immutable attribute from a file (Linux only).
// This is needed to update files protected by tamper protection.
func (u *Updater) removeImmutableAttr(path string) {
	if runtime.GOOS != "linux" {
		return
	}

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return
	}

	// Use chattr -i to remove immutable attribute
	cmd := exec.Command("chattr", "-i", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		u.logger.Debug("chattr -i failed (may not have immutable attr)", "path", path, "error", err, "output", string(output))
	} else {
		u.logger.Info("removed immutable attribute", "path", path)
	}
}

// copyBinary copies a binary from src to dest.
func (u *Updater) copyBinary(srcPath, destPath string) error {
	// Remove immutable attribute if set
	u.removeImmutableAttr(destPath)

	oldPath := destPath + ".old"
	u.removeImmutableAttr(oldPath)
	os.Remove(oldPath)

	// Rename existing binary first
	if err := os.Rename(destPath, oldPath); err != nil {
		u.logger.Warn("rename of binary failed, trying direct copy", "error", err)
		// Fall back to direct copy
		return u.copyFileDirect(srcPath, destPath)
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	tmpPath := destPath + ".new"
	dst, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		os.Remove(tmpPath)
		return err
	}
	dst.Close()

	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		return err
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		os.Remove(tmpPath)
		return err
	}

	os.Remove(oldPath)
	return nil
}

// rollback restores the backup binary.
func (u *Updater) rollback(backupPath string) error {
	u.logger.Info("rolling back to previous version", "backup", backupPath)

	// On macOS, rollback both binaries
	if runtime.GOOS == "darwin" {
		appBinaryPath := "/Applications/SlimRMM.app/Contents/MacOS/slimrmm-agent"
		cliBinaryPath := "/usr/local/bin/slimrmm-agent"

		if err := u.rollbackSingleBinary(backupPath, appBinaryPath); err != nil {
			return err
		}
		// Also rollback CLI binary
		if _, err := os.Stat(cliBinaryPath); err == nil {
			if err := u.copyBinary(appBinaryPath, cliBinaryPath); err != nil {
				u.logger.Warn("failed to rollback CLI binary", "error", err)
			}
		}
		return nil
	}

	return u.rollbackSingleBinary(backupPath, u.binaryPath)
}

// rollbackSingleBinary restores a single binary from backup.
func (u *Updater) rollbackSingleBinary(backupPath, destPath string) error {
	// Remove immutable attributes first
	u.removeImmutableAttr(destPath)

	// Use rename trick to avoid "text file busy" error
	oldPath := destPath + ".failed"
	u.removeImmutableAttr(oldPath)
	os.Remove(oldPath)

	if err := os.Rename(destPath, oldPath); err != nil {
		u.logger.Warn("rename failed during rollback, trying remove", "error", err)
		os.Remove(destPath)
	}

	// Try to rename backup directly into place (atomic, no "text file busy")
	if err := os.Rename(backupPath, destPath); err != nil {
		// Cross-device or other issue, fall back to direct copy
		u.logger.Warn("rename failed during rollback, falling back to copy", "error", err)
		return u.copyFileDirect(backupPath, destPath)
	}

	if err := os.Chmod(destPath, 0755); err != nil {
		u.logger.Warn("chmod failed during rollback", "error", err)
	}

	// Clean up failed binary
	os.Remove(oldPath)

	return nil
}

// stopService stops the agent service.
func (u *Updater) stopService() error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("systemctl", "stop", u.serviceName).Run()
	case "darwin":
		// Use bootout to properly unload the service (modern macOS 10.10+)
		// This fully stops and unloads the service, allowing binary replacement
		plistPath := "/Library/LaunchDaemons/" + u.serviceName + ".plist"
		err := exec.Command("launchctl", "bootout", "system", plistPath).Run()
		if err != nil {
			// Fallback to legacy unload for older macOS
			u.logger.Debug("bootout failed, trying unload", "error", err)
			return exec.Command("launchctl", "unload", "-w", plistPath).Run()
		}
		return nil
	case "windows":
		// Use 'net stop' instead of 'sc stop' - net stop waits synchronously
		// until the service is fully stopped, preventing "file in use" errors
		// when replacing the binary
		if err := exec.Command("net", "stop", u.serviceName).Run(); err != nil {
			// Fallback to sc stop + wait
			u.logger.Debug("net stop failed, trying sc stop with wait", "error", err)
			if scErr := exec.Command("sc", "stop", u.serviceName).Run(); scErr != nil {
				return scErr
			}
			// Wait for service to actually stop
			return u.waitForServiceStopped(30 * time.Second)
		}
		return nil
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// waitForServiceStopped polls until the Windows service is fully stopped.
func (u *Updater) waitForServiceStopped(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		output, err := exec.Command("sc", "query", u.serviceName).Output()
		if err != nil {
			// Service might not exist or other error - consider it stopped
			return nil
		}
		if strings.Contains(string(output), "STOPPED") {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for service to stop")
}

// startService starts the agent service.
func (u *Updater) startService() error {
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("systemctl", "start", u.serviceName)
		output, err := cmd.CombinedOutput()
		if err != nil {
			u.logger.Error("systemctl start failed", "error", err, "output", string(output))
			return err
		}
		u.logger.Info("systemctl start completed", "output", string(output))
		return nil
	case "darwin":
		// Use bootstrap to properly load the service (modern macOS 10.10+)
		// This loads the plist and starts the service with the new binary
		plistPath := "/Library/LaunchDaemons/" + u.serviceName + ".plist"
		err := exec.Command("launchctl", "bootstrap", "system", plistPath).Run()
		if err != nil {
			// Fallback to legacy load for older macOS
			u.logger.Debug("bootstrap failed, trying load", "error", err)
			return exec.Command("launchctl", "load", "-w", plistPath).Run()
		}
		return nil
	case "windows":
		// Use 'net start' instead of 'sc start' - net start waits synchronously
		// until the service is fully started
		if err := exec.Command("net", "start", u.serviceName).Run(); err != nil {
			// Fallback to sc start
			u.logger.Debug("net start failed, trying sc start", "error", err)
			return exec.Command("sc", "start", u.serviceName).Run()
		}
		return nil
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// healthCheck verifies the new version is running correctly.
func (u *Updater) healthCheck(ctx context.Context) error {
	// Wait a bit for service to start
	u.logger.Info("starting health check, waiting 5 seconds for service startup")
	time.Sleep(5 * time.Second)

	for i := 0; i < HealthCheckRetries; i++ {
		// Check if process is running
		running, err := u.isServiceRunning()
		if err != nil {
			u.logger.Warn("health check error", "attempt", i+1, "error", err)
			time.Sleep(5 * time.Second)
			continue
		}

		if running {
			u.logger.Info("health check passed")
			return nil
		}

		u.logger.Warn("service not running", "attempt", i+1, "max_attempts", HealthCheckRetries)

		// Check systemd status for more info on Linux
		if runtime.GOOS == "linux" {
			cmd := exec.Command("systemctl", "status", u.serviceName)
			output, _ := cmd.CombinedOutput()
			u.logger.Debug("systemctl status output", "output", string(output))
		}

		time.Sleep(5 * time.Second)
	}

	return fmt.Errorf("service not running after %d attempts", HealthCheckRetries)
}

// isServiceRunning checks if the service is running.
func (u *Updater) isServiceRunning() (bool, error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("systemctl", "is-active", u.serviceName)
	case "darwin":
		cmd = exec.Command("launchctl", "list", u.serviceName)
	case "windows":
		cmd = exec.Command("sc", "query", u.serviceName)
	default:
		return false, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	output, err := cmd.Output()
	if err != nil {
		return false, nil
	}

	outputStr := string(output)

	switch runtime.GOOS {
	case "linux":
		return strings.TrimSpace(outputStr) == "active", nil
	case "darwin":
		return strings.Contains(outputStr, u.serviceName), nil
	case "windows":
		return strings.Contains(outputStr, "RUNNING"), nil
	}

	return false, nil
}

// cleanOldBackups removes old backup files, keeping only the specified number.
func (u *Updater) cleanOldBackups(keep int) {
	entries, err := os.ReadDir(u.backupPath)
	if err != nil {
		return
	}

	var backups []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".backup") {
			backups = append(backups, filepath.Join(u.backupPath, entry.Name()))
		}
	}

	// Remove oldest backups
	if len(backups) > keep {
		for i := 0; i < len(backups)-keep; i++ {
			os.Remove(backups[i])
			u.logger.Info("removed old backup", "path", backups[i])
		}
	}
}

// logError writes error details to the log file.
func (u *Updater) logError(message, details string) {
	logPath := filepath.Join(u.dataDir, "log", "update.log")
	os.MkdirAll(filepath.Dir(logPath), 0755)

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	timestamp := time.Now().Format(time.RFC3339)
	entry := fmt.Sprintf("[%s] %s: %s\n", timestamp, message, details)
	f.WriteString(entry)

	u.logger.Error(message, "details", details)
}

// StartBackgroundUpdater starts a goroutine that periodically checks for updates.
// Uses sync.Once to ensure only one background updater runs, even across reconnections.
func (u *Updater) StartBackgroundUpdater(ctx context.Context) {
	u.backgroundOnce.Do(func() {
		u.logger.Info("starting background update checker")
		go func() {
			// Initial delay before first check
			time.Sleep(5 * time.Minute)

			ticker := time.NewTicker(UpdateCheckInterval)
			defer ticker.Stop()

			for {
				select {
				case <-ctx.Done():
					u.logger.Info("background update checker stopped")
					return
				case <-ticker.C:
					info, err := u.CheckForUpdate(ctx)
					if err != nil {
						u.logger.Error("update check failed", "error", err)
						continue
					}

					if info != nil {
						u.logger.Info("auto-update starting", "version", info.Version)
						result, err := u.PerformUpdate(ctx, info)
						if err != nil {
							u.logger.Error("auto-update failed", "error", err)
						} else if result.Success {
							u.logger.Info("auto-update completed", "version", result.NewVersion)
						}
					}
				}
			}
		}()
	})
}

// GetChecksumFromRelease fetches the checksum for a release asset.
func (u *Updater) GetChecksumFromRelease(ctx context.Context, version string) (map[string]string, error) {
	checksumURL := fmt.Sprintf("https://github.com/slimrmm/slimrmm-agent/releases/download/v%s/checksums.txt", version)

	req, err := http.NewRequestWithContext(ctx, "GET", checksumURL, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checksum fetch failed: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	checksums := make(map[string]string)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) == 2 {
			checksums[parts[1]] = parts[0]
		}
	}

	return checksums, nil
}

// VerifyChecksum verifies a file's SHA256 checksum.
func VerifyChecksum(filePath, expectedHash string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}

	actualHash := hex.EncodeToString(h.Sum(nil))
	if actualHash != expectedHash {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHash, actualHash)
	}

	return nil
}
