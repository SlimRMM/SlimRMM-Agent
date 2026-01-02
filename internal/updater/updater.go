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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kiefernetworks/slimrmm-agent/pkg/version"
)

const (
	GitHubAPIURL    = "https://api.github.com/repos/SlimRMM/SlimRMM-Agent/releases/latest"
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

// Updater manages agent updates.
type Updater struct {
	logger      *slog.Logger
	binaryPath  string
	backupPath  string
	dataDir     string
	serviceName string
}

// New creates a new Updater.
func New(logger *slog.Logger) *Updater {
	execPath, _ := os.Executable()
	dataDir := "/var/lib/slimrmm"
	if runtime.GOOS == "windows" {
		dataDir = filepath.Join(os.Getenv("ProgramData"), "SlimRMM")
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
	assetName := getAssetName()
	for _, asset := range release.Assets {
		if asset.Name == assetName {
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

// getAssetName returns the expected asset name for this platform.
func getAssetName() string {
	ext := "tar.gz"
	if runtime.GOOS == "windows" {
		ext = "zip"
	}
	return fmt.Sprintf("slimrmm-agent_%s_%s.%s", runtime.GOOS, runtime.GOARCH, ext)
}

// isNewerVersion compares two version strings.
func isNewerVersion(latest, current string) bool {
	// Simple comparison - could be enhanced with semver library
	if current == "unknown" || current == "dev" {
		return true
	}
	return latest > current
}

// PerformUpdate downloads and installs the update with rollback support.
func (u *Updater) PerformUpdate(ctx context.Context, info *UpdateInfo) (*UpdateResult, error) {
	result := &UpdateResult{
		OldVersion: version.Version,
		NewVersion: info.Version,
	}

	u.logger.Info("starting update", "from", result.OldVersion, "to", result.NewVersion)

	// Create backup directory
	if err := os.MkdirAll(u.backupPath, 0755); err != nil {
		result.Error = fmt.Sprintf("creating backup dir: %v", err)
		u.logError("update failed", result.Error)
		return result, fmt.Errorf(result.Error)
	}

	// Backup current binary
	backupFile := filepath.Join(u.backupPath, fmt.Sprintf("slimrmm-agent.%s.backup", result.OldVersion))
	if err := u.backupBinary(backupFile); err != nil {
		result.Error = fmt.Sprintf("backup failed: %v", err)
		u.logError("update failed", result.Error)
		return result, fmt.Errorf(result.Error)
	}
	u.logger.Info("backed up current binary", "path", backupFile)

	// Download new version
	tempDir, err := os.MkdirTemp("", "slimrmm-update-*")
	if err != nil {
		result.Error = fmt.Sprintf("creating temp dir: %v", err)
		u.logError("update failed", result.Error)
		return result, fmt.Errorf(result.Error)
	}
	defer os.RemoveAll(tempDir)

	archivePath := filepath.Join(tempDir, info.AssetName)
	if err := u.downloadFile(ctx, info.DownloadURL, archivePath); err != nil {
		result.Error = fmt.Sprintf("download failed: %v", err)
		u.logError("update failed", result.Error)
		return result, fmt.Errorf(result.Error)
	}
	u.logger.Info("downloaded update", "path", archivePath)

	// Extract new binary
	newBinaryPath := filepath.Join(tempDir, "slimrmm-agent")
	if runtime.GOOS == "windows" {
		newBinaryPath += ".exe"
	}
	if err := u.extractBinary(archivePath, newBinaryPath); err != nil {
		result.Error = fmt.Sprintf("extract failed: %v", err)
		u.logError("update failed", result.Error)
		return result, fmt.Errorf(result.Error)
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
		return result, fmt.Errorf(result.Error)
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
		return result, fmt.Errorf(result.Error)
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
		return result, fmt.Errorf(result.Error)
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
func (u *Updater) replaceBinary(newPath string) error {
	// On Windows, we need to rename the current binary first
	if runtime.GOOS == "windows" {
		oldPath := u.binaryPath + ".old"
		os.Remove(oldPath)
		if err := os.Rename(u.binaryPath, oldPath); err != nil {
			return err
		}
	}

	// Copy new binary
	src, err := os.Open(newPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(u.binaryPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return err
	}

	return os.Chmod(u.binaryPath, 0755)
}

// rollback restores the backup binary.
func (u *Updater) rollback(backupPath string) error {
	u.logger.Info("rolling back to previous version", "backup", backupPath)

	src, err := os.Open(backupPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(u.binaryPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return err
	}

	return os.Chmod(u.binaryPath, 0755)
}

// stopService stops the agent service.
func (u *Updater) stopService() error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("systemctl", "stop", u.serviceName)
	case "darwin":
		cmd = exec.Command("launchctl", "stop", u.serviceName)
	case "windows":
		cmd = exec.Command("sc", "stop", u.serviceName)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	return cmd.Run()
}

// startService starts the agent service.
func (u *Updater) startService() error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("systemctl", "start", u.serviceName)
	case "darwin":
		cmd = exec.Command("launchctl", "start", u.serviceName)
	case "windows":
		cmd = exec.Command("sc", "start", u.serviceName)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	return cmd.Run()
}

// healthCheck verifies the new version is running correctly.
func (u *Updater) healthCheck(ctx context.Context) error {
	// Wait a bit for service to start
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
func (u *Updater) StartBackgroundUpdater(ctx context.Context) {
	go func() {
		// Initial delay before first check
		time.Sleep(5 * time.Minute)

		ticker := time.NewTicker(UpdateCheckInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
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
}

// GetChecksumFromRelease fetches the checksum for a release asset.
func (u *Updater) GetChecksumFromRelease(ctx context.Context, version string) (map[string]string, error) {
	checksumURL := fmt.Sprintf("https://github.com/SlimRMM/SlimRMM-Agent/releases/download/v%s/checksums.txt", version)

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
