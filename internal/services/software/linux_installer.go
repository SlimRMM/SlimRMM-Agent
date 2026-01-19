// Package software provides software installation and uninstallation services.
//go:build linux

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
)

// DEBInstaller implements PlatformInstaller for DEB packages on Linux.
type DEBInstaller struct {
	logger *slog.Logger
}

// NewDEBInstaller creates a new DEB installer.
func NewDEBInstaller(logger *slog.Logger) *DEBInstaller {
	return &DEBInstaller{logger: logger}
}

// CanHandle returns true if this installer can handle DEB installations.
func (i *DEBInstaller) CanHandle(installationType models.InstallationType) bool {
	return installationType == models.InstallationTypeDEB
}

// IsAvailable returns true if dpkg is available.
func (i *DEBInstaller) IsAvailable() bool {
	_, err := exec.LookPath("dpkg")
	return err == nil
}

// Install performs a DEB package installation.
func (i *DEBInstaller) Install(ctx context.Context, req *models.InstallRequest) (*models.InstallResult, error) {
	startedAt := time.Now()

	if req.DownloadURL == "" {
		return &models.InstallResult{
			InstallationID: req.InstallationID,
			Status:         models.StatusFailed,
			Error:          "download_url is required for DEB installation",
			StartedAt:      startedAt,
			CompletedAt:    time.Now(),
		}, nil
	}

	i.logger.Info("downloading and installing DEB package",
		"installation_id", req.InstallationID,
		"filename", req.Filename,
	)

	// Download the DEB file
	tempDir := os.TempDir()
	debPath := filepath.Join(tempDir, req.Filename)

	if err := downloadFileLinux(ctx, req.DownloadURL, req.DownloadToken, debPath, i.logger); err != nil {
		return &models.InstallResult{
			InstallationID: req.InstallationID,
			Status:         models.StatusFailed,
			Error:          fmt.Sprintf("download failed: %v", err),
			StartedAt:      startedAt,
			CompletedAt:    time.Now(),
		}, nil
	}
	defer os.Remove(debPath)

	// Verify hash if provided
	if req.ExpectedHash != "" {
		actualHash, err := calculateFileHashLinux(debPath)
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

	i.logger.Info("executing dpkg",
		"installation_id", req.InstallationID,
		"deb_path", debPath,
	)

	// First try dpkg, then apt-get -f install to fix dependencies
	var output strings.Builder

	// Install with dpkg
	cmd := exec.CommandContext(ctx, "dpkg", "-i", debPath)
	dpkgOutput, dpkgErr := cmd.CombinedOutput()
	output.WriteString(string(dpkgOutput))

	exitCode := 0
	if dpkgErr != nil {
		// Try to fix dependencies with apt-get
		i.logger.Info("dpkg encountered issues, attempting to fix dependencies")
		output.WriteString("\n--- Attempting to fix dependencies ---\n")

		aptCmd := exec.CommandContext(ctx, "apt-get", "-f", "install", "-y")
		aptOutput, aptErr := aptCmd.CombinedOutput()
		output.WriteString(string(aptOutput))

		if aptErr != nil {
			if exitErr, ok := aptErr.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = -1
			}
		}
	}

	status := models.StatusCompleted
	var errMsg string
	if exitCode != 0 {
		status = models.StatusFailed
		errMsg = fmt.Sprintf("DEB installation failed with exit code %d", exitCode)
	}

	return &models.InstallResult{
		InstallationID: req.InstallationID,
		Status:         status,
		ExitCode:       exitCode,
		Output:         output.String(),
		Error:          errMsg,
		StartedAt:      startedAt,
		CompletedAt:    time.Now(),
	}, nil
}

// RPMInstaller implements PlatformInstaller for RPM packages on Linux.
type RPMInstaller struct {
	logger *slog.Logger
}

// NewRPMInstaller creates a new RPM installer.
func NewRPMInstaller(logger *slog.Logger) *RPMInstaller {
	return &RPMInstaller{logger: logger}
}

// CanHandle returns true if this installer can handle RPM installations.
func (i *RPMInstaller) CanHandle(installationType models.InstallationType) bool {
	return installationType == models.InstallationTypeRPM
}

// IsAvailable returns true if rpm or dnf is available.
func (i *RPMInstaller) IsAvailable() bool {
	_, rpmErr := exec.LookPath("rpm")
	_, dnfErr := exec.LookPath("dnf")
	return rpmErr == nil || dnfErr == nil
}

// Install performs an RPM package installation.
func (i *RPMInstaller) Install(ctx context.Context, req *models.InstallRequest) (*models.InstallResult, error) {
	startedAt := time.Now()

	if req.DownloadURL == "" {
		return &models.InstallResult{
			InstallationID: req.InstallationID,
			Status:         models.StatusFailed,
			Error:          "download_url is required for RPM installation",
			StartedAt:      startedAt,
			CompletedAt:    time.Now(),
		}, nil
	}

	i.logger.Info("downloading and installing RPM package",
		"installation_id", req.InstallationID,
		"filename", req.Filename,
	)

	// Download the RPM file
	tempDir := os.TempDir()
	rpmPath := filepath.Join(tempDir, req.Filename)

	if err := downloadFileLinux(ctx, req.DownloadURL, req.DownloadToken, rpmPath, i.logger); err != nil {
		return &models.InstallResult{
			InstallationID: req.InstallationID,
			Status:         models.StatusFailed,
			Error:          fmt.Sprintf("download failed: %v", err),
			StartedAt:      startedAt,
			CompletedAt:    time.Now(),
		}, nil
	}
	defer os.Remove(rpmPath)

	// Verify hash if provided
	if req.ExpectedHash != "" {
		actualHash, err := calculateFileHashLinux(rpmPath)
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

	// Prefer dnf over rpm for better dependency handling
	var cmd *exec.Cmd
	if _, err := exec.LookPath("dnf"); err == nil {
		i.logger.Info("executing dnf install",
			"installation_id", req.InstallationID,
			"rpm_path", rpmPath,
		)
		cmd = exec.CommandContext(ctx, "dnf", "install", "-y", rpmPath)
	} else {
		i.logger.Info("executing rpm -i",
			"installation_id", req.InstallationID,
			"rpm_path", rpmPath,
		)
		cmd = exec.CommandContext(ctx, "rpm", "-i", rpmPath)
	}

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
	if exitCode != 0 {
		status = models.StatusFailed
		errMsg = fmt.Sprintf("RPM installation failed with exit code %d", exitCode)
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

// downloadFileLinux downloads a file from URL with optional authentication.
func downloadFileLinux(ctx context.Context, url, token, destPath string, logger *slog.Logger) error {
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

// calculateFileHashLinux calculates SHA256 hash of a file.
func calculateFileHashLinux(path string) (string, error) {
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
