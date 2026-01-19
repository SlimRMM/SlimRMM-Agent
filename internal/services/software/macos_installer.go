// Package software provides software installation and uninstallation services.
//go:build darwin

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

	"github.com/slimrmm/slimrmm-agent/internal/homebrew"
	"github.com/slimrmm/slimrmm-agent/internal/services/models"
)

// isBrewAvailable checks if Homebrew is installed and available.
func isBrewAvailable() bool {
	_, err := exec.LookPath("brew")
	return err == nil
}

// CaskInstaller implements PlatformInstaller for Homebrew Cask on macOS.
type CaskInstaller struct {
	logger *slog.Logger
}

// NewCaskInstaller creates a new Cask installer.
func NewCaskInstaller(logger *slog.Logger) *CaskInstaller {
	return &CaskInstaller{logger: logger}
}

// CanHandle returns true if this installer can handle Cask installations.
func (i *CaskInstaller) CanHandle(installationType models.InstallationType) bool {
	return installationType == models.InstallationTypeCask
}

// IsAvailable returns true if Homebrew is available.
func (i *CaskInstaller) IsAvailable() bool {
	return isBrewAvailable()
}

// Install performs a Cask installation.
func (i *CaskInstaller) Install(ctx context.Context, req *models.InstallRequest) (*models.InstallResult, error) {
	startedAt := time.Now()
	caskName := req.CaskName
	if caskName == "" {
		caskName = req.PackageID
	}

	// Validate cask name
	if !homebrew.IsValidCaskName(caskName) {
		return &models.InstallResult{
			InstallationID: req.InstallationID,
			Status:         models.StatusFailed,
			Error:          fmt.Sprintf("invalid cask name: %s", caskName),
			StartedAt:      startedAt,
			CompletedAt:    time.Now(),
		}, nil
	}

	i.logger.Info("installing homebrew cask",
		"installation_id", req.InstallationID,
		"cask_name", caskName,
	)

	// Execute brew install --cask
	cmd := exec.CommandContext(ctx, "brew", "install", "--cask", caskName)
	cmd.Env = append(os.Environ(), "HOMEBREW_NO_AUTO_UPDATE=1")
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
		errMsg = fmt.Sprintf("brew install failed with exit code %d", exitCode)
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

// PKGInstaller implements PlatformInstaller for PKG packages on macOS.
type PKGInstaller struct {
	logger *slog.Logger
}

// NewPKGInstaller creates a new PKG installer.
func NewPKGInstaller(logger *slog.Logger) *PKGInstaller {
	return &PKGInstaller{logger: logger}
}

// CanHandle returns true if this installer can handle PKG installations.
func (i *PKGInstaller) CanHandle(installationType models.InstallationType) bool {
	return installationType == models.InstallationTypePKG
}

// IsAvailable returns true (installer is always available on macOS).
func (i *PKGInstaller) IsAvailable() bool {
	return true
}

// Install performs a PKG installation.
func (i *PKGInstaller) Install(ctx context.Context, req *models.InstallRequest) (*models.InstallResult, error) {
	startedAt := time.Now()

	if req.DownloadURL == "" {
		return &models.InstallResult{
			InstallationID: req.InstallationID,
			Status:         models.StatusFailed,
			Error:          "download_url is required for PKG installation",
			StartedAt:      startedAt,
			CompletedAt:    time.Now(),
		}, nil
	}

	i.logger.Info("downloading and installing PKG",
		"installation_id", req.InstallationID,
		"filename", req.Filename,
	)

	// Download the PKG file
	tempDir := os.TempDir()
	pkgPath := filepath.Join(tempDir, req.Filename)

	if err := downloadFileDarwin(ctx, req.DownloadURL, req.DownloadToken, pkgPath, i.logger); err != nil {
		return &models.InstallResult{
			InstallationID: req.InstallationID,
			Status:         models.StatusFailed,
			Error:          fmt.Sprintf("download failed: %v", err),
			StartedAt:      startedAt,
			CompletedAt:    time.Now(),
		}, nil
	}
	defer os.Remove(pkgPath)

	// Verify hash if provided
	if req.ExpectedHash != "" {
		actualHash, err := calculateFileHashDarwin(pkgPath)
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

	i.logger.Info("executing installer",
		"installation_id", req.InstallationID,
		"pkg_path", pkgPath,
	)

	// Execute installer command
	cmd := exec.CommandContext(ctx, "sudo", "installer", "-pkg", pkgPath, "-target", "/")
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
		errMsg = fmt.Sprintf("installer failed with exit code %d", exitCode)
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

// downloadFileDarwin downloads a file from URL with optional authentication.
func downloadFileDarwin(ctx context.Context, url, token, destPath string, logger *slog.Logger) error {
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

// calculateFileHashDarwin calculates SHA256 hash of a file.
func calculateFileHashDarwin(path string) (string, error) {
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
