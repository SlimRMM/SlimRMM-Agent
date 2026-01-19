// Package software provides software installation and uninstallation services.
//go:build !darwin

package software

import (
	"context"
	"log/slog"

	"github.com/slimrmm/slimrmm-agent/internal/services/models"
)

// CaskInstaller stub for non-macOS platforms.
type CaskInstaller struct {
	logger *slog.Logger
}

// NewCaskInstaller creates a stub Cask installer.
func NewCaskInstaller(logger *slog.Logger) *CaskInstaller {
	return &CaskInstaller{logger: logger}
}

// CanHandle always returns false on non-macOS.
func (i *CaskInstaller) CanHandle(installationType models.InstallationType) bool {
	return false
}

// IsAvailable always returns false on non-macOS.
func (i *CaskInstaller) IsAvailable() bool {
	return false
}

// Install returns an error on non-macOS.
func (i *CaskInstaller) Install(ctx context.Context, req *models.InstallRequest) (*models.InstallResult, error) {
	return &models.InstallResult{
		InstallationID: req.InstallationID,
		Status:         models.StatusFailed,
		Error:          "homebrew cask is only available on macOS",
	}, nil
}

// PKGInstaller stub for non-macOS platforms.
type PKGInstaller struct {
	logger *slog.Logger
}

// NewPKGInstaller creates a stub PKG installer.
func NewPKGInstaller(logger *slog.Logger) *PKGInstaller {
	return &PKGInstaller{logger: logger}
}

// CanHandle always returns false on non-macOS.
func (i *PKGInstaller) CanHandle(installationType models.InstallationType) bool {
	return false
}

// IsAvailable always returns false on non-macOS.
func (i *PKGInstaller) IsAvailable() bool {
	return false
}

// Install returns an error on non-macOS.
func (i *PKGInstaller) Install(ctx context.Context, req *models.InstallRequest) (*models.InstallResult, error) {
	return &models.InstallResult{
		InstallationID: req.InstallationID,
		Status:         models.StatusFailed,
		Error:          "PKG installation is only available on macOS",
	}, nil
}
