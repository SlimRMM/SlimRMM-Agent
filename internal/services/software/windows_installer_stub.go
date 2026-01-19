// Package software provides software installation and uninstallation services.
//go:build !windows

package software

import (
	"context"
	"log/slog"

	"github.com/slimrmm/slimrmm-agent/internal/services/models"
)

// WingetInstaller stub for non-Windows platforms.
type WingetInstaller struct {
	logger *slog.Logger
}

// NewWingetInstaller creates a stub Winget installer.
func NewWingetInstaller(logger *slog.Logger) *WingetInstaller {
	return &WingetInstaller{logger: logger}
}

// CanHandle always returns false on non-Windows.
func (i *WingetInstaller) CanHandle(installationType models.InstallationType) bool {
	return false
}

// IsAvailable always returns false on non-Windows.
func (i *WingetInstaller) IsAvailable() bool {
	return false
}

// Install returns an error on non-Windows.
func (i *WingetInstaller) Install(ctx context.Context, req *models.InstallRequest) (*models.InstallResult, error) {
	return &models.InstallResult{
		InstallationID: req.InstallationID,
		Status:         models.StatusFailed,
		Error:          "winget is only available on Windows",
	}, nil
}

// MSIInstaller stub for non-Windows platforms.
type MSIInstaller struct {
	logger *slog.Logger
}

// NewMSIInstaller creates a stub MSI installer.
func NewMSIInstaller(logger *slog.Logger) *MSIInstaller {
	return &MSIInstaller{logger: logger}
}

// CanHandle always returns false on non-Windows.
func (i *MSIInstaller) CanHandle(installationType models.InstallationType) bool {
	return false
}

// IsAvailable always returns false on non-Windows.
func (i *MSIInstaller) IsAvailable() bool {
	return false
}

// Install returns an error on non-Windows.
func (i *MSIInstaller) Install(ctx context.Context, req *models.InstallRequest) (*models.InstallResult, error) {
	return &models.InstallResult{
		InstallationID: req.InstallationID,
		Status:         models.StatusFailed,
		Error:          "MSI installation is only available on Windows",
	}, nil
}
