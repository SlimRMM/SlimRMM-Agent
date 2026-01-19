// Package software provides software installation and uninstallation services.
//go:build !windows

package software

import (
	"context"
	"log/slog"

	"github.com/slimrmm/slimrmm-agent/internal/services/models"
)

// WingetUninstaller stub for non-Windows platforms.
type WingetUninstaller struct {
	logger *slog.Logger
}

// NewWingetUninstaller creates a new Winget uninstaller stub.
func NewWingetUninstaller(logger *slog.Logger) *WingetUninstaller {
	return &WingetUninstaller{logger: logger}
}

// CanHandle returns false on non-Windows platforms.
func (u *WingetUninstaller) CanHandle(installationType models.InstallationType) bool {
	return false
}

// IsAvailable returns false on non-Windows platforms.
func (u *WingetUninstaller) IsAvailable() bool {
	return false
}

// Uninstall is not available on non-Windows platforms.
func (u *WingetUninstaller) Uninstall(ctx context.Context, req *models.UninstallRequest) (*models.UninstallResult, error) {
	return nil, nil
}

// Cleanup is not available on non-Windows platforms.
func (u *WingetUninstaller) Cleanup(ctx context.Context, req *models.UninstallRequest) (*models.CleanupResults, error) {
	return nil, nil
}

// MSIUninstaller stub for non-Windows platforms.
type MSIUninstaller struct {
	logger *slog.Logger
}

// NewMSIUninstaller creates a new MSI uninstaller stub.
func NewMSIUninstaller(logger *slog.Logger) *MSIUninstaller {
	return &MSIUninstaller{logger: logger}
}

// CanHandle returns false on non-Windows platforms.
func (u *MSIUninstaller) CanHandle(installationType models.InstallationType) bool {
	return false
}

// IsAvailable returns false on non-Windows platforms.
func (u *MSIUninstaller) IsAvailable() bool {
	return false
}

// Uninstall is not available on non-Windows platforms.
func (u *MSIUninstaller) Uninstall(ctx context.Context, req *models.UninstallRequest) (*models.UninstallResult, error) {
	return nil, nil
}

// Cleanup is not available on non-Windows platforms.
func (u *MSIUninstaller) Cleanup(ctx context.Context, req *models.UninstallRequest) (*models.CleanupResults, error) {
	return nil, nil
}
