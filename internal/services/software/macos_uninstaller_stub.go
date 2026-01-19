// Package software provides software installation and uninstallation services.
//go:build !darwin

package software

import (
	"context"
	"log/slog"

	"github.com/slimrmm/slimrmm-agent/internal/services/models"
)

// PKGUninstaller stub for non-macOS platforms.
type PKGUninstaller struct {
	logger *slog.Logger
}

// NewPKGUninstaller creates a new PKG uninstaller stub.
func NewPKGUninstaller(logger *slog.Logger) *PKGUninstaller {
	return &PKGUninstaller{logger: logger}
}

// CanHandle returns false on non-macOS platforms.
func (u *PKGUninstaller) CanHandle(installationType models.InstallationType) bool {
	return false
}

// IsAvailable returns false on non-macOS platforms.
func (u *PKGUninstaller) IsAvailable() bool {
	return false
}

// Uninstall is not available on non-macOS platforms.
func (u *PKGUninstaller) Uninstall(ctx context.Context, req *models.UninstallRequest) (*models.UninstallResult, error) {
	return nil, nil
}

// Cleanup is not available on non-macOS platforms.
func (u *PKGUninstaller) Cleanup(ctx context.Context, req *models.UninstallRequest) (*models.CleanupResults, error) {
	return nil, nil
}

// CaskUninstaller stub for non-macOS platforms.
type CaskUninstaller struct {
	logger *slog.Logger
}

// NewCaskUninstaller creates a new Cask uninstaller stub.
func NewCaskUninstaller(logger *slog.Logger) *CaskUninstaller {
	return &CaskUninstaller{logger: logger}
}

// CanHandle returns false on non-macOS platforms.
func (u *CaskUninstaller) CanHandle(installationType models.InstallationType) bool {
	return false
}

// IsAvailable returns false on non-macOS platforms.
func (u *CaskUninstaller) IsAvailable() bool {
	return false
}

// Uninstall is not available on non-macOS platforms.
func (u *CaskUninstaller) Uninstall(ctx context.Context, req *models.UninstallRequest) (*models.UninstallResult, error) {
	return nil, nil
}

// Cleanup is not available on non-macOS platforms.
func (u *CaskUninstaller) Cleanup(ctx context.Context, req *models.UninstallRequest) (*models.CleanupResults, error) {
	return nil, nil
}
