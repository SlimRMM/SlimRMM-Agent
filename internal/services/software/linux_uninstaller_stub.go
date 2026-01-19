// Package software provides software installation and uninstallation services.
//go:build !linux

package software

import (
	"context"
	"log/slog"

	"github.com/slimrmm/slimrmm-agent/internal/services/models"
)

// DEBUninstaller stub for non-Linux platforms.
type DEBUninstaller struct {
	logger *slog.Logger
}

// NewDEBUninstaller creates a new DEB uninstaller stub.
func NewDEBUninstaller(logger *slog.Logger) *DEBUninstaller {
	return &DEBUninstaller{logger: logger}
}

// CanHandle returns false on non-Linux platforms.
func (u *DEBUninstaller) CanHandle(installationType models.InstallationType) bool {
	return false
}

// IsAvailable returns false on non-Linux platforms.
func (u *DEBUninstaller) IsAvailable() bool {
	return false
}

// Uninstall is not available on non-Linux platforms.
func (u *DEBUninstaller) Uninstall(ctx context.Context, req *models.UninstallRequest) (*models.UninstallResult, error) {
	return nil, nil
}

// Cleanup is not available on non-Linux platforms.
func (u *DEBUninstaller) Cleanup(ctx context.Context, req *models.UninstallRequest) (*models.CleanupResults, error) {
	return nil, nil
}

// RPMUninstaller stub for non-Linux platforms.
type RPMUninstaller struct {
	logger *slog.Logger
}

// NewRPMUninstaller creates a new RPM uninstaller stub.
func NewRPMUninstaller(logger *slog.Logger) *RPMUninstaller {
	return &RPMUninstaller{logger: logger}
}

// CanHandle returns false on non-Linux platforms.
func (u *RPMUninstaller) CanHandle(installationType models.InstallationType) bool {
	return false
}

// IsAvailable returns false on non-Linux platforms.
func (u *RPMUninstaller) IsAvailable() bool {
	return false
}

// Uninstall is not available on non-Linux platforms.
func (u *RPMUninstaller) Uninstall(ctx context.Context, req *models.UninstallRequest) (*models.UninstallResult, error) {
	return nil, nil
}

// Cleanup is not available on non-Linux platforms.
func (u *RPMUninstaller) Cleanup(ctx context.Context, req *models.UninstallRequest) (*models.CleanupResults, error) {
	return nil, nil
}
