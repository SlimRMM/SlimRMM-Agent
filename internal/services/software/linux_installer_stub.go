// Package software provides software installation and uninstallation services.
//go:build !linux

package software

import (
	"context"
	"log/slog"

	"github.com/slimrmm/slimrmm-agent/internal/services/models"
)

// DEBInstaller stub for non-Linux platforms.
type DEBInstaller struct {
	logger *slog.Logger
}

// NewDEBInstaller creates a stub DEB installer.
func NewDEBInstaller(logger *slog.Logger) *DEBInstaller {
	return &DEBInstaller{logger: logger}
}

// CanHandle always returns false on non-Linux.
func (i *DEBInstaller) CanHandle(installationType models.InstallationType) bool {
	return false
}

// IsAvailable always returns false on non-Linux.
func (i *DEBInstaller) IsAvailable() bool {
	return false
}

// Install returns an error on non-Linux.
func (i *DEBInstaller) Install(ctx context.Context, req *models.InstallRequest) (*models.InstallResult, error) {
	return &models.InstallResult{
		InstallationID: req.InstallationID,
		Status:         models.StatusFailed,
		Error:          "DEB installation is only available on Linux",
	}, nil
}

// RPMInstaller stub for non-Linux platforms.
type RPMInstaller struct {
	logger *slog.Logger
}

// NewRPMInstaller creates a stub RPM installer.
func NewRPMInstaller(logger *slog.Logger) *RPMInstaller {
	return &RPMInstaller{logger: logger}
}

// CanHandle always returns false on non-Linux.
func (i *RPMInstaller) CanHandle(installationType models.InstallationType) bool {
	return false
}

// IsAvailable always returns false on non-Linux.
func (i *RPMInstaller) IsAvailable() bool {
	return false
}

// Install returns an error on non-Linux.
func (i *RPMInstaller) Install(ctx context.Context, req *models.InstallRequest) (*models.InstallResult, error) {
	return &models.InstallResult{
		InstallationID: req.InstallationID,
		Status:         models.StatusFailed,
		Error:          "RPM installation is only available on Linux",
	}, nil
}
