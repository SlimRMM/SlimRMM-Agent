// Package software provides software installation and uninstallation services.
package software

import (
	"log/slog"
)

// Services contains all software-related services.
type Services struct {
	Installation   InstallationService
	Uninstallation UninstallationService
	FileLock       FileLockService
}

// NewServices creates all software services with proper dependencies.
func NewServices(logger *slog.Logger) *Services {
	// Create file lock service
	fileLockService := NewFileLockService(logger)

	// Create platform-specific installers
	installers := []PlatformInstaller{
		NewWingetInstaller(logger),
		NewMSIInstaller(logger),
		NewCaskInstaller(logger),
		NewPKGInstaller(logger),
		NewDEBInstaller(logger),
		NewRPMInstaller(logger),
	}

	// Create installation service
	installationService := NewInstallationService(logger, installers...)

	// Create platform-specific uninstallers (to be implemented)
	uninstallers := []PlatformUninstaller{}

	// Create uninstallation service
	// Note: SnapshotService is nil for now, can be implemented later
	uninstallationService := NewUninstallationService(
		logger,
		nil, // SnapshotService
		fileLockService,
		uninstallers...,
	)

	return &Services{
		Installation:   installationService,
		Uninstallation: uninstallationService,
		FileLock:       fileLockService,
	}
}

// SetInstallationProgressCallback sets the progress callback for installation service.
func (s *Services) SetInstallationProgressCallback(callback ProgressCallback) {
	if svc, ok := s.Installation.(*DefaultInstallationService); ok {
		svc.SetProgressCallback(callback)
	}
}

// SetUninstallationProgressCallback sets the progress callback for uninstallation service.
func (s *Services) SetUninstallationProgressCallback(callback ProgressCallback) {
	if svc, ok := s.Uninstallation.(*DefaultUninstallationService); ok {
		svc.SetProgressCallback(callback)
	}
}
