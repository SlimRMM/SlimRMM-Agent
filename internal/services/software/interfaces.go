// Package software provides software installation and uninstallation services.
package software

import (
	"context"

	"github.com/slimrmm/slimrmm-agent/internal/services/models"
)

// InstallationService defines the interface for software installation operations.
type InstallationService interface {
	// Install installs software based on the request type.
	Install(ctx context.Context, req *models.InstallRequest) (*models.InstallResult, error)

	// CancelInstallation cancels a running installation.
	CancelInstallation(ctx context.Context, installationID string) error

	// GetInstallationStatus retrieves the status of an installation.
	GetInstallationStatus(ctx context.Context, installationID string) (*models.InstallResult, error)

	// IsInstalling checks if an installation is currently running.
	IsInstalling(installationID string) bool
}

// UninstallationService defines the interface for software uninstallation operations.
type UninstallationService interface {
	// Uninstall uninstalls software based on the request type.
	Uninstall(ctx context.Context, req *models.UninstallRequest) (*models.UninstallResult, error)

	// CancelUninstallation cancels a running uninstallation.
	CancelUninstallation(ctx context.Context, uninstallationID string) error

	// GetUninstallationStatus retrieves the status of an uninstallation.
	GetUninstallationStatus(ctx context.Context, uninstallationID string) (*models.UninstallResult, error)

	// IsUninstalling checks if an uninstallation is currently running.
	IsUninstalling(uninstallationID string) bool

	// CreateSnapshot creates a pre-uninstall snapshot for rollback.
	CreateSnapshot(ctx context.Context, req *models.UninstallRequest) (*models.Snapshot, error)

	// Rollback rolls back an uninstallation using a snapshot.
	Rollback(ctx context.Context, uninstallationID string, snapshotID string) error
}

// ProgressCallback is called to report installation/uninstallation progress.
type ProgressCallback func(progress interface{})

// InstallationServiceWithProgress extends InstallationService with progress reporting.
type InstallationServiceWithProgress interface {
	InstallationService

	// SetProgressCallback sets the callback for progress updates.
	SetProgressCallback(callback ProgressCallback)
}

// UninstallationServiceWithProgress extends UninstallationService with progress reporting.
type UninstallationServiceWithProgress interface {
	UninstallationService

	// SetProgressCallback sets the callback for progress updates.
	SetProgressCallback(callback ProgressCallback)
}

// PlatformInstaller defines platform-specific installation operations.
type PlatformInstaller interface {
	// CanHandle returns true if this installer can handle the given installation type.
	CanHandle(installationType models.InstallationType) bool

	// Install performs the platform-specific installation.
	Install(ctx context.Context, req *models.InstallRequest) (*models.InstallResult, error)

	// IsAvailable returns true if this installer is available on the current system.
	IsAvailable() bool
}

// PlatformUninstaller defines platform-specific uninstallation operations.
type PlatformUninstaller interface {
	// CanHandle returns true if this uninstaller can handle the given installation type.
	CanHandle(installationType models.InstallationType) bool

	// Uninstall performs the platform-specific uninstallation.
	Uninstall(ctx context.Context, req *models.UninstallRequest) (*models.UninstallResult, error)

	// Cleanup performs post-uninstall cleanup.
	Cleanup(ctx context.Context, req *models.UninstallRequest) (*models.CleanupResults, error)

	// IsAvailable returns true if this uninstaller is available on the current system.
	IsAvailable() bool
}

// FileLockService defines operations for file lock detection and resolution.
type FileLockService interface {
	// DetectLocks detects file locks for the given paths.
	DetectLocks(ctx context.Context, paths []string) ([]models.FileLockInfo, error)

	// ResolveLocks resolves file locks using the specified strategies.
	ResolveLocks(ctx context.Context, resolutions []models.FileLockResolution) error

	// IsPathLocked checks if a specific path is locked.
	IsPathLocked(ctx context.Context, path string) (bool, error)
}

// SnapshotService defines operations for pre-uninstall snapshots.
type SnapshotService interface {
	// CreateSnapshot creates a snapshot before uninstallation.
	CreateSnapshot(ctx context.Context, req *models.UninstallRequest) (*models.Snapshot, error)

	// RestoreSnapshot restores a snapshot for rollback.
	RestoreSnapshot(ctx context.Context, snapshotID string) error

	// DeleteSnapshot deletes a snapshot.
	DeleteSnapshot(ctx context.Context, snapshotID string) error

	// GetSnapshot retrieves a snapshot by ID.
	GetSnapshot(ctx context.Context, snapshotID string) (*models.Snapshot, error)
}
