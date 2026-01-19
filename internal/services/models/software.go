// Package models defines domain models and DTOs for service layer communication.
package models

import (
	"time"
)

// InstallationType represents the type of software installation.
type InstallationType string

const (
	InstallationTypeWinget   InstallationType = "winget"
	InstallationTypeMSI      InstallationType = "msi"
	InstallationTypePKG      InstallationType = "pkg"
	InstallationTypeCask     InstallationType = "cask"
	InstallationTypeDEB      InstallationType = "deb"
	InstallationTypeRPM      InstallationType = "rpm"
	InstallationTypeFormula  InstallationType = "formula"
)

// InstallationStatus represents the status of an installation operation.
type InstallationStatus string

const (
	StatusPending    InstallationStatus = "pending"
	StatusInstalling InstallationStatus = "installing"
	StatusCompleted  InstallationStatus = "completed"
	StatusFailed     InstallationStatus = "failed"
	StatusCancelled  InstallationStatus = "cancelled"
)

// UninstallationStatus represents the status of an uninstallation operation.
type UninstallationStatus string

const (
	UninstallStatusPending       UninstallationStatus = "pending"
	UninstallStatusUninstalling  UninstallationStatus = "uninstalling"
	UninstallStatusCleaningUp    UninstallationStatus = "cleaning_up"
	UninstallStatusCompleted     UninstallationStatus = "completed"
	UninstallStatusFailed        UninstallationStatus = "failed"
	UninstallStatusCancelled     UninstallationStatus = "cancelled"
	UninstallStatusRolledBack    UninstallationStatus = "rolled_back"
)

// CleanupMode specifies how aggressive the cleanup should be.
type CleanupMode string

const (
	CleanupModeNone     CleanupMode = "none"
	CleanupModeBasic    CleanupMode = "basic"
	CleanupModeFull     CleanupMode = "full"
	CleanupModeComplete CleanupMode = "complete"
)

// InstallRequest represents a software installation request.
type InstallRequest struct {
	InstallationID   string           `json:"installation_id"`
	InstallationType InstallationType `json:"installation_type"`
	PackageID        string           `json:"package_id,omitempty"`
	PackageName      string           `json:"package_name,omitempty"`
	DownloadURL      string           `json:"download_url,omitempty"`
	DownloadToken    string           `json:"download_token,omitempty"`
	ExpectedHash     string           `json:"expected_hash,omitempty"`
	Filename         string           `json:"filename,omitempty"`
	Silent           bool             `json:"silent"`
	SilentArgs       string           `json:"silent_args,omitempty"`
	TimeoutSeconds   int              `json:"timeout_seconds,omitempty"`
	// Cask-specific fields
	CaskName string `json:"cask_name,omitempty"`
}

// InstallResult represents the result of a software installation.
type InstallResult struct {
	InstallationID string             `json:"installation_id"`
	Status         InstallationStatus `json:"status"`
	ExitCode       int                `json:"exit_code,omitempty"`
	Output         string             `json:"output,omitempty"`
	Error          string             `json:"error,omitempty"`
	StartedAt      time.Time          `json:"started_at"`
	CompletedAt    time.Time          `json:"completed_at,omitempty"`
	Duration       float64            `json:"duration_seconds,omitempty"`
}

// InstallProgress represents progress during installation.
type InstallProgress struct {
	InstallationID string             `json:"installation_id"`
	Status         InstallationStatus `json:"status"`
	Output         string             `json:"output,omitempty"`
	Percent        int                `json:"percent,omitempty"`
}

// UninstallRequest represents a software uninstallation request.
type UninstallRequest struct {
	UninstallationID  string           `json:"uninstallation_id"`
	InstallationType  InstallationType `json:"installation_type"`
	PackageID         string           `json:"package_id,omitempty"`
	PackageName       string           `json:"package_name,omitempty"`
	ProductCode       string           `json:"product_code,omitempty"`
	UninstallString   string           `json:"uninstall_string,omitempty"`
	CleanupMode       CleanupMode      `json:"cleanup_mode,omitempty"`
	CleanupPaths      []string         `json:"cleanup_paths,omitempty"`
	Publisher         string           `json:"publisher,omitempty"`
	TimeoutSeconds    int              `json:"timeout_seconds,omitempty"`
	ForceKill         bool             `json:"force_kill,omitempty"`
	CreateSnapshot    bool             `json:"create_snapshot,omitempty"`
	// Cask-specific fields
	CaskName       string         `json:"cask_name,omitempty"`
	CaskCleanup    *CaskCleanup   `json:"cask_cleanup,omitempty"`
	// DEB/RPM-specific fields
	DebPackageName string `json:"deb_package_name,omitempty"`
	RpmPackageName string `json:"rpm_package_name,omitempty"`
}

// CaskCleanup contains Homebrew cask cleanup information.
type CaskCleanup struct {
	Artifacts    []CaskArtifact `json:"artifacts,omitempty"`
	ZapStanza    *ZapStanza     `json:"zap_stanza,omitempty"`
	CaskDir      string         `json:"cask_dir,omitempty"`
}

// CaskArtifact represents a cask artifact to remove.
type CaskArtifact struct {
	Type   string   `json:"type"`
	Values []string `json:"values"`
}

// ZapStanza contains zap stanza cleanup information.
type ZapStanza struct {
	Trash     []string `json:"trash,omitempty"`
	Delete    []string `json:"delete,omitempty"`
	Rmdir     []string `json:"rmdir,omitempty"`
	LaunchCtl []string `json:"launchctl,omitempty"`
	Pkgutil   []string `json:"pkgutil,omitempty"`
	Script    []string `json:"script,omitempty"`
}

// UninstallResult represents the result of a software uninstallation.
type UninstallResult struct {
	UninstallationID string               `json:"uninstallation_id"`
	Status           UninstallationStatus `json:"status"`
	ExitCode         int                  `json:"exit_code,omitempty"`
	Output           string               `json:"output,omitempty"`
	Error            string               `json:"error,omitempty"`
	StartedAt        time.Time            `json:"started_at"`
	CompletedAt      time.Time            `json:"completed_at,omitempty"`
	Duration         float64              `json:"duration_seconds,omitempty"`
	CleanupResults   *CleanupResults      `json:"cleanup_results,omitempty"`
	SnapshotID       string               `json:"snapshot_id,omitempty"`
}

// CleanupResults contains the results of cleanup operations.
type CleanupResults struct {
	PathsRemoved    []string `json:"paths_removed,omitempty"`
	PathsFailed     []string `json:"paths_failed,omitempty"`
	RegistryRemoved []string `json:"registry_removed,omitempty"`
	RegistryFailed  []string `json:"registry_failed,omitempty"`
	BytesFreed      int64    `json:"bytes_freed,omitempty"`
}

// UninstallProgress represents progress during uninstallation.
type UninstallProgress struct {
	UninstallationID string               `json:"uninstallation_id"`
	Status           UninstallationStatus `json:"status"`
	Output           string               `json:"output,omitempty"`
	Phase            string               `json:"phase,omitempty"`
}

// FileLockInfo represents information about a locked file.
type FileLockInfo struct {
	Path     string `json:"path"`
	Process  string `json:"process"`
	PID      int    `json:"pid"`
	LockType string `json:"lock_type,omitempty"`
}

// FileLockResolution represents a file lock resolution strategy.
type FileLockResolution struct {
	Lock      FileLockInfo `json:"lock"`
	Strategy  string       `json:"strategy"` // terminate, schedule, rename, skip
	ForceKill bool         `json:"force_kill,omitempty"`
}

// Snapshot represents a pre-uninstall snapshot for rollback.
type Snapshot struct {
	ID            string            `json:"id"`
	CreatedAt     time.Time         `json:"created_at"`
	PackageInfo   map[string]string `json:"package_info"`
	RegistryKeys  []string          `json:"registry_keys,omitempty"`
	FilePaths     []string          `json:"file_paths,omitempty"`
	SnapshotPath  string            `json:"snapshot_path,omitempty"`
}

// OperationLog represents a log entry for an operation.
type OperationLog struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Details   string    `json:"details,omitempty"`
}
