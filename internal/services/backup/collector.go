// Package backup provides backup collection services for the RMM agent.
package backup

import (
	"context"
	"time"
)

// BackupType defines the type of backup.
type BackupType string

// Supported backup types.
const (
	TypeAgentConfig       BackupType = "agent_config"
	TypeAgentLogs         BackupType = "agent_logs"
	TypeSystemState       BackupType = "system_state"
	TypeSoftwareInventory BackupType = "software_inventory"
	TypeComplianceResults BackupType = "compliance_results"
	TypeFull              BackupType = "full"
	TypeFilesAndFolders   BackupType = "files_and_folders"
	TypeDockerContainer   BackupType = "docker_container"
	TypeDockerVolume      BackupType = "docker_volume"
	TypeDockerImage       BackupType = "docker_image"
	TypeDockerCompose     BackupType = "docker_compose"
	TypeProxmoxVM         BackupType = "proxmox_vm"
	TypeProxmoxLXC        BackupType = "proxmox_lxc"
	TypeProxmoxConfig     BackupType = "proxmox_config"
	TypeHyperVVM          BackupType = "hyperv_vm"
	TypeHyperVCheckpoint  BackupType = "hyperv_checkpoint"
	TypeHyperVConfig      BackupType = "hyperv_config"
	TypePostgreSQL        BackupType = "postgresql"
	TypeMySQL             BackupType = "mysql"
)

// BackupStrategy defines the backup strategy.
type BackupStrategy string

// Supported backup strategies.
const (
	StrategyFull         BackupStrategy = "full"
	StrategyIncremental  BackupStrategy = "incremental"
	StrategyDifferential BackupStrategy = "differential"
	StrategySynthetic    BackupStrategy = "synthetic_full"
)

// FileManifestEntry represents metadata for a single file in a backup manifest.
type FileManifestEntry struct {
	Path         string    `json:"path"`
	Size         int64     `json:"size"`
	ModTime      time.Time `json:"mod_time"`
	Mode         uint32    `json:"mode"`
	IsDir        bool      `json:"is_dir"`
	IsSymlink    bool      `json:"is_symlink"`
	LinkTarget   string    `json:"link_target,omitempty"`
	SHA256       string    `json:"sha256,omitempty"`
	ArchiveBit   bool      `json:"archive_bit,omitempty"`
	ChangeType   string    `json:"change_type,omitempty"` // new, modified, unchanged, deleted
}

// FileManifest represents a complete manifest of files in a backup.
type FileManifest struct {
	BackupID      string               `json:"backup_id"`
	BackupType    BackupType           `json:"backup_type"`
	Strategy      BackupStrategy       `json:"strategy"`
	BaseBackupID  string               `json:"base_backup_id,omitempty"`
	ParentBackupID string              `json:"parent_backup_id,omitempty"`
	CreatedAt     time.Time            `json:"created_at"`
	TotalFiles    int                  `json:"total_files"`
	TotalSize     int64                `json:"total_size"`
	Files         []FileManifestEntry  `json:"files"`
}

// DeltaInfo contains information about changes since the last backup.
type DeltaInfo struct {
	NewFiles      int   `json:"new_files"`
	ModifiedFiles int   `json:"modified_files"`
	DeletedFiles  int   `json:"deleted_files"`
	UnchangedFiles int  `json:"unchanged_files"`
	DeltaSize     int64 `json:"delta_size"`
}

// CollectorConfig contains configuration for backup collection.
type CollectorConfig struct {
	// Common fields
	BackupType BackupType
	AgentUUID  string
	ConfigPath string
	DataDir    string
	LogDir     string

	// Backup strategy fields (for incremental/differential backups)
	Strategy           BackupStrategy   `json:"strategy,omitempty"`
	BaseBackupID       string           `json:"base_backup_id,omitempty"`
	ParentBackupID     string           `json:"parent_backup_id,omitempty"`
	PreviousManifest   *FileManifest    `json:"previous_manifest,omitempty"`
	PreviousManifestURL string          `json:"previous_manifest_url,omitempty"`
	UseArchiveBit      bool             `json:"use_archive_bit,omitempty"`
	ComputeHashes      bool             `json:"compute_hashes,omitempty"`

	// Files and folders backup
	Paths           []string
	ExcludePatterns []string
	IncludeHidden   bool
	MaxFileSize     int64

	// Docker backup
	ContainerID string
	VolumeName  string
	ImageName   string
	ComposePath string

	// Proxmox backup
	VMID           int
	ProxmoxStorage string
	ProxmoxMode    string

	// Hyper-V backup
	VMName         string
	CheckpointName string
	ExportPath     string

	// Database backup
	DatabaseType   string
	ConnectionType string
	Host           string
	Port           int
	SocketPath     string
	Username       string
	Password       string
	DatabaseName   string
	SchemaOnly     bool
	DataOnly       bool
	AllDatabases   bool
}

// CollectorResult contains the result of a backup collection.
type CollectorResult struct {
	Data      []byte        `json:"data"`
	Manifest  *FileManifest `json:"manifest,omitempty"`
	DeltaInfo *DeltaInfo    `json:"delta_info,omitempty"`
}

// Collector defines the interface for backup data collectors.
type Collector interface {
	// Collect gathers backup data for the specified type.
	Collect(ctx context.Context, config CollectorConfig) ([]byte, error)

	// Type returns the backup type this collector handles.
	Type() BackupType
}

// IncrementalCollector extends Collector with incremental backup support.
type IncrementalCollector interface {
	Collector

	// CollectIncremental gathers backup data with manifest and delta information.
	CollectIncremental(ctx context.Context, config CollectorConfig) (*CollectorResult, error)

	// SupportsIncremental returns true if this collector supports incremental backups.
	SupportsIncremental() bool
}

// CollectorRegistry manages backup collectors.
type CollectorRegistry struct {
	collectors map[BackupType]Collector
}

// NewCollectorRegistry creates a new collector registry.
func NewCollectorRegistry() *CollectorRegistry {
	return &CollectorRegistry{
		collectors: make(map[BackupType]Collector),
	}
}

// Register registers a collector for a backup type.
func (r *CollectorRegistry) Register(c Collector) {
	r.collectors[c.Type()] = c
}

// Get returns the collector for a backup type.
func (r *CollectorRegistry) Get(t BackupType) (Collector, bool) {
	c, ok := r.collectors[t]
	return c, ok
}

// Collect collects backup data using the appropriate collector.
func (r *CollectorRegistry) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	collector, ok := r.Get(config.BackupType)
	if !ok {
		return nil, &ErrUnknownBackupType{Type: string(config.BackupType)}
	}
	return collector.Collect(ctx, config)
}

// CollectIncremental collects backup data with manifest support using the appropriate collector.
func (r *CollectorRegistry) CollectIncremental(ctx context.Context, config CollectorConfig) (*CollectorResult, error) {
	collector, ok := r.Get(config.BackupType)
	if !ok {
		return nil, &ErrUnknownBackupType{Type: string(config.BackupType)}
	}

	// Check if collector supports incremental backups
	if incCollector, ok := collector.(IncrementalCollector); ok && incCollector.SupportsIncremental() {
		return incCollector.CollectIncremental(ctx, config)
	}

	// Fall back to regular collection without manifest
	data, err := collector.Collect(ctx, config)
	if err != nil {
		return nil, err
	}

	return &CollectorResult{
		Data: data,
	}, nil
}

// SupportsIncremental checks if the collector for a backup type supports incremental backups.
func (r *CollectorRegistry) SupportsIncremental(t BackupType) bool {
	collector, ok := r.Get(t)
	if !ok {
		return false
	}

	if incCollector, ok := collector.(IncrementalCollector); ok {
		return incCollector.SupportsIncremental()
	}

	return false
}
