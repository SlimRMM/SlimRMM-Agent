// Package backup provides backup collection services for the RMM agent.
package backup

import (
	"context"
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

// CollectorConfig contains configuration for backup collection.
type CollectorConfig struct {
	// Common fields
	BackupType BackupType
	AgentUUID  string
	ConfigPath string
	DataDir    string
	LogDir     string

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

// Collector defines the interface for backup data collectors.
type Collector interface {
	// Collect gathers backup data for the specified type.
	Collect(ctx context.Context, config CollectorConfig) ([]byte, error)

	// Type returns the backup type this collector handles.
	Type() BackupType
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
