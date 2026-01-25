package backup

import (
	"context"
	"encoding/json"
	"runtime"
	"time"
)

// ProxmoxClient interface for Proxmox operations.
type ProxmoxClient interface {
	IsProxmoxHost() bool
	CreateVMBackup(ctx context.Context, vmid int, storage, mode string) (*ProxmoxBackupResult, error)
	CreateLXCBackup(ctx context.Context, vmid int, storage, mode string) (*ProxmoxBackupResult, error)
	GetClusterConfig(ctx context.Context) (map[string]interface{}, error)
}

// ProxmoxBackupResult represents the result of a Proxmox backup.
type ProxmoxBackupResult struct {
	Success  bool
	TaskID   string
	FileName string
	Size     int64
	Error    string
}

// ProxmoxVMCollector collects Proxmox VM backups.
type ProxmoxVMCollector struct {
	client ProxmoxClient
	config AgentConfig
	logger Logger
}

// NewProxmoxVMCollector creates a new Proxmox VM collector.
func NewProxmoxVMCollector(client ProxmoxClient, config AgentConfig, logger Logger) *ProxmoxVMCollector {
	return &ProxmoxVMCollector{client: client, config: config, logger: logger}
}

// Type returns the backup type.
func (c *ProxmoxVMCollector) Type() BackupType {
	return TypeProxmoxVM
}

// Collect collects a Proxmox VM backup.
func (c *ProxmoxVMCollector) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	if runtime.GOOS != "linux" {
		return nil, &ErrPlatformUnsupported{
			Feature:  "Proxmox backup",
			Platform: runtime.GOOS,
		}
	}

	if c.client == nil || !c.client.IsProxmoxHost() {
		return nil, &ErrFeatureUnavailable{
			Feature: "Proxmox",
			Reason:  "this system is not a Proxmox host",
		}
	}

	if config.VMID == 0 {
		return nil, &ErrMissingParameter{
			Parameter: "vmid",
			Context:   "proxmox_vm backup",
		}
	}

	// Create backup
	result, err := c.client.CreateVMBackup(ctx, config.VMID, config.ProxmoxStorage, config.ProxmoxMode)
	if err != nil {
		return nil, &ErrCollectionFailed{
			Type:   TypeProxmoxVM,
			Reason: "failed to create Proxmox VM backup",
			Err:    err,
		}
	}

	if result == nil {
		return nil, &ErrCollectionFailed{
			Type:   TypeProxmoxVM,
			Reason: "no backup result returned",
		}
	}

	if !result.Success {
		return nil, &ErrCollectionFailed{
			Type:   TypeProxmoxVM,
			Reason: result.Error,
		}
	}

	backupData := map[string]interface{}{
		"backup_type":  "proxmox_vm",
		"vmid":         config.VMID,
		"storage":      config.ProxmoxStorage,
		"mode":         config.ProxmoxMode,
		"task_id":      result.TaskID,
		"file_name":    result.FileName,
		"size":         result.Size,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"agent_uuid":   config.AgentUUID,
	}

	return json.Marshal(backupData)
}

// ProxmoxLXCCollector collects Proxmox LXC container backups.
type ProxmoxLXCCollector struct {
	client ProxmoxClient
	config AgentConfig
	logger Logger
}

// NewProxmoxLXCCollector creates a new Proxmox LXC collector.
func NewProxmoxLXCCollector(client ProxmoxClient, config AgentConfig, logger Logger) *ProxmoxLXCCollector {
	return &ProxmoxLXCCollector{client: client, config: config, logger: logger}
}

// Type returns the backup type.
func (c *ProxmoxLXCCollector) Type() BackupType {
	return TypeProxmoxLXC
}

// Collect collects a Proxmox LXC backup.
func (c *ProxmoxLXCCollector) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	if runtime.GOOS != "linux" {
		return nil, &ErrPlatformUnsupported{
			Feature:  "Proxmox backup",
			Platform: runtime.GOOS,
		}
	}

	if c.client == nil || !c.client.IsProxmoxHost() {
		return nil, &ErrFeatureUnavailable{
			Feature: "Proxmox",
			Reason:  "this system is not a Proxmox host",
		}
	}

	if config.VMID == 0 {
		return nil, &ErrMissingParameter{
			Parameter: "vmid",
			Context:   "proxmox_lxc backup",
		}
	}

	// Create backup
	result, err := c.client.CreateLXCBackup(ctx, config.VMID, config.ProxmoxStorage, config.ProxmoxMode)
	if err != nil {
		return nil, &ErrCollectionFailed{
			Type:   TypeProxmoxLXC,
			Reason: "failed to create Proxmox LXC backup",
			Err:    err,
		}
	}

	if result == nil {
		return nil, &ErrCollectionFailed{
			Type:   TypeProxmoxLXC,
			Reason: "no backup result returned",
		}
	}

	if !result.Success {
		return nil, &ErrCollectionFailed{
			Type:   TypeProxmoxLXC,
			Reason: result.Error,
		}
	}

	backupData := map[string]interface{}{
		"backup_type": "proxmox_lxc",
		"vmid":        config.VMID,
		"storage":     config.ProxmoxStorage,
		"mode":        config.ProxmoxMode,
		"task_id":     result.TaskID,
		"file_name":   result.FileName,
		"size":        result.Size,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"agent_uuid":  config.AgentUUID,
	}

	return json.Marshal(backupData)
}

// ProxmoxConfigCollector collects Proxmox cluster configuration backups.
type ProxmoxConfigCollector struct {
	client ProxmoxClient
	config AgentConfig
	logger Logger
}

// NewProxmoxConfigCollector creates a new Proxmox config collector.
func NewProxmoxConfigCollector(client ProxmoxClient, config AgentConfig, logger Logger) *ProxmoxConfigCollector {
	return &ProxmoxConfigCollector{client: client, config: config, logger: logger}
}

// Type returns the backup type.
func (c *ProxmoxConfigCollector) Type() BackupType {
	return TypeProxmoxConfig
}

// Collect collects Proxmox cluster configuration.
func (c *ProxmoxConfigCollector) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	if runtime.GOOS != "linux" {
		return nil, &ErrPlatformUnsupported{
			Feature:  "Proxmox backup",
			Platform: runtime.GOOS,
		}
	}

	if c.client == nil || !c.client.IsProxmoxHost() {
		return nil, &ErrFeatureUnavailable{
			Feature: "Proxmox",
			Reason:  "this system is not a Proxmox host",
		}
	}

	clusterConfig, err := c.client.GetClusterConfig(ctx)
	if err != nil {
		return nil, &ErrCollectionFailed{
			Type:   TypeProxmoxConfig,
			Reason: "failed to get Proxmox cluster configuration",
			Err:    err,
		}
	}

	backupData := map[string]interface{}{
		"backup_type":    "proxmox_config",
		"cluster_config": clusterConfig,
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
		"agent_uuid":     config.AgentUUID,
	}

	return json.Marshal(backupData)
}
