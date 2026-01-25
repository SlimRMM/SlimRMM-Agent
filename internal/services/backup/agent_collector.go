package backup

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AgentPaths contains paths to agent files.
type AgentPaths struct {
	ConfigFile string
	CACert     string
	ClientCert string
	LogDir     string
	DataDir    string
}

// AgentConfig provides agent configuration access.
type AgentConfig interface {
	GetUUID() string
	IsMTLSEnabled() bool
}

// AgentConfigCollector collects agent configuration backups.
type AgentConfigCollector struct {
	paths  AgentPaths
	config AgentConfig
}

// NewAgentConfigCollector creates a new agent config collector.
func NewAgentConfigCollector(paths AgentPaths, config AgentConfig) *AgentConfigCollector {
	return &AgentConfigCollector{paths: paths, config: config}
}

// Type returns the backup type.
func (c *AgentConfigCollector) Type() BackupType {
	return TypeAgentConfig
}

// Collect collects agent configuration data.
func (c *AgentConfigCollector) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	backupData := make(map[string]interface{})

	// Read config file
	if configData, err := os.ReadFile(c.paths.ConfigFile); err == nil {
		backupData["config.json"] = base64.StdEncoding.EncodeToString(configData)
	}

	// Include mTLS certificates (public parts only)
	if c.config.IsMTLSEnabled() {
		if caCert, err := os.ReadFile(c.paths.CACert); err == nil {
			backupData["ca.crt"] = base64.StdEncoding.EncodeToString(caCert)
		}
		if clientCert, err := os.ReadFile(c.paths.ClientCert); err == nil {
			backupData["client.crt"] = base64.StdEncoding.EncodeToString(clientCert)
		}
		// Note: Client key is intentionally NOT included for security
	}

	backupData["backup_type"] = "agent_config"
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = c.config.GetUUID()

	return json.Marshal(backupData)
}

// AgentLogsCollector collects agent log backups.
type AgentLogsCollector struct {
	paths  AgentPaths
	config AgentConfig
	logger Logger
}

// NewAgentLogsCollector creates a new agent logs collector.
func NewAgentLogsCollector(paths AgentPaths, config AgentConfig, logger Logger) *AgentLogsCollector {
	return &AgentLogsCollector{paths: paths, config: config, logger: logger}
}

// Type returns the backup type.
func (c *AgentLogsCollector) Type() BackupType {
	return TypeAgentLogs
}

// Collect collects agent log files.
func (c *AgentLogsCollector) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	backupData := make(map[string]interface{})

	// Collect all log files
	logFiles := make(map[string]string)
	err := filepath.Walk(c.paths.LogDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".log") {
			// Limit log file size to 10MB each
			if info.Size() > 10*1024*1024 {
				return nil
			}
			if data, err := os.ReadFile(path); err == nil {
				relPath, _ := filepath.Rel(c.paths.LogDir, path)
				logFiles[relPath] = base64.StdEncoding.EncodeToString(data)
			}
		}
		return nil
	})
	if err != nil && c.logger != nil {
		c.logger.Warn("error walking log directory", "error", err)
	}

	backupData["logs"] = logFiles
	backupData["backup_type"] = "agent_logs"
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = c.config.GetUUID()

	return json.Marshal(backupData)
}

// SystemStateCollector collects system state using osquery.
type SystemStateCollector struct {
	config        AgentConfig
	osqueryClient OsqueryClient
}

// OsqueryClient interface for osquery operations.
type OsqueryClient interface {
	IsAvailable() bool
	GetSystemInfo(ctx context.Context) (*OsqueryResult, error)
	Query(ctx context.Context, query string) (*OsqueryResult, error)
}

// OsqueryResult represents an osquery result.
type OsqueryResult struct {
	Rows []map[string]string
}

// NewSystemStateCollector creates a new system state collector.
func NewSystemStateCollector(config AgentConfig, osqueryClient OsqueryClient) *SystemStateCollector {
	return &SystemStateCollector{config: config, osqueryClient: osqueryClient}
}

// Type returns the backup type.
func (c *SystemStateCollector) Type() BackupType {
	return TypeSystemState
}

// Collect collects system state data.
func (c *SystemStateCollector) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	backupData := make(map[string]interface{})

	if c.osqueryClient != nil && c.osqueryClient.IsAvailable() {
		// System info
		if result, err := c.osqueryClient.GetSystemInfo(ctx); err == nil {
			backupData["system_info"] = result.Rows
		}

		// OS version
		if result, err := c.osqueryClient.Query(ctx, "SELECT * FROM os_version"); err == nil {
			backupData["os_version"] = result.Rows
		}

		// Kernel info
		if result, err := c.osqueryClient.Query(ctx, "SELECT * FROM kernel_info"); err == nil {
			backupData["kernel_info"] = result.Rows
		}

		// CPU info
		if result, err := c.osqueryClient.Query(ctx, "SELECT * FROM cpu_info"); err == nil {
			backupData["cpu_info"] = result.Rows
		}

		// Memory info
		if result, err := c.osqueryClient.Query(ctx, "SELECT * FROM memory_info"); err == nil {
			backupData["memory_info"] = result.Rows
		}

		// Disk info
		if result, err := c.osqueryClient.Query(ctx, "SELECT * FROM disk_info"); err == nil {
			backupData["disk_info"] = result.Rows
		}

		// Network interfaces
		if result, err := c.osqueryClient.Query(ctx, "SELECT * FROM interface_addresses"); err == nil {
			backupData["network_interfaces"] = result.Rows
		}

		// Users
		if result, err := c.osqueryClient.Query(ctx, "SELECT * FROM users"); err == nil {
			backupData["users"] = result.Rows
		}

		// Groups
		if result, err := c.osqueryClient.Query(ctx, "SELECT * FROM groups"); err == nil {
			backupData["groups"] = result.Rows
		}
	}

	backupData["backup_type"] = "system_state"
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = c.config.GetUUID()

	return json.Marshal(backupData)
}

// SoftwareInventoryCollector collects software inventory.
type SoftwareInventoryCollector struct {
	config        AgentConfig
	osqueryClient OsqueryClient
}

// NewSoftwareInventoryCollector creates a new software inventory collector.
func NewSoftwareInventoryCollector(config AgentConfig, osqueryClient OsqueryClient) *SoftwareInventoryCollector {
	return &SoftwareInventoryCollector{config: config, osqueryClient: osqueryClient}
}

// Type returns the backup type.
func (c *SoftwareInventoryCollector) Type() BackupType {
	return TypeSoftwareInventory
}

// Collect collects software inventory data.
func (c *SoftwareInventoryCollector) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	backupData := make(map[string]interface{})

	if c.osqueryClient != nil && c.osqueryClient.IsAvailable() {
		// Installed programs (cross-platform)
		if result, err := c.osqueryClient.Query(ctx, "SELECT * FROM programs"); err == nil {
			backupData["programs"] = result.Rows
		}

		// Browser extensions
		if result, err := c.osqueryClient.Query(ctx, "SELECT * FROM chrome_extensions"); err == nil {
			backupData["chrome_extensions"] = result.Rows
		}

		if result, err := c.osqueryClient.Query(ctx, "SELECT * FROM firefox_addons"); err == nil {
			backupData["firefox_addons"] = result.Rows
		}
	}

	backupData["backup_type"] = "software_inventory"
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = c.config.GetUUID()

	return json.Marshal(backupData)
}

// ComplianceResultsCollector collects compliance results.
type ComplianceResultsCollector struct {
	config          AgentConfig
	complianceCache string // Path to compliance cache file
}

// NewComplianceResultsCollector creates a new compliance results collector.
func NewComplianceResultsCollector(config AgentConfig, complianceCachePath string) *ComplianceResultsCollector {
	return &ComplianceResultsCollector{config: config, complianceCache: complianceCachePath}
}

// Type returns the backup type.
func (c *ComplianceResultsCollector) Type() BackupType {
	return TypeComplianceResults
}

// Collect collects compliance results data.
func (c *ComplianceResultsCollector) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	backupData := make(map[string]interface{})

	// Read cached compliance results
	if c.complianceCache != "" {
		if data, err := os.ReadFile(c.complianceCache); err == nil {
			var results interface{}
			if json.Unmarshal(data, &results) == nil {
				backupData["compliance_results"] = results
			}
		}
	}

	backupData["backup_type"] = "compliance_results"
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = c.config.GetUUID()

	return json.Marshal(backupData)
}
