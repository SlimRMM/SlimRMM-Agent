// Package backup provides backup collection services for the RMM agent.
package backup

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
)

// BackupCapability represents a backup capability with its availability status.
type BackupCapability struct {
	Type                BackupType `json:"type"`
	Available           bool       `json:"available"`
	Reason              string     `json:"reason,omitempty"`
	SupportsIncremental bool       `json:"supports_incremental"`
	SupportsScheduled   bool       `json:"supports_scheduled"`
	RequiresCredentials bool       `json:"requires_credentials"`
	Dependencies        []string   `json:"dependencies,omitempty"`
}

// BackupCapabilities contains all detected backup capabilities for an agent.
type BackupCapabilities struct {
	// Core backup types
	AgentConfig       BackupCapability `json:"agent_config"`
	AgentLogs         BackupCapability `json:"agent_logs"`
	SystemState       BackupCapability `json:"system_state"`
	SoftwareInventory BackupCapability `json:"software_inventory"`
	ComplianceResults BackupCapability `json:"compliance_results"`
	FilesAndFolders   BackupCapability `json:"files_and_folders"`

	// Docker backup types
	DockerContainer BackupCapability `json:"docker_container"`
	DockerVolume    BackupCapability `json:"docker_volume"`
	DockerImage     BackupCapability `json:"docker_image"`
	DockerCompose   BackupCapability `json:"docker_compose"`

	// Virtualization backup types
	ProxmoxVM         BackupCapability `json:"proxmox_vm"`
	ProxmoxLXC        BackupCapability `json:"proxmox_lxc"`
	ProxmoxConfig     BackupCapability `json:"proxmox_config"`
	HyperVVM          BackupCapability `json:"hyperv_vm"`
	HyperVCheckpoint  BackupCapability `json:"hyperv_checkpoint"`
	HyperVConfig      BackupCapability `json:"hyperv_config"`

	// Database backup types
	PostgreSQL BackupCapability `json:"postgresql"`
	MySQL      BackupCapability `json:"mysql"`

	// Platform info
	Platform         string   `json:"platform"`
	AvailableTypes   []string `json:"available_types"`
	UnavailableTypes []string `json:"unavailable_types"`
}

// CapabilityDetector detects available backup capabilities on the system.
type CapabilityDetector struct {
	registry *CollectorRegistry
}

// NewCapabilityDetector creates a new capability detector.
func NewCapabilityDetector(registry *CollectorRegistry) *CapabilityDetector {
	return &CapabilityDetector{
		registry: registry,
	}
}

// DetectCapabilities detects all available backup capabilities.
func (d *CapabilityDetector) DetectCapabilities(ctx context.Context) *BackupCapabilities {
	caps := &BackupCapabilities{
		Platform:         runtime.GOOS,
		AvailableTypes:   []string{},
		UnavailableTypes: []string{},
	}

	// Core backup types - always available
	caps.AgentConfig = d.detectAgentConfigCapability()
	caps.AgentLogs = d.detectAgentLogsCapability()
	caps.SystemState = d.detectSystemStateCapability()
	caps.SoftwareInventory = d.detectSoftwareInventoryCapability()
	caps.ComplianceResults = d.detectComplianceResultsCapability()
	caps.FilesAndFolders = d.detectFilesAndFoldersCapability()

	// Docker capabilities
	caps.DockerContainer = d.detectDockerCapability("docker_container")
	caps.DockerVolume = d.detectDockerCapability("docker_volume")
	caps.DockerImage = d.detectDockerCapability("docker_image")
	caps.DockerCompose = d.detectDockerComposeCapability()

	// Proxmox capabilities
	caps.ProxmoxVM = d.detectProxmoxCapability("proxmox_vm")
	caps.ProxmoxLXC = d.detectProxmoxCapability("proxmox_lxc")
	caps.ProxmoxConfig = d.detectProxmoxCapability("proxmox_config")

	// Hyper-V capabilities
	caps.HyperVVM = d.detectHyperVCapability("hyperv_vm")
	caps.HyperVCheckpoint = d.detectHyperVCapability("hyperv_checkpoint")
	caps.HyperVConfig = d.detectHyperVCapability("hyperv_config")

	// Database capabilities
	caps.PostgreSQL = d.detectPostgreSQLCapability()
	caps.MySQL = d.detectMySQLCapability()

	// Build summary lists
	d.buildCapabilitySummary(caps)

	return caps
}

// detectAgentConfigCapability checks if agent config backup is available.
func (d *CapabilityDetector) detectAgentConfigCapability() BackupCapability {
	return BackupCapability{
		Type:                TypeAgentConfig,
		Available:           true,
		SupportsIncremental: false,
		SupportsScheduled:   true,
		RequiresCredentials: false,
	}
}

// detectAgentLogsCapability checks if agent logs backup is available.
func (d *CapabilityDetector) detectAgentLogsCapability() BackupCapability {
	return BackupCapability{
		Type:                TypeAgentLogs,
		Available:           true,
		SupportsIncremental: false,
		SupportsScheduled:   true,
		RequiresCredentials: false,
	}
}

// detectSystemStateCapability checks if system state backup is available.
func (d *CapabilityDetector) detectSystemStateCapability() BackupCapability {
	return BackupCapability{
		Type:                TypeSystemState,
		Available:           true,
		SupportsIncremental: false,
		SupportsScheduled:   true,
		RequiresCredentials: false,
	}
}

// detectSoftwareInventoryCapability checks if software inventory backup is available.
func (d *CapabilityDetector) detectSoftwareInventoryCapability() BackupCapability {
	return BackupCapability{
		Type:                TypeSoftwareInventory,
		Available:           true,
		SupportsIncremental: false,
		SupportsScheduled:   true,
		RequiresCredentials: false,
	}
}

// detectComplianceResultsCapability checks if compliance results backup is available.
func (d *CapabilityDetector) detectComplianceResultsCapability() BackupCapability {
	return BackupCapability{
		Type:                TypeComplianceResults,
		Available:           true,
		SupportsIncremental: false,
		SupportsScheduled:   true,
		RequiresCredentials: false,
	}
}

// detectFilesAndFoldersCapability checks if files and folders backup is available.
func (d *CapabilityDetector) detectFilesAndFoldersCapability() BackupCapability {
	supportsIncremental := false
	if d.registry != nil {
		supportsIncremental = d.registry.SupportsIncremental(TypeFilesAndFolders)
	}

	return BackupCapability{
		Type:                TypeFilesAndFolders,
		Available:           true,
		SupportsIncremental: supportsIncremental,
		SupportsScheduled:   true,
		RequiresCredentials: false,
	}
}

// detectDockerCapability checks if Docker backup capabilities are available.
func (d *CapabilityDetector) detectDockerCapability(backupType string) BackupCapability {
	cap := BackupCapability{
		Type:                BackupType(backupType),
		SupportsIncremental: false,
		SupportsScheduled:   true,
		RequiresCredentials: false,
		Dependencies:        []string{"docker"},
	}

	// Check if Docker is available
	if !isDockerAvailable() {
		cap.Available = false
		cap.Reason = "Docker not installed or not running"
		return cap
	}

	cap.Available = true
	return cap
}

// detectDockerComposeCapability checks if Docker Compose backup is available.
func (d *CapabilityDetector) detectDockerComposeCapability() BackupCapability {
	cap := BackupCapability{
		Type:                TypeDockerCompose,
		SupportsIncremental: false,
		SupportsScheduled:   true,
		RequiresCredentials: false,
		Dependencies:        []string{"docker", "docker-compose"},
	}

	// Check if Docker and Docker Compose are available
	if !isDockerAvailable() {
		cap.Available = false
		cap.Reason = "Docker not installed or not running"
		return cap
	}

	if !isDockerComposeAvailable() {
		cap.Available = false
		cap.Reason = "Docker Compose not installed"
		return cap
	}

	cap.Available = true
	return cap
}

// detectProxmoxCapability checks if Proxmox backup capabilities are available.
func (d *CapabilityDetector) detectProxmoxCapability(backupType string) BackupCapability {
	cap := BackupCapability{
		Type:                BackupType(backupType),
		SupportsIncremental: false,
		SupportsScheduled:   true,
		RequiresCredentials: true,
		Dependencies:        []string{"proxmox-ve", "pvesh"},
	}

	// Check if running on Proxmox
	if !isProxmoxHost() {
		cap.Available = false
		cap.Reason = "Not running on Proxmox VE host"
		return cap
	}

	// Check if pvesh command is available
	if !isPveshAvailable() {
		cap.Available = false
		cap.Reason = "Proxmox API tools (pvesh) not available"
		return cap
	}

	cap.Available = true
	return cap
}

// detectHyperVCapability checks if Hyper-V backup capabilities are available.
func (d *CapabilityDetector) detectHyperVCapability(backupType string) BackupCapability {
	cap := BackupCapability{
		Type:                BackupType(backupType),
		SupportsIncremental: false,
		SupportsScheduled:   true,
		RequiresCredentials: false,
		Dependencies:        []string{"hyper-v", "powershell"},
	}

	// Hyper-V is only available on Windows
	if runtime.GOOS != "windows" {
		cap.Available = false
		cap.Reason = "Hyper-V is only available on Windows"
		return cap
	}

	// Check if Hyper-V is installed and enabled
	if !isHyperVAvailable() {
		cap.Available = false
		cap.Reason = "Hyper-V not installed or not enabled"
		return cap
	}

	cap.Available = true
	return cap
}

// detectPostgreSQLCapability checks if PostgreSQL backup is available.
func (d *CapabilityDetector) detectPostgreSQLCapability() BackupCapability {
	cap := BackupCapability{
		Type:                TypePostgreSQL,
		SupportsIncremental: false,
		SupportsScheduled:   true,
		RequiresCredentials: true,
		Dependencies:        []string{"pg_dump"},
	}

	// Check if pg_dump is available
	if !isPgDumpAvailable() {
		cap.Available = false
		cap.Reason = "pg_dump not installed"
		return cap
	}

	cap.Available = true
	return cap
}

// detectMySQLCapability checks if MySQL backup is available.
func (d *CapabilityDetector) detectMySQLCapability() BackupCapability {
	cap := BackupCapability{
		Type:                TypeMySQL,
		SupportsIncremental: false,
		SupportsScheduled:   true,
		RequiresCredentials: true,
		Dependencies:        []string{"mysqldump"},
	}

	// Check if mysqldump is available
	if !isMySQLDumpAvailable() {
		cap.Available = false
		cap.Reason = "mysqldump not installed"
		return cap
	}

	cap.Available = true
	return cap
}

// buildCapabilitySummary builds the summary lists of available and unavailable types.
func (d *CapabilityDetector) buildCapabilitySummary(caps *BackupCapabilities) {
	allCaps := []BackupCapability{
		caps.AgentConfig,
		caps.AgentLogs,
		caps.SystemState,
		caps.SoftwareInventory,
		caps.ComplianceResults,
		caps.FilesAndFolders,
		caps.DockerContainer,
		caps.DockerVolume,
		caps.DockerImage,
		caps.DockerCompose,
		caps.ProxmoxVM,
		caps.ProxmoxLXC,
		caps.ProxmoxConfig,
		caps.HyperVVM,
		caps.HyperVCheckpoint,
		caps.HyperVConfig,
		caps.PostgreSQL,
		caps.MySQL,
	}

	for _, cap := range allCaps {
		if cap.Available {
			caps.AvailableTypes = append(caps.AvailableTypes, string(cap.Type))
		} else {
			caps.UnavailableTypes = append(caps.UnavailableTypes, string(cap.Type))
		}
	}
}

// Helper functions to check for dependencies

func isDockerAvailable() bool {
	cmd := exec.Command("docker", "info")
	err := cmd.Run()
	return err == nil
}

func isDockerComposeAvailable() bool {
	// Try docker compose (v2) first
	cmd := exec.Command("docker", "compose", "version")
	if err := cmd.Run(); err == nil {
		return true
	}

	// Fall back to docker-compose (v1)
	cmd = exec.Command("docker-compose", "version")
	return cmd.Run() == nil
}

func isProxmoxHost() bool {
	// Check for Proxmox-specific files
	cmd := exec.Command("test", "-f", "/etc/pve/local/pve-ssl.pem")
	if err := cmd.Run(); err == nil {
		return true
	}

	// Alternative: check for pveversion command
	cmd = exec.Command("which", "pveversion")
	return cmd.Run() == nil
}

func isPveshAvailable() bool {
	cmd := exec.Command("which", "pvesh")
	return cmd.Run() == nil
}

func isHyperVAvailable() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	// Check using PowerShell
	cmd := exec.Command("powershell", "-Command",
		"Get-WindowsFeature -Name Hyper-V | Where-Object {$_.Installed -eq $true}")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.Contains(string(output), "Hyper-V")
}

func isPgDumpAvailable() bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("where", "pg_dump")
	} else {
		cmd = exec.Command("which", "pg_dump")
	}
	return cmd.Run() == nil
}

func isMySQLDumpAvailable() bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("where", "mysqldump")
	} else {
		cmd = exec.Command("which", "mysqldump")
	}
	return cmd.Run() == nil
}

// GetRegisteredCapabilities returns capabilities for registered collectors only.
func (r *CollectorRegistry) GetRegisteredCapabilities() []BackupCapability {
	caps := make([]BackupCapability, 0, len(r.collectors))

	for backupType, collector := range r.collectors {
		cap := BackupCapability{
			Type:                backupType,
			Available:           true,
			SupportsScheduled:   true,
			RequiresCredentials: false,
		}

		// Check if collector supports incremental backups
		if incCollector, ok := collector.(IncrementalCollector); ok {
			cap.SupportsIncremental = incCollector.SupportsIncremental()
		}

		// Set credentials requirement based on type
		switch backupType {
		case TypePostgreSQL, TypeMySQL:
			cap.RequiresCredentials = true
		case TypeProxmoxVM, TypeProxmoxLXC, TypeProxmoxConfig:
			cap.RequiresCredentials = true
		}

		caps = append(caps, cap)
	}

	return caps
}
