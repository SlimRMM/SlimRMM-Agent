package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"time"
)

// vmNamePattern validates VM names to prevent command injection.
var vmNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9\s\-_.]*$`)

// HyperVVMCollector collects Hyper-V VM backups.
type HyperVVMCollector struct {
	config AgentConfig
	logger Logger
}

// NewHyperVVMCollector creates a new Hyper-V VM collector.
func NewHyperVVMCollector(config AgentConfig, logger Logger) *HyperVVMCollector {
	return &HyperVVMCollector{config: config, logger: logger}
}

// Type returns the backup type.
func (c *HyperVVMCollector) Type() BackupType {
	return TypeHyperVVM
}

// Collect collects a Hyper-V VM backup.
func (c *HyperVVMCollector) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	if runtime.GOOS != "windows" {
		return nil, &ErrPlatformUnsupported{
			Feature:  "Hyper-V backup",
			Platform: runtime.GOOS,
		}
	}

	if config.VMName == "" {
		return nil, &ErrMissingParameter{
			Parameter: "vm_name",
			Context:   "hyperv_vm backup",
		}
	}

	// Validate VM name to prevent command injection
	if !vmNamePattern.MatchString(config.VMName) {
		return nil, &ErrCollectionFailed{
			Type:   TypeHyperVVM,
			Reason: "invalid VM name: contains disallowed characters",
		}
	}

	// Get VM info
	vmInfo, err := c.getVMInfo(ctx, config.VMName)
	if err != nil {
		return nil, err
	}

	// Determine export path
	exportPath := config.ExportPath
	if exportPath == "" {
		exportPath = filepath.Join(os.TempDir(), "hyperv-backup-"+config.VMName)
	}

	// Create export directory
	if err := os.MkdirAll(exportPath, 0755); err != nil {
		return nil, &ErrCollectionFailed{
			Type:   TypeHyperVVM,
			Reason: "failed to create export directory",
			Err:    err,
		}
	}
	defer os.RemoveAll(exportPath)

	// Export VM
	if err := c.exportVM(ctx, config.VMName, exportPath); err != nil {
		return nil, err
	}

	// Archive the export
	archiveData, err := c.archiveExport(exportPath)
	if err != nil {
		return nil, err
	}

	backupData := map[string]interface{}{
		"backup_type":  "hyperv_vm",
		"vm_name":      config.VMName,
		"vm_info":      vmInfo,
		"archive_size": len(archiveData),
		"archive_data": base64.StdEncoding.EncodeToString(archiveData),
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"agent_uuid":   config.AgentUUID,
	}

	return json.Marshal(backupData)
}

// getVMInfo gets information about a Hyper-V VM.
func (c *HyperVVMCollector) getVMInfo(ctx context.Context, vmName string) (map[string]interface{}, error) {
	script := fmt.Sprintf(`Get-VM -Name '%s' | Select-Object Name, State, CPUUsage, MemoryAssigned, Uptime, Status | ConvertTo-Json`, escapePowerShellString(vmName))

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		return nil, &ErrCollectionFailed{
			Type:   TypeHyperVVM,
			Reason: "failed to get VM info",
			Err:    err,
		}
	}

	var vmInfo map[string]interface{}
	if err := json.Unmarshal(output, &vmInfo); err != nil {
		return nil, &ErrCollectionFailed{
			Type:   TypeHyperVVM,
			Reason: "failed to parse VM info",
			Err:    err,
		}
	}

	return vmInfo, nil
}

// exportVM exports a Hyper-V VM.
func (c *HyperVVMCollector) exportVM(ctx context.Context, vmName, exportPath string) error {
	script := fmt.Sprintf(`Export-VM -Name '%s' -Path '%s'`, escapePowerShellString(vmName), escapePowerShellString(exportPath))

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err := cmd.Run(); err != nil {
		return &ErrCollectionFailed{
			Type:   TypeHyperVVM,
			Reason: "failed to export VM",
			Err:    err,
		}
	}

	return nil
}

// archiveExport creates a tar.gz archive of the export directory.
func (c *HyperVVMCollector) archiveExport(exportPath string) ([]byte, error) {
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)

	err := filepath.Walk(exportPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return nil
		}

		relPath, _ := filepath.Rel(exportPath, path)
		header.Name = relPath

		if err := tarWriter.WriteHeader(header); err != nil {
			return nil
		}

		if !info.IsDir() && info.Mode().IsRegular() {
			file, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer file.Close()

			if _, err := io.Copy(tarWriter, file); err != nil {
				return nil
			}
		}

		return nil
	})

	if err != nil {
		return nil, &ErrCollectionFailed{
			Type:   TypeHyperVVM,
			Reason: "failed to archive export",
			Err:    err,
		}
	}

	if err := tarWriter.Close(); err != nil {
		return nil, &ErrCollectionFailed{
			Type:   TypeHyperVVM,
			Reason: "failed to close tar writer",
			Err:    err,
		}
	}

	if err := gzWriter.Close(); err != nil {
		return nil, &ErrCollectionFailed{
			Type:   TypeHyperVVM,
			Reason: "failed to close gzip writer",
			Err:    err,
		}
	}

	return buf.Bytes(), nil
}

// HyperVCheckpointCollector collects Hyper-V checkpoint backups.
type HyperVCheckpointCollector struct {
	config AgentConfig
	logger Logger
}

// NewHyperVCheckpointCollector creates a new Hyper-V checkpoint collector.
func NewHyperVCheckpointCollector(config AgentConfig, logger Logger) *HyperVCheckpointCollector {
	return &HyperVCheckpointCollector{config: config, logger: logger}
}

// Type returns the backup type.
func (c *HyperVCheckpointCollector) Type() BackupType {
	return TypeHyperVCheckpoint
}

// Collect creates a Hyper-V checkpoint.
func (c *HyperVCheckpointCollector) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	if runtime.GOOS != "windows" {
		return nil, &ErrPlatformUnsupported{
			Feature:  "Hyper-V backup",
			Platform: runtime.GOOS,
		}
	}

	if config.VMName == "" {
		return nil, &ErrMissingParameter{
			Parameter: "vm_name",
			Context:   "hyperv_checkpoint backup",
		}
	}

	// Validate VM name
	if !vmNamePattern.MatchString(config.VMName) {
		return nil, &ErrCollectionFailed{
			Type:   TypeHyperVCheckpoint,
			Reason: "invalid VM name: contains disallowed characters",
		}
	}

	// Generate checkpoint name if not provided
	checkpointName := config.CheckpointName
	if checkpointName == "" {
		checkpointName = fmt.Sprintf("Backup-%s", time.Now().Format("20060102-150405"))
	}

	// Validate checkpoint name
	if !vmNamePattern.MatchString(checkpointName) {
		return nil, &ErrCollectionFailed{
			Type:   TypeHyperVCheckpoint,
			Reason: "invalid checkpoint name: contains disallowed characters",
		}
	}

	// Create checkpoint
	if err := c.createCheckpoint(ctx, config.VMName, checkpointName); err != nil {
		return nil, err
	}

	backupData := map[string]interface{}{
		"backup_type":     "hyperv_checkpoint",
		"vm_name":         config.VMName,
		"checkpoint_name": checkpointName,
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
		"agent_uuid":      config.AgentUUID,
	}

	return json.Marshal(backupData)
}

// createCheckpoint creates a Hyper-V checkpoint.
func (c *HyperVCheckpointCollector) createCheckpoint(ctx context.Context, vmName, checkpointName string) error {
	script := fmt.Sprintf(`Checkpoint-VM -Name '%s' -SnapshotName '%s'`,
		escapePowerShellString(vmName),
		escapePowerShellString(checkpointName))

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err := cmd.Run(); err != nil {
		return &ErrCollectionFailed{
			Type:   TypeHyperVCheckpoint,
			Reason: "failed to create checkpoint",
			Err:    err,
		}
	}

	return nil
}

// HyperVConfigCollector collects Hyper-V configuration backups.
type HyperVConfigCollector struct {
	config AgentConfig
	logger Logger
}

// NewHyperVConfigCollector creates a new Hyper-V config collector.
func NewHyperVConfigCollector(config AgentConfig, logger Logger) *HyperVConfigCollector {
	return &HyperVConfigCollector{config: config, logger: logger}
}

// Type returns the backup type.
func (c *HyperVConfigCollector) Type() BackupType {
	return TypeHyperVConfig
}

// Collect collects Hyper-V host configuration.
func (c *HyperVConfigCollector) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	if runtime.GOOS != "windows" {
		return nil, &ErrPlatformUnsupported{
			Feature:  "Hyper-V backup",
			Platform: runtime.GOOS,
		}
	}

	// Get Hyper-V host settings
	hostSettings, err := c.getHostSettings(ctx)
	if err != nil {
		return nil, err
	}

	// Get list of VMs
	vms, err := c.listVMs(ctx)
	if err != nil {
		return nil, err
	}

	// Get virtual switches
	switches, err := c.listVirtualSwitches(ctx)
	if err != nil {
		return nil, err
	}

	backupData := map[string]interface{}{
		"backup_type":      "hyperv_config",
		"host_settings":    hostSettings,
		"virtual_machines": vms,
		"virtual_switches": switches,
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
		"agent_uuid":       config.AgentUUID,
	}

	return json.Marshal(backupData)
}

// getHostSettings gets Hyper-V host settings.
func (c *HyperVConfigCollector) getHostSettings(ctx context.Context) (map[string]interface{}, error) {
	script := `Get-VMHost | Select-Object * | ConvertTo-Json -Depth 3`

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		return nil, &ErrCollectionFailed{
			Type:   TypeHyperVConfig,
			Reason: "failed to get Hyper-V host settings",
			Err:    err,
		}
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(output, &settings); err != nil {
		return nil, nil // Return nil on parse error, continue with other data
	}

	return settings, nil
}

// listVMs lists all Hyper-V VMs.
func (c *HyperVConfigCollector) listVMs(ctx context.Context) ([]map[string]interface{}, error) {
	script := `Get-VM | Select-Object Name, State, CPUUsage, MemoryAssigned, Uptime, Status, Generation, Version | ConvertTo-Json`

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		return nil, nil // Return nil on error, continue with other data
	}

	var vms []map[string]interface{}
	if err := json.Unmarshal(output, &vms); err != nil {
		// Try as single object
		var vm map[string]interface{}
		if err := json.Unmarshal(output, &vm); err == nil {
			vms = []map[string]interface{}{vm}
		}
	}

	return vms, nil
}

// listVirtualSwitches lists all Hyper-V virtual switches.
func (c *HyperVConfigCollector) listVirtualSwitches(ctx context.Context) ([]map[string]interface{}, error) {
	script := `Get-VMSwitch | Select-Object Name, SwitchType, NetAdapterInterfaceDescription | ConvertTo-Json`

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		return nil, nil // Return nil on error, continue with other data
	}

	var switches []map[string]interface{}
	if err := json.Unmarshal(output, &switches); err != nil {
		// Try as single object
		var sw map[string]interface{}
		if err := json.Unmarshal(output, &sw); err == nil {
			switches = []map[string]interface{}{sw}
		}
	}

	return switches, nil
}

// escapePowerShellString escapes a string for safe use in PowerShell single-quoted strings.
func escapePowerShellString(s string) string {
	// In PowerShell single-quoted strings, single quotes are escaped by doubling them
	return regexp.MustCompile(`'`).ReplaceAllString(s, "''")
}
