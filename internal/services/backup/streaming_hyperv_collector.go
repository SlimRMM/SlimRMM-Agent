// Package backup provides streaming Hyper-V backup collectors.
// These collectors stream VM exports directly to the upload destination
// without loading entire VM data into memory.
//
//go:build windows
// +build windows

package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"
)

// vmNameValidator validates VM names to prevent command injection.
var vmNameValidator = regexp.MustCompile(`^[a-zA-Z0-9_\-\s\.]+$`)

// StreamingHyperVVMCollector collects Hyper-V VM backups using streaming.
type StreamingHyperVVMCollector struct {
	logger  *slog.Logger
	tempDir string
}

// NewStreamingHyperVVMCollector creates a new streaming Hyper-V VM collector.
func NewStreamingHyperVVMCollector(logger *slog.Logger, tempDir string) *StreamingHyperVVMCollector {
	if logger == nil {
		logger = slog.Default()
	}
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	return &StreamingHyperVVMCollector{
		logger:  logger,
		tempDir: tempDir,
	}
}

// Type returns the backup type.
func (c *StreamingHyperVVMCollector) Type() BackupType {
	return TypeHyperVVM
}

// SupportsStreaming returns true as this collector supports streaming.
func (c *StreamingHyperVVMCollector) SupportsStreaming() bool {
	return true
}

// CollectStream writes Hyper-V VM export directly to the writer.
// Uses a temporary directory for the export, then streams the tar to the writer.
func (c *StreamingHyperVVMCollector) CollectStream(ctx context.Context, config CollectorConfig, w io.Writer) (int64, error) {
	if !isHyperVAvailable() {
		return 0, &ErrFeatureUnavailable{Feature: "Hyper-V"}
	}

	if config.VMName == "" {
		return 0, &ErrMissingParameter{
			Parameter: "vm_name",
			Context:   "hyperv_vm backup",
		}
	}

	// Validate VM name to prevent command injection
	if !isValidVMName(config.VMName) {
		return 0, fmt.Errorf("invalid VM name: contains disallowed characters")
	}

	c.logger.Info("starting streaming Hyper-V VM backup",
		"vm_name", config.VMName,
	)

	// Get VM info
	vmInfo, err := c.getVMInfo(ctx, config.VMName)
	if err != nil {
		return 0, fmt.Errorf("getting VM info: %w", err)
	}

	// Create metadata
	metadata := map[string]interface{}{
		"backup_type": "hyperv_vm",
		"vm_name":     config.VMName,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"agent_uuid":  config.AgentUUID,
		"version":     2, // Version 2 = streaming format
		"vm_info":     vmInfo,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return 0, fmt.Errorf("marshaling metadata: %w", err)
	}

	// Write metadata length + metadata
	metaLen := uint32(len(metadataBytes))
	if _, err := w.Write([]byte{byte(metaLen >> 24), byte(metaLen >> 16), byte(metaLen >> 8), byte(metaLen)}); err != nil {
		return 0, fmt.Errorf("writing metadata length: %w", err)
	}
	if _, err := w.Write(metadataBytes); err != nil {
		return 0, fmt.Errorf("writing metadata: %w", err)
	}

	var totalWritten int64 = 4 + int64(len(metadataBytes))

	// Create temporary export directory
	exportDir := filepath.Join(c.tempDir, fmt.Sprintf("hyperv_export_%d", time.Now().UnixNano()))
	if err := os.MkdirAll(exportDir, 0700); err != nil {
		return totalWritten, fmt.Errorf("creating export directory: %w", err)
	}
	defer os.RemoveAll(exportDir)

	// Export VM to temporary directory
	if err := c.exportVM(ctx, config.VMName, exportDir); err != nil {
		return totalWritten, fmt.Errorf("exporting VM: %w", err)
	}

	// Stream tar of export directory directly to writer
	exportBytes, err := c.streamExportTar(ctx, exportDir, config.VMName, w)
	if err != nil {
		return totalWritten, fmt.Errorf("streaming export tar: %w", err)
	}

	totalWritten += exportBytes

	c.logger.Info("Hyper-V VM backup streaming complete",
		"vm_name", config.VMName,
		"total_bytes", totalWritten,
	)

	return totalWritten, nil
}

// getVMInfo gets VM information via PowerShell.
func (c *StreamingHyperVVMCollector) getVMInfo(ctx context.Context, vmName string) (map[string]interface{}, error) {
	escapedName := escapePowerShellString(vmName)
	script := fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		Get-VM -Name '%s' | Select-Object Name, State, Generation, ProcessorCount,
			@{N='MemoryMB';E={$_.MemoryAssigned/1MB}},
			@{N='DynamicMemory';E={$_.DynamicMemoryEnabled}},
			Uptime, Status | ConvertTo-Json -Depth 2
	`, escapedName)

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("getting VM info: %w", err)
	}

	var vmInfo map[string]interface{}
	if err := json.Unmarshal(output, &vmInfo); err != nil {
		return nil, fmt.Errorf("parsing VM info: %w", err)
	}

	return vmInfo, nil
}

// exportVM exports the VM to a directory.
func (c *StreamingHyperVVMCollector) exportVM(ctx context.Context, vmName, exportDir string) error {
	escapedName := escapePowerShellString(vmName)
	escapedDir := escapePowerShellString(exportDir)

	script := fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		$vm = Get-VM -Name '%s'
		if ($vm.State -eq 'Running') {
			# Use VSS for consistent backup without stopping VM
			Export-VM -Name '%s' -Path '%s' -CaptureLiveState $true
		} else {
			Export-VM -Name '%s' -Path '%s'
		}
	`, escapedName, escapedName, escapedDir, escapedName, escapedDir)

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("export failed: %w - %s", err, string(output))
	}

	return nil
}

// streamExportTar streams tar of export directory to writer.
func (c *StreamingHyperVVMCollector) streamExportTar(ctx context.Context, exportDir, vmName string, w io.Writer) (int64, error) {
	vmExportPath := filepath.Join(exportDir, vmName)

	// Use tar command to stream the directory
	// On Windows, we use the built-in tar (available since Windows 10 1803)
	cmd := exec.CommandContext(ctx, "tar", "-cf", "-", "-C", vmExportPath, ".")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("creating stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return 0, fmt.Errorf("creating stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("starting tar: %w", err)
	}

	// Stream with fixed-size buffer
	buf := make([]byte, 8*1024*1024)
	n, copyErr := io.CopyBuffer(w, stdout, buf)

	stderrBytes, _ := io.ReadAll(io.LimitReader(stderr, MaxResponseBodySize))

	if err := cmd.Wait(); err != nil {
		if len(stderrBytes) > 0 {
			return n, fmt.Errorf("tar failed: %w - %s", err, string(stderrBytes))
		}
		return n, fmt.Errorf("tar failed: %w", err)
	}

	if copyErr != nil {
		return n, fmt.Errorf("streaming tar data: %w", copyErr)
	}

	return n, nil
}

// StreamingHyperVCheckpointCollector collects Hyper-V checkpoint backups.
type StreamingHyperVCheckpointCollector struct {
	logger *slog.Logger
}

// NewStreamingHyperVCheckpointCollector creates a new streaming Hyper-V checkpoint collector.
func NewStreamingHyperVCheckpointCollector(logger *slog.Logger) *StreamingHyperVCheckpointCollector {
	if logger == nil {
		logger = slog.Default()
	}
	return &StreamingHyperVCheckpointCollector{logger: logger}
}

// Type returns the backup type.
func (c *StreamingHyperVCheckpointCollector) Type() BackupType {
	return TypeHyperVCheckpoint
}

// SupportsStreaming returns true as this collector supports streaming.
func (c *StreamingHyperVCheckpointCollector) SupportsStreaming() bool {
	return true
}

// CollectStream creates a checkpoint and returns metadata.
func (c *StreamingHyperVCheckpointCollector) CollectStream(ctx context.Context, config CollectorConfig, w io.Writer) (int64, error) {
	if !isHyperVAvailable() {
		return 0, &ErrFeatureUnavailable{Feature: "Hyper-V"}
	}

	if config.VMName == "" {
		return 0, &ErrMissingParameter{
			Parameter: "vm_name",
			Context:   "hyperv_checkpoint backup",
		}
	}

	if !isValidVMName(config.VMName) {
		return 0, fmt.Errorf("invalid VM name: contains disallowed characters")
	}

	c.logger.Info("starting streaming Hyper-V checkpoint backup",
		"vm_name", config.VMName,
	)

	// Generate checkpoint name if not provided
	checkpointName := config.CheckpointName
	if checkpointName == "" {
		checkpointName = fmt.Sprintf("SlimRMM_Backup_%s", time.Now().Format("20060102_150405"))
	}

	if !isValidVMName(checkpointName) {
		return 0, fmt.Errorf("invalid checkpoint name: contains disallowed characters")
	}

	// Create checkpoint
	checkpointInfo, err := c.createCheckpoint(ctx, config.VMName, checkpointName)
	if err != nil {
		return 0, fmt.Errorf("creating checkpoint: %w", err)
	}

	// Create metadata
	metadata := map[string]interface{}{
		"backup_type":     "hyperv_checkpoint",
		"vm_name":         config.VMName,
		"checkpoint_name": checkpointName,
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
		"agent_uuid":      config.AgentUUID,
		"version":         2,
		"checkpoint_info": checkpointInfo,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return 0, fmt.Errorf("marshaling metadata: %w", err)
	}

	// Write metadata length + metadata
	metaLen := uint32(len(metadataBytes))
	if _, err := w.Write([]byte{byte(metaLen >> 24), byte(metaLen >> 16), byte(metaLen >> 8), byte(metaLen)}); err != nil {
		return 0, fmt.Errorf("writing metadata length: %w", err)
	}
	if _, err := w.Write(metadataBytes); err != nil {
		return 0, fmt.Errorf("writing metadata: %w", err)
	}

	totalWritten := int64(4 + len(metadataBytes))

	c.logger.Info("Hyper-V checkpoint backup streaming complete",
		"vm_name", config.VMName,
		"checkpoint_name", checkpointName,
		"total_bytes", totalWritten,
	)

	return totalWritten, nil
}

// createCheckpoint creates a VM checkpoint.
func (c *StreamingHyperVCheckpointCollector) createCheckpoint(ctx context.Context, vmName, checkpointName string) (interface{}, error) {
	escapedVM := escapePowerShellString(vmName)
	escapedCP := escapePowerShellString(checkpointName)

	script := fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		Checkpoint-VM -Name '%s' -SnapshotName '%s'
		Get-VMSnapshot -VMName '%s' -Name '%s' | ConvertTo-Json -Depth 3
	`, escapedVM, escapedCP, escapedVM, escapedCP)

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("creating checkpoint: %w", err)
	}

	var checkpointInfo interface{}
	if json.Unmarshal(output, &checkpointInfo) != nil {
		// Return raw output if JSON parsing fails
		return string(output), nil
	}

	return checkpointInfo, nil
}

// StreamingHyperVConfigCollector collects Hyper-V configuration backups.
type StreamingHyperVConfigCollector struct {
	logger *slog.Logger
}

// NewStreamingHyperVConfigCollector creates a new streaming Hyper-V config collector.
func NewStreamingHyperVConfigCollector(logger *slog.Logger) *StreamingHyperVConfigCollector {
	if logger == nil {
		logger = slog.Default()
	}
	return &StreamingHyperVConfigCollector{logger: logger}
}

// Type returns the backup type.
func (c *StreamingHyperVConfigCollector) Type() BackupType {
	return TypeHyperVConfig
}

// SupportsStreaming returns true as this collector supports streaming.
func (c *StreamingHyperVConfigCollector) SupportsStreaming() bool {
	return true
}

// CollectStream collects Hyper-V configuration data.
func (c *StreamingHyperVConfigCollector) CollectStream(ctx context.Context, config CollectorConfig, w io.Writer) (int64, error) {
	if !isHyperVAvailable() {
		return 0, &ErrFeatureUnavailable{Feature: "Hyper-V"}
	}

	c.logger.Info("starting streaming Hyper-V config backup")

	// Collect various Hyper-V configuration data
	vmsInfo := c.getVMsList(ctx)
	switchesInfo := c.getSwitchesInfo(ctx)
	hostInfo := c.getHostInfo(ctx)
	storageInfo := c.getStorageInfo(ctx)

	// Create metadata
	metadata := map[string]interface{}{
		"backup_type":   "hyperv_config",
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
		"agent_uuid":    config.AgentUUID,
		"version":       2,
		"vms":           vmsInfo,
		"switches":      switchesInfo,
		"host":          hostInfo,
		"storage_paths": storageInfo,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return 0, fmt.Errorf("marshaling metadata: %w", err)
	}

	// Write metadata length + metadata
	metaLen := uint32(len(metadataBytes))
	if _, err := w.Write([]byte{byte(metaLen >> 24), byte(metaLen >> 16), byte(metaLen >> 8), byte(metaLen)}); err != nil {
		return 0, fmt.Errorf("writing metadata length: %w", err)
	}
	if _, err := w.Write(metadataBytes); err != nil {
		return 0, fmt.Errorf("writing metadata: %w", err)
	}

	totalWritten := int64(4 + len(metadataBytes))

	c.logger.Info("Hyper-V config backup streaming complete",
		"total_bytes", totalWritten,
	)

	return totalWritten, nil
}

// getVMsList gets list of all VMs.
func (c *StreamingHyperVConfigCollector) getVMsList(ctx context.Context) interface{} {
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-VM | Select-Object Name, State, Generation, ProcessorCount | ConvertTo-Json -Depth 2")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var result interface{}
	json.Unmarshal(output, &result)
	return result
}

// getSwitchesInfo gets virtual switch information.
func (c *StreamingHyperVConfigCollector) getSwitchesInfo(ctx context.Context) interface{} {
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-VMSwitch | Select-Object Name, SwitchType, NetAdapterInterfaceDescription | ConvertTo-Json -Depth 2")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var result interface{}
	json.Unmarshal(output, &result)
	return result
}

// getHostInfo gets Hyper-V host information.
func (c *StreamingHyperVConfigCollector) getHostInfo(ctx context.Context) interface{} {
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-VMHost | Select-Object ComputerName, LogicalProcessorCount, MemoryCapacity | ConvertTo-Json -Depth 2")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var result interface{}
	json.Unmarshal(output, &result)
	return result
}

// getStorageInfo gets default storage paths.
func (c *StreamingHyperVConfigCollector) getStorageInfo(ctx context.Context) interface{} {
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-VMHost | Select-Object VirtualHardDiskPath, VirtualMachinePath | ConvertTo-Json -Depth 2")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var result interface{}
	json.Unmarshal(output, &result)
	return result
}

// isHyperVAvailable checks if Hyper-V is available.
func isHyperVAvailable() bool {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V | Select-Object -ExpandProperty State")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return string(output) == "Enabled\r\n" || string(output) == "Enabled"
}

// isValidVMName validates VM name to prevent command injection.
func isValidVMName(name string) bool {
	return vmNameValidator.MatchString(name)
}

// escapePowerShellString escapes a string for use in PowerShell.
func escapePowerShellString(s string) string {
	// Replace single quotes with two single quotes
	result := ""
	for _, c := range s {
		if c == '\'' {
			result += "''"
		} else {
			result += string(c)
		}
	}
	return result
}
