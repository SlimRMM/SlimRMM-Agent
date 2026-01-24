// Package hyperv provides backup operations for Hyper-V VMs via Export/Import.
package hyperv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ExportRequest represents a VM export request.
type ExportRequest struct {
	VMName      string `json:"vm_name"`
	VMID        string `json:"vm_id,omitempty"`
	ExportPath  string `json:"export_path"`
	CaptureLive bool   `json:"capture_live,omitempty"` // Use live export (VSS)
	Timeout     int    `json:"timeout,omitempty"`      // Timeout in seconds
}

// ExportResult represents the result of a VM export operation.
type ExportResult struct {
	Success     bool   `json:"success"`
	VMName      string `json:"vm_name"`
	VMID        string `json:"vm_id,omitempty"`
	ExportPath  string `json:"export_path"`
	VMCXPath    string `json:"vmcx_path,omitempty"`
	Size        int64  `json:"size,omitempty"`
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at,omitempty"`
	Duration    int64  `json:"duration_ms"`
	Error       string `json:"error,omitempty"`
}

// ImportRequest represents a VM import request.
type ImportRequest struct {
	VMCXPath        string `json:"vmcx_path"`
	DestinationPath string `json:"destination_path,omitempty"`
	GenerateNewID   bool   `json:"generate_new_id"` // Generate new VMID
	Copy            bool   `json:"copy"`            // Copy files instead of registering in-place
	VHDDestination  string `json:"vhd_destination,omitempty"`
	Timeout         int    `json:"timeout,omitempty"`
}

// ImportResult represents the result of a VM import operation.
type ImportResult struct {
	Success     bool   `json:"success"`
	VMName      string `json:"vm_name,omitempty"`
	VMID        string `json:"vm_id,omitempty"`
	VMCXPath    string `json:"vmcx_path"`
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at,omitempty"`
	Duration    int64  `json:"duration_ms"`
	Error       string `json:"error,omitempty"`
}

// BackupRequest represents a Hyper-V backup request (wrapper for export with additional options).
type BackupRequest struct {
	VMName           string `json:"vm_name"`
	VMID             string `json:"vm_id,omitempty"`
	BackupPath       string `json:"backup_path"`
	UseVSS           bool   `json:"use_vss"`           // Use Volume Shadow Copy for live backup
	CreateCheckpoint bool   `json:"create_checkpoint"` // Create checkpoint before backup
	CheckpointName   string `json:"checkpoint_name,omitempty"`
	Timeout          int    `json:"timeout,omitempty"`
}

// BackupResult represents the result of a backup operation.
type BackupResult struct {
	Success        bool   `json:"success"`
	VMName         string `json:"vm_name"`
	VMID           string `json:"vm_id,omitempty"`
	BackupPath     string `json:"backup_path"`
	CheckpointName string `json:"checkpoint_name,omitempty"`
	ExportPath     string `json:"export_path,omitempty"`
	Size           int64  `json:"size,omitempty"`
	StartedAt      string `json:"started_at"`
	CompletedAt    string `json:"completed_at,omitempty"`
	Duration       int64  `json:"duration_ms"`
	Error          string `json:"error,omitempty"`
}

const defaultBackupTimeout = 30 * time.Minute

// ExportVM exports a VM to a specified path.
func (c *Client) ExportVM(ctx context.Context, req ExportRequest) *ExportResult {
	start := time.Now()
	result := &ExportResult{
		VMName:     req.VMName,
		VMID:       req.VMID,
		ExportPath: req.ExportPath,
		StartedAt:  start.Format(time.RFC3339),
	}

	// Set timeout
	timeout := defaultBackupTimeout
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Resolve VM name if only ID is provided
	vmName := req.VMName
	if vmName == "" && req.VMID != "" {
		vm, err := c.GetVMByID(ctx, req.VMID)
		if err != nil {
			result.Error = fmt.Sprintf("failed to find VM with ID %s: %v", req.VMID, err)
			result.Duration = time.Since(start).Milliseconds()
			return result
		}
		vmName = vm.Name
		result.VMName = vmName
	}

	if vmName == "" {
		result.Error = "vm_name or vm_id is required"
		result.Duration = time.Since(start).Milliseconds()
		return result
	}

	if req.ExportPath == "" {
		result.Error = "export_path is required"
		result.Duration = time.Since(start).Milliseconds()
		return result
	}

	// Create export directory if it doesn't exist
	if err := os.MkdirAll(req.ExportPath, 0755); err != nil {
		result.Error = fmt.Sprintf("failed to create export directory: %v", err)
		result.Duration = time.Since(start).Milliseconds()
		return result
	}

	// Build export command
	var psCmd string
	if req.CaptureLive {
		// Use VSS for live export
		psCmd = fmt.Sprintf("Export-VM -Name %s -Path %s -CaptureLiveState CaptureSavedState",
			PSString(vmName), PSString(req.ExportPath))
	} else {
		psCmd = fmt.Sprintf("Export-VM -Name %s -Path %s",
			PSString(vmName), PSString(req.ExportPath))
	}

	_, err := c.ExecutePS(ctx, psCmd)
	result.Duration = time.Since(start).Milliseconds()
	result.CompletedAt = time.Now().Format(time.RFC3339)

	if err != nil {
		result.Error = err.Error()
		return result
	}

	// Find the exported VMCX file
	vmExportPath := filepath.Join(req.ExportPath, vmName)
	vmcxPath := filepath.Join(vmExportPath, "Virtual Machines")

	// Get directory size
	var totalSize int64
	filepath.Walk(vmExportPath, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})
	result.Size = totalSize

	// Find VMCX file
	entries, err := os.ReadDir(vmcxPath)
	if err == nil {
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) == ".vmcx" {
				result.VMCXPath = filepath.Join(vmcxPath, entry.Name())
				break
			}
		}
	}

	result.Success = true
	return result
}

// ImportVM imports a VM from an exported VMCX file.
func (c *Client) ImportVM(ctx context.Context, req ImportRequest) *ImportResult {
	start := time.Now()
	result := &ImportResult{
		VMCXPath:  req.VMCXPath,
		StartedAt: start.Format(time.RFC3339),
	}

	// Set timeout
	timeout := defaultBackupTimeout
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if req.VMCXPath == "" {
		result.Error = "vmcx_path is required"
		result.Duration = time.Since(start).Milliseconds()
		return result
	}

	// Check if VMCX file exists
	if _, err := os.Stat(req.VMCXPath); os.IsNotExist(err) {
		result.Error = fmt.Sprintf("VMCX file not found: %s", req.VMCXPath)
		result.Duration = time.Since(start).Milliseconds()
		return result
	}

	// Build import command
	var cmdParts []string
	cmdParts = append(cmdParts, fmt.Sprintf("$vm = Import-VM -Path %s", PSString(req.VMCXPath)))

	if req.GenerateNewID {
		cmdParts = []string{fmt.Sprintf("$vm = Import-VM -Path %s -GenerateNewId", PSString(req.VMCXPath))}
	}

	if req.Copy {
		cmdParts = []string{fmt.Sprintf("$vm = Import-VM -Path %s -Copy", PSString(req.VMCXPath))}
		if req.GenerateNewID {
			cmdParts = []string{fmt.Sprintf("$vm = Import-VM -Path %s -Copy -GenerateNewId", PSString(req.VMCXPath))}
		}
		if req.VHDDestination != "" {
			cmdParts = []string{fmt.Sprintf("$vm = Import-VM -Path %s -Copy -VhdDestinationPath %s -GenerateNewId",
				PSString(req.VMCXPath), PSString(req.VHDDestination))}
		}
	}

	// Add return of VM info
	cmdParts = append(cmdParts, `
	[PSCustomObject]@{
		VMId = $vm.Id.ToString()
		Name = $vm.Name
	} | ConvertTo-Json`)

	psCmd := fmt.Sprintf("%s; %s", cmdParts[0], cmdParts[len(cmdParts)-1])

	type importOutput struct {
		VMId string `json:"VMId"`
		Name string `json:"Name"`
	}

	var output importOutput
	if err := c.ExecutePSWithJSON(ctx, psCmd, &output); err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start).Milliseconds()
		return result
	}

	result.Success = true
	result.VMName = output.Name
	result.VMID = output.VMId
	result.Duration = time.Since(start).Milliseconds()
	result.CompletedAt = time.Now().Format(time.RFC3339)

	return result
}

// CreateBackup creates a full backup of a VM using export.
func (c *Client) CreateBackup(ctx context.Context, req BackupRequest) *BackupResult {
	start := time.Now()
	result := &BackupResult{
		VMName:     req.VMName,
		VMID:       req.VMID,
		BackupPath: req.BackupPath,
		StartedAt:  start.Format(time.RFC3339),
	}

	// Set timeout
	timeout := defaultBackupTimeout
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Resolve VM name if only ID is provided
	vmName := req.VMName
	if vmName == "" && req.VMID != "" {
		vm, err := c.GetVMByID(ctx, req.VMID)
		if err != nil {
			result.Error = fmt.Sprintf("failed to find VM with ID %s: %v", req.VMID, err)
			result.Duration = time.Since(start).Milliseconds()
			return result
		}
		vmName = vm.Name
		result.VMName = vmName
		result.VMID = vm.ID
	}

	if vmName == "" {
		result.Error = "vm_name or vm_id is required"
		result.Duration = time.Since(start).Milliseconds()
		return result
	}

	// Create checkpoint before backup if requested
	if req.CreateCheckpoint {
		checkpointName := req.CheckpointName
		if checkpointName == "" {
			checkpointName = fmt.Sprintf("Backup_%s", time.Now().Format("20060102_150405"))
		}

		cpResult := c.CreateCheckpoint(ctx, CheckpointRequest{
			VMName:         vmName,
			CheckpointName: checkpointName,
		})

		if !cpResult.Success {
			result.Error = fmt.Sprintf("failed to create checkpoint: %s", cpResult.Error)
			result.Duration = time.Since(start).Milliseconds()
			return result
		}

		result.CheckpointName = checkpointName
	}

	// Create timestamped backup directory
	backupDir := filepath.Join(req.BackupPath, time.Now().Format("20060102_150405"))

	// Export the VM
	exportResult := c.ExportVM(ctx, ExportRequest{
		VMName:      vmName,
		ExportPath:  backupDir,
		CaptureLive: req.UseVSS,
	})

	if !exportResult.Success {
		result.Error = exportResult.Error
		result.Duration = time.Since(start).Milliseconds()
		return result
	}

	result.Success = true
	result.ExportPath = exportResult.ExportPath
	result.Size = exportResult.Size
	result.Duration = time.Since(start).Milliseconds()
	result.CompletedAt = time.Now().Format(time.RFC3339)

	return result
}

// BulkBackup creates backups for multiple VMs.
func (c *Client) BulkBackup(ctx context.Context, vmNames []string, backupPath string, useVSS bool) []BackupResult {
	results := make([]BackupResult, 0, len(vmNames))

	for _, vmName := range vmNames {
		result := c.CreateBackup(ctx, BackupRequest{
			VMName:     vmName,
			BackupPath: backupPath,
			UseVSS:     useVSS,
		})
		results = append(results, *result)
	}

	return results
}

// ListExports lists exported VMs in a directory.
func (c *Client) ListExports(ctx context.Context, exportPath string) ([]ExportInfo, error) {
	exports := make([]ExportInfo, 0)

	entries, err := os.ReadDir(exportPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read export directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		vmPath := filepath.Join(exportPath, entry.Name())
		vmcxPath := filepath.Join(vmPath, "Virtual Machines")

		// Check if this looks like an exported VM
		if _, err := os.Stat(vmcxPath); os.IsNotExist(err) {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Find VMCX file
		var vmcxFile string
		vmcxEntries, err := os.ReadDir(vmcxPath)
		if err == nil {
			for _, vmcxEntry := range vmcxEntries {
				if filepath.Ext(vmcxEntry.Name()) == ".vmcx" {
					vmcxFile = filepath.Join(vmcxPath, vmcxEntry.Name())
					break
				}
			}
		}

		// Calculate total size
		var totalSize int64
		filepath.Walk(vmPath, func(path string, fi os.FileInfo, err error) error {
			if err == nil && !fi.IsDir() {
				totalSize += fi.Size()
			}
			return nil
		})

		exports = append(exports, ExportInfo{
			VMName:     entry.Name(),
			ExportPath: vmPath,
			VMCXPath:   vmcxFile,
			Size:       totalSize,
			ExportedAt: info.ModTime(),
		})
	}

	return exports, nil
}

// ExportInfo represents information about an exported VM.
type ExportInfo struct {
	VMName     string    `json:"vm_name"`
	ExportPath string    `json:"export_path"`
	VMCXPath   string    `json:"vmcx_path"`
	Size       int64     `json:"size"`
	ExportedAt time.Time `json:"exported_at"`
}
