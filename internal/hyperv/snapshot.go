// Package hyperv provides checkpoint (snapshot) management for Hyper-V VMs.
package hyperv

import (
	"context"
	"fmt"
	"time"
)

// Checkpoint represents a Hyper-V VM checkpoint (snapshot).
type Checkpoint struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	VMName         string    `json:"vm_name"`
	VMID           string    `json:"vm_id"`
	CreationTime   time.Time `json:"creation_time"`
	ParentID       string    `json:"parent_id,omitempty"`
	CheckpointType string    `json:"checkpoint_type"` // Standard, Production
	Notes          string    `json:"notes,omitempty"`
}

// checkpointPSOutput is the JSON structure from Get-VMSnapshot.
type checkpointPSOutput struct {
	Id                 string `json:"Id"`
	Name               string `json:"Name"`
	VMName             string `json:"VMName"`
	VMId               string `json:"VMId"`
	CreationTime       string `json:"CreationTime"`
	ParentCheckpointId string `json:"ParentCheckpointId"`
	CheckpointType     int    `json:"CheckpointType"`
	Notes              string `json:"Notes"`
}

// CheckpointRequest represents a request to create a checkpoint.
type CheckpointRequest struct {
	VMName         string `json:"vm_name"`
	VMID           string `json:"vm_id,omitempty"`
	CheckpointName string `json:"checkpoint_name"`
	Notes          string `json:"notes,omitempty"`
}

// CheckpointResult represents the result of a checkpoint operation.
type CheckpointResult struct {
	Success    bool        `json:"success"`
	Message    string      `json:"message,omitempty"`
	Error      string      `json:"error,omitempty"`
	Checkpoint *Checkpoint `json:"checkpoint,omitempty"`
	Duration   int64       `json:"duration_ms"`
}

// RestoreCheckpointRequest represents a request to restore a checkpoint.
type RestoreCheckpointRequest struct {
	VMName         string `json:"vm_name"`
	VMID           string `json:"vm_id,omitempty"`
	CheckpointName string `json:"checkpoint_name"`
	CheckpointID   string `json:"checkpoint_id,omitempty"`
}

// DeleteCheckpointRequest represents a request to delete a checkpoint.
type DeleteCheckpointRequest struct {
	VMName             string `json:"vm_name"`
	VMID               string `json:"vm_id,omitempty"`
	CheckpointName     string `json:"checkpoint_name"`
	CheckpointID       string `json:"checkpoint_id,omitempty"`
	IncludeAllChildren bool   `json:"include_all_children,omitempty"`
}

// checkpointTypeMap converts PowerShell CheckpointType enum to string.
var checkpointTypeMap = map[int]string{
	0: "Disabled",
	1: "Production",
	2: "ProductionOnly",
	3: "Standard",
}

// GetCheckpoints returns all checkpoints for a VM.
func (c *Client) GetCheckpoints(ctx context.Context, vmName string) ([]Checkpoint, error) {
	psCmd := fmt.Sprintf(`Get-VMSnapshot -VMName %s -ErrorAction SilentlyContinue | ForEach-Object {
		[PSCustomObject]@{
			Id = $_.Id.ToString()
			Name = $_.Name
			VMName = $_.VMName
			VMId = $_.VMId.ToString()
			CreationTime = $_.CreationTime.ToString("o")
			ParentCheckpointId = if ($_.ParentCheckpointId) { $_.ParentCheckpointId.ToString() } else { $null }
			CheckpointType = [int]$_.CheckpointType
			Notes = $_.Notes
		}
	} | ConvertTo-Json -Depth 3`, PSString(vmName))

	var output []checkpointPSOutput
	if err := c.ExecutePSWithJSON(ctx, psCmd, &output); err != nil {
		// May be empty or no checkpoints
		return []Checkpoint{}, nil
	}

	// Handle single checkpoint case
	if len(output) == 0 {
		var single checkpointPSOutput
		if err := c.ExecutePSWithJSON(ctx, psCmd, &single); err == nil && single.Name != "" {
			output = append(output, single)
		}
	}

	checkpoints := make([]Checkpoint, 0, len(output))
	for _, out := range output {
		cp := psOutputToCheckpoint(out)
		checkpoints = append(checkpoints, cp)
	}

	return checkpoints, nil
}

// CreateCheckpoint creates a new checkpoint for a VM.
func (c *Client) CreateCheckpoint(ctx context.Context, req CheckpointRequest) *CheckpointResult {
	start := time.Now()
	result := &CheckpointResult{}

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
	}

	if vmName == "" {
		result.Error = "vm_name or vm_id is required"
		result.Duration = time.Since(start).Milliseconds()
		return result
	}

	if req.CheckpointName == "" {
		result.Error = "checkpoint_name is required"
		result.Duration = time.Since(start).Milliseconds()
		return result
	}

	// Create the checkpoint
	psCmd := fmt.Sprintf("Checkpoint-VM -Name %s -SnapshotName %s",
		PSString(vmName), PSString(req.CheckpointName))

	if req.Notes != "" {
		// Notes are not directly supported in Checkpoint-VM, would need to set after
		// For now, we'll add notes after creation if provided
	}

	_, err := c.ExecutePS(ctx, psCmd)
	result.Duration = time.Since(start).Milliseconds()

	if err != nil {
		result.Error = err.Error()
		return result
	}

	// Get the created checkpoint
	getCmd := fmt.Sprintf(`Get-VMSnapshot -VMName %s -Name %s | ForEach-Object {
		[PSCustomObject]@{
			Id = $_.Id.ToString()
			Name = $_.Name
			VMName = $_.VMName
			VMId = $_.VMId.ToString()
			CreationTime = $_.CreationTime.ToString("o")
			ParentCheckpointId = if ($_.ParentCheckpointId) { $_.ParentCheckpointId.ToString() } else { $null }
			CheckpointType = [int]$_.CheckpointType
			Notes = $_.Notes
		}
	} | ConvertTo-Json`, PSString(vmName), PSString(req.CheckpointName))

	var cpOut checkpointPSOutput
	if err := c.ExecutePSWithJSON(ctx, getCmd, &cpOut); err == nil && cpOut.Name != "" {
		cp := psOutputToCheckpoint(cpOut)
		result.Checkpoint = &cp
	}

	result.Success = true
	result.Message = fmt.Sprintf("Checkpoint '%s' created successfully", req.CheckpointName)

	return result
}

// RestoreCheckpoint restores a VM to a checkpoint.
func (c *Client) RestoreCheckpoint(ctx context.Context, req RestoreCheckpointRequest) *CheckpointResult {
	start := time.Now()
	result := &CheckpointResult{}

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
	}

	if vmName == "" {
		result.Error = "vm_name or vm_id is required"
		result.Duration = time.Since(start).Milliseconds()
		return result
	}

	// Build restore command
	var psCmd string
	if req.CheckpointID != "" {
		// Restore by checkpoint ID
		psCmd = fmt.Sprintf(`Get-VMSnapshot -Id %s | Restore-VMSnapshot -Confirm:$false`,
			PSString(req.CheckpointID))
	} else if req.CheckpointName != "" {
		// Restore by name
		psCmd = fmt.Sprintf("Restore-VMSnapshot -VMName %s -Name %s -Confirm:$false",
			PSString(vmName), PSString(req.CheckpointName))
	} else {
		result.Error = "checkpoint_name or checkpoint_id is required"
		result.Duration = time.Since(start).Milliseconds()
		return result
	}

	_, err := c.ExecutePS(ctx, psCmd)
	result.Duration = time.Since(start).Milliseconds()

	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Success = true
	result.Message = "Checkpoint restored successfully"

	return result
}

// DeleteCheckpoint deletes a checkpoint.
func (c *Client) DeleteCheckpoint(ctx context.Context, req DeleteCheckpointRequest) *CheckpointResult {
	start := time.Now()
	result := &CheckpointResult{}

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
	}

	if vmName == "" {
		result.Error = "vm_name or vm_id is required"
		result.Duration = time.Since(start).Milliseconds()
		return result
	}

	// Build delete command
	var psCmd string
	childrenFlag := ""
	if req.IncludeAllChildren {
		childrenFlag = " -IncludeAllChildSnapshots"
	}

	if req.CheckpointID != "" {
		// Delete by checkpoint ID
		psCmd = fmt.Sprintf(`Get-VMSnapshot -Id %s | Remove-VMSnapshot -Confirm:$false%s`,
			PSString(req.CheckpointID), childrenFlag)
	} else if req.CheckpointName != "" {
		// Delete by name
		psCmd = fmt.Sprintf("Remove-VMSnapshot -VMName %s -Name %s -Confirm:$false%s",
			PSString(vmName), PSString(req.CheckpointName), childrenFlag)
	} else {
		result.Error = "checkpoint_name or checkpoint_id is required"
		result.Duration = time.Since(start).Milliseconds()
		return result
	}

	_, err := c.ExecutePS(ctx, psCmd)
	result.Duration = time.Since(start).Milliseconds()

	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Success = true
	result.Message = "Checkpoint deleted successfully"

	return result
}

// psOutputToCheckpoint converts PowerShell output to Checkpoint struct.
func psOutputToCheckpoint(out checkpointPSOutput) Checkpoint {
	cpType := checkpointTypeMap[out.CheckpointType]
	if cpType == "" {
		cpType = "Unknown"
	}

	creationTime, _ := time.Parse(time.RFC3339, out.CreationTime)

	return Checkpoint{
		ID:             out.Id,
		Name:           out.Name,
		VMName:         out.VMName,
		VMID:           out.VMId,
		CreationTime:   creationTime,
		ParentID:       out.ParentCheckpointId,
		CheckpointType: cpType,
		Notes:          out.Notes,
	}
}
