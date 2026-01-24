// Package hyperv provides resource types and listing functions.
package hyperv

import (
	"context"
	"sort"
)

// VMState represents the state of a Hyper-V VM.
type VMState string

const (
	VMStateRunning         VMState = "Running"
	VMStateOff             VMState = "Off"
	VMStateSaved           VMState = "Saved"
	VMStatePaused          VMState = "Paused"
	VMStateStarting        VMState = "Starting"
	VMStateStopping        VMState = "Stopping"
	VMStateSaving          VMState = "Saving"
	VMStatePausing         VMState = "Pausing"
	VMStateResuming        VMState = "Resuming"
	VMStateReset           VMState = "Reset"
	VMStateFastSaved       VMState = "FastSaved"
	VMStateFastSaving      VMState = "FastSaving"
	VMStateRunningCritical VMState = "RunningCritical"
	VMStateOffCritical     VMState = "OffCritical"
	VMStateOther           VMState = "Other"
)

// VM represents a Hyper-V virtual machine.
type VM struct {
	ID                       string  `json:"id"`
	Name                     string  `json:"name"`
	State                    VMState `json:"state"`
	CPUCount                 int     `json:"cpu_count"`
	MemoryAssigned           uint64  `json:"memory_assigned"` // bytes
	MemoryDemand             uint64  `json:"memory_demand"`   // bytes
	MemoryStartup            uint64  `json:"memory_startup"`  // bytes
	DynamicMemory            bool    `json:"dynamic_memory"`
	Generation               int     `json:"generation"` // 1 or 2
	Version                  string  `json:"version"`
	Path                     string  `json:"path"`
	CheckpointCount          int     `json:"checkpoint_count"`
	Uptime                   int64   `json:"uptime"`           // seconds
	Status                   string  `json:"status,omitempty"` // human-readable status
	ReplicationState         string  `json:"replication_state,omitempty"`
	Notes                    string  `json:"notes,omitempty"`
	CPUUsage                 int     `json:"cpu_usage"` // percentage
	IntegrationServicesState string  `json:"integration_services_state,omitempty"`
}

// vmPSOutput is the JSON structure returned by Get-VM PowerShell command.
type vmPSOutput struct {
	Id                       string `json:"Id"`
	VMId                     string `json:"VMId"`
	Name                     string `json:"Name"`
	State                    int    `json:"State"`
	ProcessorCount           int    `json:"ProcessorCount"`
	MemoryAssigned           int64  `json:"MemoryAssigned"`
	MemoryDemand             int64  `json:"MemoryDemand"`
	MemoryStartup            int64  `json:"MemoryStartup"`
	DynamicMemoryEnabled     bool   `json:"DynamicMemoryEnabled"`
	Generation               int    `json:"Generation"`
	Version                  string `json:"Version"`
	Path                     string `json:"Path"`
	CheckpointCount          int    `json:"CheckpointCount"`
	UptimeSeconds            int64  `json:"UptimeSeconds"`
	Status                   string `json:"Status"`
	ReplicationState         int    `json:"ReplicationState"`
	Notes                    string `json:"Notes"`
	CPUUsage                 int    `json:"CPUUsage"`
	IntegrationServicesState string `json:"IntegrationServicesState"`
}

// ResourceList contains a list of VMs with summary information.
type ResourceList struct {
	VMs         []VM   `json:"vms"`
	TotalVMs    int    `json:"total_vms"`
	RunningVMs  int    `json:"running_vms"`
	StoppedVMs  int    `json:"stopped_vms"`
	PausedVMs   int    `json:"paused_vms"`
	TotalCPUs   int    `json:"total_cpus"`
	TotalMemory uint64 `json:"total_memory"`
	UsedMemory  uint64 `json:"used_memory"`
	HostName    string `json:"host_name"`
	ClusterMode bool   `json:"cluster_mode"`
}

// stateMap converts PowerShell VMState enum to string.
var stateMap = map[int]VMState{
	1:  VMStateOther,
	2:  VMStateRunning,
	3:  VMStateOff,
	4:  VMStateStopping,
	5:  VMStateSaved,
	6:  VMStatePaused,
	7:  VMStateStarting,
	8:  VMStateReset,
	9:  VMStateSaving,
	10: VMStatePausing,
	11: VMStateResuming,
	12: VMStateFastSaved,
	13: VMStateFastSaving,
	// Critical states
	32768: VMStateRunningCritical,
	32769: VMStateOffCritical,
}

// GetResources returns all VMs from the Hyper-V host.
func (c *Client) GetResources(ctx context.Context) (*ResourceList, error) {
	result := &ResourceList{
		VMs:      make([]VM, 0),
		HostName: c.hostName,
	}

	// PowerShell command to get all VMs with checkpoint count
	psCmd := `Get-VM | ForEach-Object {
		$vm = $_
		$checkpointCount = (Get-VMSnapshot -VMName $vm.Name -ErrorAction SilentlyContinue | Measure-Object).Count
		$uptimeSeconds = 0
		if ($vm.Uptime) { $uptimeSeconds = [int]$vm.Uptime.TotalSeconds }
		[PSCustomObject]@{
			Id = $vm.Id.ToString()
			VMId = $vm.VMId.ToString()
			Name = $vm.Name
			State = [int]$vm.State
			ProcessorCount = $vm.ProcessorCount
			MemoryAssigned = $vm.MemoryAssigned
			MemoryDemand = $vm.MemoryDemand
			MemoryStartup = $vm.MemoryStartup
			DynamicMemoryEnabled = $vm.DynamicMemoryEnabled
			Generation = $vm.Generation
			Version = $vm.Version
			Path = $vm.Path
			CheckpointCount = $checkpointCount
			UptimeSeconds = $uptimeSeconds
			Status = $vm.Status
			ReplicationState = [int]$vm.ReplicationState
			Notes = $vm.Notes
			CPUUsage = $vm.CPUUsage
			IntegrationServicesState = $vm.IntegrationServicesState
		}
	} | ConvertTo-Json -Depth 3`

	var vmsOutput []vmPSOutput
	if err := c.ExecutePSWithJSON(ctx, psCmd, &vmsOutput); err != nil {
		// Try simpler query without extra fields
		simplePsCmd := `Get-VM | Select-Object Id, Name, State, ProcessorCount, MemoryAssigned, Generation, Path | ConvertTo-Json`
		if err := c.ExecutePSWithJSON(ctx, simplePsCmd, &vmsOutput); err != nil {
			return nil, err
		}
	}

	// Handle single VM case (PowerShell returns object instead of array)
	if len(vmsOutput) == 0 {
		// Try single object
		var singleVM vmPSOutput
		if err := c.ExecutePSWithJSON(ctx, psCmd, &singleVM); err == nil && singleVM.Name != "" {
			vmsOutput = append(vmsOutput, singleVM)
		}
	}

	// Convert to our VM type
	for _, vmOut := range vmsOutput {
		vm := psOutputToVM(vmOut)
		result.VMs = append(result.VMs, vm)
		result.TotalVMs++

		switch vm.State {
		case VMStateRunning, VMStateRunningCritical:
			result.RunningVMs++
			result.UsedMemory += vm.MemoryAssigned
		case VMStateOff, VMStateOffCritical:
			result.StoppedVMs++
		case VMStatePaused:
			result.PausedVMs++
		}

		result.TotalCPUs += vm.CPUCount
		result.TotalMemory += vm.MemoryStartup
	}

	// Sort by name
	sort.Slice(result.VMs, func(i, j int) bool {
		return result.VMs[i].Name < result.VMs[j].Name
	})

	// Check cluster status
	result.ClusterMode = isClusterEnabled(ctx)

	return result, nil
}

// GetVM returns a specific VM by name.
func (c *Client) GetVM(ctx context.Context, vmName string) (*VM, error) {
	psCmd := `Get-VM -Name ` + PSString(vmName) + ` | ForEach-Object {
		$vm = $_
		$checkpointCount = (Get-VMSnapshot -VMName $vm.Name -ErrorAction SilentlyContinue | Measure-Object).Count
		$uptimeSeconds = 0
		if ($vm.Uptime) { $uptimeSeconds = [int]$vm.Uptime.TotalSeconds }
		[PSCustomObject]@{
			Id = $vm.Id.ToString()
			VMId = $vm.VMId.ToString()
			Name = $vm.Name
			State = [int]$vm.State
			ProcessorCount = $vm.ProcessorCount
			MemoryAssigned = $vm.MemoryAssigned
			MemoryDemand = $vm.MemoryDemand
			MemoryStartup = $vm.MemoryStartup
			DynamicMemoryEnabled = $vm.DynamicMemoryEnabled
			Generation = $vm.Generation
			Version = $vm.Version
			Path = $vm.Path
			CheckpointCount = $checkpointCount
			UptimeSeconds = $uptimeSeconds
			Status = $vm.Status
			ReplicationState = [int]$vm.ReplicationState
			Notes = $vm.Notes
			CPUUsage = $vm.CPUUsage
			IntegrationServicesState = $vm.IntegrationServicesState
		}
	} | ConvertTo-Json`

	var vmOut vmPSOutput
	if err := c.ExecutePSWithJSON(ctx, psCmd, &vmOut); err != nil {
		return nil, err
	}

	vm := psOutputToVM(vmOut)
	return &vm, nil
}

// GetVMByID returns a specific VM by ID.
func (c *Client) GetVMByID(ctx context.Context, vmID string) (*VM, error) {
	psCmd := `Get-VM | Where-Object { $_.Id.ToString() -eq ` + PSString(vmID) + ` } | ForEach-Object {
		$vm = $_
		$checkpointCount = (Get-VMSnapshot -VMName $vm.Name -ErrorAction SilentlyContinue | Measure-Object).Count
		$uptimeSeconds = 0
		if ($vm.Uptime) { $uptimeSeconds = [int]$vm.Uptime.TotalSeconds }
		[PSCustomObject]@{
			Id = $vm.Id.ToString()
			VMId = $vm.VMId.ToString()
			Name = $vm.Name
			State = [int]$vm.State
			ProcessorCount = $vm.ProcessorCount
			MemoryAssigned = $vm.MemoryAssigned
			MemoryDemand = $vm.MemoryDemand
			MemoryStartup = $vm.MemoryStartup
			DynamicMemoryEnabled = $vm.DynamicMemoryEnabled
			Generation = $vm.Generation
			Version = $vm.Version
			Path = $vm.Path
			CheckpointCount = $checkpointCount
			UptimeSeconds = $uptimeSeconds
			Status = $vm.Status
			ReplicationState = [int]$vm.ReplicationState
			Notes = $vm.Notes
			CPUUsage = $vm.CPUUsage
			IntegrationServicesState = $vm.IntegrationServicesState
		}
	} | ConvertTo-Json`

	var vmOut vmPSOutput
	if err := c.ExecutePSWithJSON(ctx, psCmd, &vmOut); err != nil {
		return nil, err
	}

	vm := psOutputToVM(vmOut)
	return &vm, nil
}

// psOutputToVM converts PowerShell output to VM struct.
func psOutputToVM(out vmPSOutput) VM {
	state := stateMap[out.State]
	if state == "" {
		state = VMStateOther
	}

	id := out.Id
	if id == "" {
		id = out.VMId
	}

	return VM{
		ID:                       id,
		Name:                     out.Name,
		State:                    state,
		CPUCount:                 out.ProcessorCount,
		MemoryAssigned:           uint64(out.MemoryAssigned),
		MemoryDemand:             uint64(out.MemoryDemand),
		MemoryStartup:            uint64(out.MemoryStartup),
		DynamicMemory:            out.DynamicMemoryEnabled,
		Generation:               out.Generation,
		Version:                  out.Version,
		Path:                     out.Path,
		CheckpointCount:          out.CheckpointCount,
		Uptime:                   out.UptimeSeconds,
		Status:                   out.Status,
		Notes:                    out.Notes,
		CPUUsage:                 out.CPUUsage,
		IntegrationServicesState: out.IntegrationServicesState,
	}
}
