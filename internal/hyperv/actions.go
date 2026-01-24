// Package hyperv provides control actions for Hyper-V VMs.
package hyperv

import (
	"context"
	"fmt"
	"time"
)

// ActionType represents the type of control action.
type ActionType string

const (
	ActionStart   ActionType = "start"
	ActionStop    ActionType = "stop"
	ActionRestart ActionType = "restart"
	ActionPause   ActionType = "pause"
	ActionResume  ActionType = "resume"
	ActionReset   ActionType = "reset"
	ActionSave    ActionType = "save"
)

// ActionResult represents the result of a control action.
type ActionResult struct {
	Success   bool       `json:"success"`
	Action    ActionType `json:"action"`
	VMName    string     `json:"vm_name"`
	VMID      string     `json:"vm_id,omitempty"`
	Message   string     `json:"message,omitempty"`
	Error     string     `json:"error,omitempty"`
	StartedAt string     `json:"started_at"`
	Duration  int64      `json:"duration_ms"`
	NewState  VMState    `json:"new_state,omitempty"`
}

// ActionRequest represents a control action request.
type ActionRequest struct {
	VMName  string     `json:"vm_name"`
	VMID    string     `json:"vm_id,omitempty"`
	Action  ActionType `json:"action"`
	Timeout int        `json:"timeout,omitempty"` // seconds, default 60
	Force   bool       `json:"force,omitempty"`   // force stop
}

const defaultActionTimeout = 60 * time.Second

// ExecuteAction performs a control action on a VM.
func (c *Client) ExecuteAction(ctx context.Context, req ActionRequest) *ActionResult {
	start := time.Now()
	result := &ActionResult{
		Action:    req.Action,
		VMName:    req.VMName,
		VMID:      req.VMID,
		StartedAt: start.Format(time.RFC3339),
	}

	// Set timeout
	timeout := defaultActionTimeout
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

	// Build PowerShell command based on action
	var psCmd string
	switch req.Action {
	case ActionStart:
		psCmd = fmt.Sprintf("Start-VM -Name %s", PSString(vmName))

	case ActionStop:
		if req.Force {
			psCmd = fmt.Sprintf("Stop-VM -Name %s -Force -TurnOff", PSString(vmName))
		} else {
			psCmd = fmt.Sprintf("Stop-VM -Name %s -Force", PSString(vmName))
		}

	case ActionRestart:
		psCmd = fmt.Sprintf("Restart-VM -Name %s -Force", PSString(vmName))

	case ActionPause:
		psCmd = fmt.Sprintf("Suspend-VM -Name %s", PSString(vmName))

	case ActionResume:
		psCmd = fmt.Sprintf("Resume-VM -Name %s", PSString(vmName))

	case ActionReset:
		// Hard reset: stop + start
		psCmd = fmt.Sprintf("Stop-VM -Name %s -Force -TurnOff; Start-VM -Name %s", PSString(vmName), PSString(vmName))

	case ActionSave:
		psCmd = fmt.Sprintf("Save-VM -Name %s", PSString(vmName))

	default:
		result.Error = fmt.Sprintf("unknown action: %s", req.Action)
		result.Duration = time.Since(start).Milliseconds()
		return result
	}

	// Execute the command
	_, err := c.ExecutePS(ctx, psCmd)
	result.Duration = time.Since(start).Milliseconds()

	if err != nil {
		result.Error = err.Error()
		return result
	}

	// Get the new state
	vm, err := c.GetVM(ctx, vmName)
	if err == nil {
		result.NewState = vm.State
		result.VMID = vm.ID
	}

	result.Success = true
	result.Message = fmt.Sprintf("%s action completed successfully", req.Action)

	return result
}

// BulkAction executes an action on multiple VMs.
func (c *Client) BulkAction(ctx context.Context, action ActionType, vmNames []string, force bool) []ActionResult {
	results := make([]ActionResult, 0, len(vmNames))

	for _, vmName := range vmNames {
		req := ActionRequest{
			VMName: vmName,
			Action: action,
			Force:  force,
		}
		result := c.ExecuteAction(ctx, req)
		results = append(results, *result)
	}

	return results
}

// StartVM starts a virtual machine.
func (c *Client) StartVM(ctx context.Context, vmName string) *ActionResult {
	return c.ExecuteAction(ctx, ActionRequest{
		VMName: vmName,
		Action: ActionStart,
	})
}

// StopVM stops a virtual machine.
func (c *Client) StopVM(ctx context.Context, vmName string, force bool) *ActionResult {
	return c.ExecuteAction(ctx, ActionRequest{
		VMName: vmName,
		Action: ActionStop,
		Force:  force,
	})
}

// RestartVM restarts a virtual machine.
func (c *Client) RestartVM(ctx context.Context, vmName string) *ActionResult {
	return c.ExecuteAction(ctx, ActionRequest{
		VMName: vmName,
		Action: ActionRestart,
	})
}

// PauseVM pauses (suspends) a virtual machine.
func (c *Client) PauseVM(ctx context.Context, vmName string) *ActionResult {
	return c.ExecuteAction(ctx, ActionRequest{
		VMName: vmName,
		Action: ActionPause,
	})
}

// ResumeVM resumes a paused virtual machine.
func (c *Client) ResumeVM(ctx context.Context, vmName string) *ActionResult {
	return c.ExecuteAction(ctx, ActionRequest{
		VMName: vmName,
		Action: ActionResume,
	})
}

// ResetVM hard resets a virtual machine.
func (c *Client) ResetVM(ctx context.Context, vmName string) *ActionResult {
	return c.ExecuteAction(ctx, ActionRequest{
		VMName: vmName,
		Action: ActionReset,
	})
}

// SaveVM saves the state of a virtual machine.
func (c *Client) SaveVM(ctx context.Context, vmName string) *ActionResult {
	return c.ExecuteAction(ctx, ActionRequest{
		VMName: vmName,
		Action: ActionSave,
	})
}
