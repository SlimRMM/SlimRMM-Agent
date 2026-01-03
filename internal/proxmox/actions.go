// Package proxmox provides control actions for VMs and containers.
package proxmox

import (
	"context"
	"fmt"
	"time"

	"github.com/luthermonson/go-proxmox"
)

// ActionType represents the type of control action.
type ActionType string

const (
	ActionStart    ActionType = "start"
	ActionStop     ActionType = "stop"
	ActionShutdown ActionType = "shutdown"
	ActionRestart  ActionType = "restart"
	ActionReset    ActionType = "reset"
	ActionSuspend  ActionType = "suspend"
	ActionResume   ActionType = "resume"
)

// ActionResult represents the result of a control action.
type ActionResult struct {
	Success   bool       `json:"success"`
	Action    ActionType `json:"action"`
	VMID      uint64     `json:"vmid"`
	Type      ResourceType `json:"type"`
	TaskID    string     `json:"task_id,omitempty"`
	Message   string     `json:"message,omitempty"`
	Error     string     `json:"error,omitempty"`
	StartedAt string     `json:"started_at"`
	Duration  int64      `json:"duration_ms"`
}

// ActionRequest represents a control action request.
type ActionRequest struct {
	VMID    uint64       `json:"vmid"`
	Type    ResourceType `json:"type"`
	Action  ActionType   `json:"action"`
	Timeout int          `json:"timeout,omitempty"` // seconds, default 60
	Force   bool         `json:"force,omitempty"`   // force stop/shutdown
}

const defaultActionTimeout = 60 * time.Second

// ExecuteAction performs a control action on a VM or container.
func (c *Client) ExecuteAction(ctx context.Context, req ActionRequest) *ActionResult {
	start := time.Now()
	result := &ActionResult{
		Action:    req.Action,
		VMID:      req.VMID,
		Type:      req.Type,
		StartedAt: start.Format(time.RFC3339),
	}

	// Set timeout
	timeout := defaultActionTimeout
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Get the node
	node, err := c.GetNode(ctx)
	if err != nil {
		result.Error = fmt.Sprintf("failed to get node: %v", err)
		result.Duration = time.Since(start).Milliseconds()
		return result
	}

	// Execute action based on resource type
	var taskID string
	if req.Type == ResourceTypeVM || req.Type == "" {
		taskID, err = c.executeVMAction(ctx, node, req)
	} else {
		taskID, err = c.executeContainerAction(ctx, node, req)
	}

	result.Duration = time.Since(start).Milliseconds()

	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Success = true
	result.TaskID = taskID
	result.Message = fmt.Sprintf("%s action completed successfully", req.Action)

	return result
}

// executeVMAction executes an action on a VM.
func (c *Client) executeVMAction(ctx context.Context, node *proxmox.Node, req ActionRequest) (string, error) {
	vm, err := node.VirtualMachine(ctx, int(req.VMID))
	if err != nil {
		return "", fmt.Errorf("VM %d not found: %w", req.VMID, err)
	}

	var task *proxmox.Task

	switch req.Action {
	case ActionStart:
		task, err = vm.Start(ctx)

	case ActionStop:
		if req.Force {
			task, err = vm.Stop(ctx)
		} else {
			// Try graceful shutdown first, then stop
			task, err = vm.Shutdown(ctx)
		}

	case ActionShutdown:
		task, err = vm.Shutdown(ctx)

	case ActionRestart:
		task, err = vm.Reboot(ctx)

	case ActionReset:
		task, err = vm.Reset(ctx)

	case ActionSuspend:
		// VMs use Pause for suspend
		task, err = vm.Pause(ctx)

	case ActionResume:
		task, err = vm.Resume(ctx)

	default:
		return "", fmt.Errorf("unknown action: %s", req.Action)
	}

	if err != nil {
		return "", err
	}

	if task != nil {
		// Wait for task completion
		if err := task.Wait(ctx, time.Second, defaultActionTimeout); err != nil {
			return string(task.UPID), fmt.Errorf("task failed: %w", err)
		}
		return string(task.UPID), nil
	}

	return "", nil
}

// executeContainerAction executes an action on a container.
func (c *Client) executeContainerAction(ctx context.Context, node *proxmox.Node, req ActionRequest) (string, error) {
	ct, err := node.Container(ctx, int(req.VMID))
	if err != nil {
		return "", fmt.Errorf("container %d not found: %w", req.VMID, err)
	}

	var task *proxmox.Task

	switch req.Action {
	case ActionStart:
		task, err = ct.Start(ctx)

	case ActionStop:
		task, err = ct.Stop(ctx)

	case ActionShutdown:
		// Container shutdown: (ctx, force, timeout)
		task, err = ct.Shutdown(ctx, false, 60)

	case ActionRestart:
		task, err = ct.Reboot(ctx)

	case ActionResume:
		task, err = ct.Resume(ctx)

	case ActionSuspend:
		task, err = ct.Suspend(ctx)

	case ActionReset:
		// Containers don't have reset, use stop + start
		task, err = ct.Stop(ctx)
		if err == nil && task != nil {
			task.Wait(ctx, time.Second, defaultActionTimeout)
			task, err = ct.Start(ctx)
		}

	default:
		return "", fmt.Errorf("unknown action: %s", req.Action)
	}

	if err != nil {
		return "", err
	}

	if task != nil {
		// Wait for task completion
		if err := task.Wait(ctx, time.Second, defaultActionTimeout); err != nil {
			return string(task.UPID), fmt.Errorf("task failed: %w", err)
		}
		return string(task.UPID), nil
	}

	return "", nil
}

// BulkAction executes an action on multiple VMs/containers.
func (c *Client) BulkAction(ctx context.Context, action ActionType, vmids []uint64, resourceType ResourceType) []ActionResult {
	results := make([]ActionResult, 0, len(vmids))

	for _, vmid := range vmids {
		req := ActionRequest{
			VMID:   vmid,
			Type:   resourceType,
			Action: action,
		}
		result := c.ExecuteAction(ctx, req)
		results = append(results, *result)
	}

	return results
}

// StartVM starts a virtual machine.
func (c *Client) StartVM(ctx context.Context, vmid uint64) *ActionResult {
	return c.ExecuteAction(ctx, ActionRequest{
		VMID:   vmid,
		Type:   ResourceTypeVM,
		Action: ActionStart,
	})
}

// StopVM stops a virtual machine.
func (c *Client) StopVM(ctx context.Context, vmid uint64, force bool) *ActionResult {
	return c.ExecuteAction(ctx, ActionRequest{
		VMID:   vmid,
		Type:   ResourceTypeVM,
		Action: ActionStop,
		Force:  force,
	})
}

// ShutdownVM gracefully shuts down a virtual machine.
func (c *Client) ShutdownVM(ctx context.Context, vmid uint64) *ActionResult {
	return c.ExecuteAction(ctx, ActionRequest{
		VMID:   vmid,
		Type:   ResourceTypeVM,
		Action: ActionShutdown,
	})
}

// RestartVM restarts a virtual machine.
func (c *Client) RestartVM(ctx context.Context, vmid uint64) *ActionResult {
	return c.ExecuteAction(ctx, ActionRequest{
		VMID:   vmid,
		Type:   ResourceTypeVM,
		Action: ActionRestart,
	})
}

// ResetVM hard resets a virtual machine.
func (c *Client) ResetVM(ctx context.Context, vmid uint64) *ActionResult {
	return c.ExecuteAction(ctx, ActionRequest{
		VMID:   vmid,
		Type:   ResourceTypeVM,
		Action: ActionReset,
	})
}

// StartContainer starts a container.
func (c *Client) StartContainer(ctx context.Context, vmid uint64) *ActionResult {
	return c.ExecuteAction(ctx, ActionRequest{
		VMID:   vmid,
		Type:   ResourceTypeContainer,
		Action: ActionStart,
	})
}

// StopContainer stops a container.
func (c *Client) StopContainer(ctx context.Context, vmid uint64) *ActionResult {
	return c.ExecuteAction(ctx, ActionRequest{
		VMID:   vmid,
		Type:   ResourceTypeContainer,
		Action: ActionStop,
	})
}

// ShutdownContainer gracefully shuts down a container.
func (c *Client) ShutdownContainer(ctx context.Context, vmid uint64) *ActionResult {
	return c.ExecuteAction(ctx, ActionRequest{
		VMID:   vmid,
		Type:   ResourceTypeContainer,
		Action: ActionShutdown,
	})
}

// RestartContainer restarts a container.
func (c *Client) RestartContainer(ctx context.Context, vmid uint64) *ActionResult {
	return c.ExecuteAction(ctx, ActionRequest{
		VMID:   vmid,
		Type:   ResourceTypeContainer,
		Action: ActionRestart,
	})
}
