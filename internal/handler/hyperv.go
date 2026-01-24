// Package handler provides Hyper-V action handlers.
package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/slimrmm/slimrmm-agent/internal/hyperv"
)

var (
	hypervClientMu sync.RWMutex
	hypervClient   *hyperv.Client
)

// registerHyperVHandlers registers all Hyper-V related handlers.
func (h *Handler) registerHyperVHandlers() {
	h.handlers["hyperv_info"] = h.handleHyperVInfo
	h.handlers["hyperv_resources"] = h.handleHyperVResources
	h.handlers["hyperv_vm"] = h.handleHyperVVM
	h.handlers["hyperv_action"] = h.handleHyperVAction

	// Checkpoint (snapshot) handlers
	h.handlers["hyperv_checkpoints"] = h.handleHyperVCheckpoints
	h.handlers["hyperv_create_checkpoint"] = h.handleHyperVCreateCheckpoint
	h.handlers["hyperv_restore_checkpoint"] = h.handleHyperVRestoreCheckpoint
	h.handlers["hyperv_delete_checkpoint"] = h.handleHyperVDeleteCheckpoint

	// Backup handlers
	h.handlers["hyperv_export"] = h.handleHyperVExport
	h.handlers["hyperv_import"] = h.handleHyperVImport
	h.handlers["hyperv_backup"] = h.handleHyperVBackup
	h.handlers["hyperv_list_exports"] = h.handleHyperVListExports
}

// getHyperVClient returns the shared Hyper-V client, creating it if needed.
func (h *Handler) getHyperVClient(ctx context.Context) (*hyperv.Client, error) {
	hypervClientMu.RLock()
	if hypervClient != nil {
		hypervClientMu.RUnlock()
		return hypervClient, nil
	}
	hypervClientMu.RUnlock()

	hypervClientMu.Lock()
	defer hypervClientMu.Unlock()

	// Double-check after acquiring write lock
	if hypervClient != nil {
		return hypervClient, nil
	}

	// Create new client
	client, err := hyperv.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("initializing Hyper-V client: %w", err)
	}

	hypervClient = client
	return hypervClient, nil
}

// handleHyperVInfo returns Hyper-V detection information.
func (h *Handler) handleHyperVInfo(ctx context.Context, data json.RawMessage) (interface{}, error) {
	info := hyperv.Detect(ctx)
	return info, nil
}

// handleHyperVResources returns all VMs on the host.
func (h *Handler) handleHyperVResources(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if !hyperv.IsHyperVHost() {
		return nil, fmt.Errorf("not a Hyper-V host")
	}

	client, err := h.getHyperVClient(ctx)
	if err != nil {
		return nil, err
	}

	return client.GetResources(ctx)
}

// hypervVMRequest is used to get a specific VM.
type hypervVMRequest struct {
	VMName string `json:"vm_name,omitempty"`
	VMID   string `json:"vm_id,omitempty"`
}

// handleHyperVVM returns a specific VM.
func (h *Handler) handleHyperVVM(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if !hyperv.IsHyperVHost() {
		return nil, fmt.Errorf("not a Hyper-V host")
	}

	var req hypervVMRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	client, err := h.getHyperVClient(ctx)
	if err != nil {
		return nil, err
	}

	if req.VMName != "" {
		return client.GetVM(ctx, req.VMName)
	}
	if req.VMID != "" {
		return client.GetVMByID(ctx, req.VMID)
	}

	return nil, fmt.Errorf("vm_name or vm_id is required")
}

// handleHyperVAction executes a control action on a VM.
func (h *Handler) handleHyperVAction(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if !hyperv.IsHyperVHost() {
		return nil, fmt.Errorf("not a Hyper-V host")
	}

	var req hyperv.ActionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Validate action
	switch req.Action {
	case hyperv.ActionStart, hyperv.ActionStop, hyperv.ActionRestart,
		hyperv.ActionPause, hyperv.ActionResume, hyperv.ActionReset, hyperv.ActionSave:
		// Valid actions
	default:
		return nil, fmt.Errorf("invalid action: %s", req.Action)
	}

	client, err := h.getHyperVClient(ctx)
	if err != nil {
		return nil, err
	}

	result := client.ExecuteAction(ctx, req)

	h.logger.Info("hyperv action executed",
		"action", req.Action,
		"vm_name", req.VMName,
		"success", result.Success,
	)

	return result, nil
}

// handleHyperVCheckpoints returns all checkpoints for a VM.
func (h *Handler) handleHyperVCheckpoints(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if !hyperv.IsHyperVHost() {
		return nil, fmt.Errorf("not a Hyper-V host")
	}

	var req hypervVMRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if req.VMName == "" {
		return nil, fmt.Errorf("vm_name is required")
	}

	client, err := h.getHyperVClient(ctx)
	if err != nil {
		return nil, err
	}

	return client.GetCheckpoints(ctx, req.VMName)
}

// handleHyperVCreateCheckpoint creates a new checkpoint.
func (h *Handler) handleHyperVCreateCheckpoint(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if !hyperv.IsHyperVHost() {
		return nil, fmt.Errorf("not a Hyper-V host")
	}

	var req hyperv.CheckpointRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	client, err := h.getHyperVClient(ctx)
	if err != nil {
		return nil, err
	}

	result := client.CreateCheckpoint(ctx, req)

	h.logger.Info("hyperv checkpoint created",
		"vm_name", req.VMName,
		"checkpoint_name", req.CheckpointName,
		"success", result.Success,
	)

	return result, nil
}

// handleHyperVRestoreCheckpoint restores a checkpoint.
func (h *Handler) handleHyperVRestoreCheckpoint(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if !hyperv.IsHyperVHost() {
		return nil, fmt.Errorf("not a Hyper-V host")
	}

	var req hyperv.RestoreCheckpointRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	client, err := h.getHyperVClient(ctx)
	if err != nil {
		return nil, err
	}

	result := client.RestoreCheckpoint(ctx, req)

	h.logger.Info("hyperv checkpoint restored",
		"vm_name", req.VMName,
		"checkpoint_name", req.CheckpointName,
		"success", result.Success,
	)

	return result, nil
}

// handleHyperVDeleteCheckpoint deletes a checkpoint.
func (h *Handler) handleHyperVDeleteCheckpoint(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if !hyperv.IsHyperVHost() {
		return nil, fmt.Errorf("not a Hyper-V host")
	}

	var req hyperv.DeleteCheckpointRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	client, err := h.getHyperVClient(ctx)
	if err != nil {
		return nil, err
	}

	result := client.DeleteCheckpoint(ctx, req)

	h.logger.Info("hyperv checkpoint deleted",
		"vm_name", req.VMName,
		"checkpoint_name", req.CheckpointName,
		"success", result.Success,
	)

	return result, nil
}

// handleHyperVExport exports a VM.
func (h *Handler) handleHyperVExport(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if !hyperv.IsHyperVHost() {
		return nil, fmt.Errorf("not a Hyper-V host")
	}

	var req hyperv.ExportRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	client, err := h.getHyperVClient(ctx)
	if err != nil {
		return nil, err
	}

	result := client.ExportVM(ctx, req)

	h.logger.Info("hyperv export completed",
		"vm_name", req.VMName,
		"export_path", req.ExportPath,
		"success", result.Success,
	)

	return result, nil
}

// handleHyperVImport imports a VM.
func (h *Handler) handleHyperVImport(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if !hyperv.IsHyperVHost() {
		return nil, fmt.Errorf("not a Hyper-V host")
	}

	var req hyperv.ImportRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	client, err := h.getHyperVClient(ctx)
	if err != nil {
		return nil, err
	}

	result := client.ImportVM(ctx, req)

	h.logger.Info("hyperv import completed",
		"vmcx_path", req.VMCXPath,
		"vm_name", result.VMName,
		"success", result.Success,
	)

	return result, nil
}

// handleHyperVBackup creates a backup of a VM.
func (h *Handler) handleHyperVBackup(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if !hyperv.IsHyperVHost() {
		return nil, fmt.Errorf("not a Hyper-V host")
	}

	var req hyperv.BackupRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	client, err := h.getHyperVClient(ctx)
	if err != nil {
		return nil, err
	}

	result := client.CreateBackup(ctx, req)

	h.logger.Info("hyperv backup completed",
		"vm_name", req.VMName,
		"backup_path", req.BackupPath,
		"success", result.Success,
	)

	return result, nil
}

// hypervListExportsRequest is used to list exports.
type hypervListExportsRequest struct {
	ExportPath string `json:"export_path"`
}

// handleHyperVListExports lists exported VMs.
func (h *Handler) handleHyperVListExports(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if !hyperv.IsHyperVHost() {
		return nil, fmt.Errorf("not a Hyper-V host")
	}

	var req hypervListExportsRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if req.ExportPath == "" {
		return nil, fmt.Errorf("export_path is required")
	}

	client, err := h.getHyperVClient(ctx)
	if err != nil {
		return nil, err
	}

	return client.ListExports(ctx, req.ExportPath)
}

// GetHyperVInfo returns Hyper-V information for heartbeat.
// Returns nil if not a Hyper-V host.
func GetHyperVInfo(ctx context.Context) *hyperv.Info {
	if !hyperv.IsHyperVHost() {
		return nil
	}
	return hyperv.Detect(ctx)
}

// CloseHyperVClient closes the shared Hyper-V client.
func CloseHyperVClient() {
	hypervClientMu.Lock()
	defer hypervClientMu.Unlock()

	if hypervClient != nil {
		hypervClient.Close()
		hypervClient = nil
	}
}
