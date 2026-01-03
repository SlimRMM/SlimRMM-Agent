// Package handler provides Proxmox action handlers.
package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/slimrmm/slimrmm-agent/internal/proxmox"
)

var (
	proxmoxClientMu sync.RWMutex
	proxmoxClient   *proxmox.Client
)

// registerProxmoxHandlers registers all Proxmox-related handlers.
func (h *Handler) registerProxmoxHandlers() {
	h.handlers["proxmox_info"] = h.handleProxmoxInfo
	h.handlers["proxmox_resources"] = h.handleProxmoxResources
	h.handlers["proxmox_action"] = h.handleProxmoxAction
	h.handlers["proxmox_resource"] = h.handleProxmoxResource
}

// getProxmoxClient returns the shared Proxmox client, creating it if needed.
func (h *Handler) getProxmoxClient(ctx context.Context) (*proxmox.Client, error) {
	proxmoxClientMu.RLock()
	if proxmoxClient != nil {
		proxmoxClientMu.RUnlock()
		return proxmoxClient, nil
	}
	proxmoxClientMu.RUnlock()

	proxmoxClientMu.Lock()
	defer proxmoxClientMu.Unlock()

	// Double-check after acquiring write lock
	if proxmoxClient != nil {
		return proxmoxClient, nil
	}

	// Create new client using the agent's base directory
	client, err := proxmox.NewClient(ctx, h.paths.BaseDir)
	if err != nil {
		return nil, fmt.Errorf("initializing Proxmox client: %w", err)
	}

	proxmoxClient = client
	return proxmoxClient, nil
}

// handleProxmoxInfo returns Proxmox detection information.
// This does NOT require API authentication - uses CLI detection only.
func (h *Handler) handleProxmoxInfo(ctx context.Context, data json.RawMessage) (interface{}, error) {
	info := proxmox.Detect(ctx)
	return info, nil
}

// handleProxmoxResources returns all VMs and containers.
func (h *Handler) handleProxmoxResources(ctx context.Context, data json.RawMessage) (interface{}, error) {
	// Check if this is a Proxmox host first
	if !proxmox.IsProxmoxHost() {
		return nil, fmt.Errorf("not a Proxmox host")
	}

	client, err := h.getProxmoxClient(ctx)
	if err != nil {
		return nil, err
	}

	return client.GetResources(ctx)
}

// proxmoxResourceRequest is used to get a specific resource.
type proxmoxResourceRequest struct {
	VMID uint64              `json:"vmid"`
	Type proxmox.ResourceType `json:"type,omitempty"`
}

// handleProxmoxResource returns a specific VM or container.
func (h *Handler) handleProxmoxResource(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if !proxmox.IsProxmoxHost() {
		return nil, fmt.Errorf("not a Proxmox host")
	}

	var req proxmoxResourceRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	client, err := h.getProxmoxClient(ctx)
	if err != nil {
		return nil, err
	}

	return client.GetResource(ctx, req.VMID, req.Type)
}

// handleProxmoxAction executes a control action on a VM or container.
func (h *Handler) handleProxmoxAction(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if !proxmox.IsProxmoxHost() {
		return nil, fmt.Errorf("not a Proxmox host")
	}

	var req proxmox.ActionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Validate action
	switch req.Action {
	case proxmox.ActionStart, proxmox.ActionStop, proxmox.ActionShutdown,
		proxmox.ActionRestart, proxmox.ActionReset, proxmox.ActionSuspend, proxmox.ActionResume:
		// Valid actions
	default:
		return nil, fmt.Errorf("invalid action: %s", req.Action)
	}

	client, err := h.getProxmoxClient(ctx)
	if err != nil {
		return nil, err
	}

	result := client.ExecuteAction(ctx, req)

	// Log the action
	h.logger.Info("proxmox action executed",
		"action", req.Action,
		"vmid", req.VMID,
		"type", req.Type,
		"success", result.Success,
		"task_id", result.TaskID,
	)

	return result, nil
}

// GetProxmoxInfo returns Proxmox information for heartbeat.
// Returns nil if not a Proxmox host.
func GetProxmoxInfo(ctx context.Context) *proxmox.Info {
	if !proxmox.IsProxmoxHost() {
		return nil
	}
	return proxmox.Detect(ctx)
}

// CloseProxmoxClient closes the shared Proxmox client.
func CloseProxmoxClient() {
	proxmoxClientMu.Lock()
	defer proxmoxClientMu.Unlock()

	if proxmoxClient != nil {
		proxmoxClient.Close()
		proxmoxClient = nil
	}
}
