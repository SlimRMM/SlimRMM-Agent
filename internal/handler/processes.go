// Package handler - list_processes and maintenance mode handlers.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/slimrmm/slimrmm-agent/internal/actions"
)

// ErrMaintenanceActive is returned by destructive handlers when the agent is
// currently in maintenance mode. Handlers that mutate system state (scripts,
// patches, updates, installs, reboots, registry changes, container pruning,
// etc.) must check IsInMaintenance() at the start and return this sentinel
// error so the backend can distinguish policy rejections from real failures.
var ErrMaintenanceActive = errors.New("agent is in maintenance mode, destructive operations are blocked")

// handleListProcesses enumerates the running processes on the host and returns
// them in a shape consumable by the backend's GET /agents/{id}/processes
// endpoint.
func (h *Handler) handleListProcesses(ctx context.Context, data json.RawMessage) (interface{}, error) {
	procs, err := actions.ListProcesses(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing processes: %w", err)
	}
	return map[string]interface{}{
		"processes": procs,
		"count":     len(procs),
	}, nil
}

// setMaintenanceRequest is the payload for set_maintenance_mode.
type setMaintenanceRequest struct {
	Enabled bool `json:"enabled"`
}

// handleSetMaintenanceMode flips the agent's maintenance flag. While the flag
// is set, destructive handlers (script-exec, patching, updates, installs,
// reboots, etc.) refuse to run and return ErrMaintenanceActive. Read-only
// handlers and the maintenance toggle itself remain available.
func (h *Handler) handleSetMaintenanceMode(ctx context.Context, data json.RawMessage) (interface{}, error) {
	req, err := unmarshalRequest[setMaintenanceRequest](data)
	if err != nil {
		return nil, err
	}
	h.maintenanceMode.Store(req.Enabled)
	h.logger.Info("maintenance mode updated", "enabled", req.Enabled)
	return map[string]interface{}{
		"maintenance": req.Enabled,
	}, nil
}

// handleGetMaintenanceStatus returns the current maintenance flag.
func (h *Handler) handleGetMaintenanceStatus(ctx context.Context, data json.RawMessage) (interface{}, error) {
	return map[string]interface{}{
		"maintenance": h.maintenanceMode.Load(),
	}, nil
}

// IsInMaintenance reports whether the agent has been placed into maintenance
// mode. Safe for concurrent use.
func (h *Handler) IsInMaintenance() bool {
	return h.maintenanceMode.Load()
}
