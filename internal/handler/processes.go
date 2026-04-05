// Package handler - list_processes and maintenance mode handlers.
package handler

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/slimrmm/slimrmm-agent/internal/actions"
)

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
// is set, other handlers may opt to refuse destructive work (script-exec,
// patching, etc.) by checking IsInMaintenance().
//
// TODO: wire up rejection logic in long-running / destructive handlers to
// honour this flag. For now we only record the state so the backend can sync
// it and probe it via get_maintenance_status.
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
