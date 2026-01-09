package handler

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/slimrmm/slimrmm-agent/internal/remotedesktop"
)

// registerRemoteDesktopHandlers registers all remote desktop related handlers.
func (h *Handler) registerRemoteDesktopHandlers() {
	h.handlers["start_remote_desktop"] = h.handleStartRemoteDesktop
	h.handlers["stop_remote_desktop"] = h.handleStopRemoteDesktop
	h.handlers["get_monitors"] = h.handleGetMonitors
	h.handlers["remote_control"] = h.handleRemoteControl
	h.handlers["set_quality"] = h.handleSetQuality
	h.handlers["set_monitor"] = h.handleSetMonitor
	h.handlers["check_remote_desktop"] = h.handleCheckRemoteDesktop
}

type startRemoteDesktopRequest struct {
	SessionID string `json:"session_id"`
	Quality   string `json:"quality"`
	MonitorID int    `json:"monitor_id"`
}

func (h *Handler) handleStartRemoteDesktop(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req startRemoteDesktopRequest
	if err := json.Unmarshal(data, &req); err != nil {
		req.SessionID = h.cfg.GetUUID()
	}

	if req.SessionID == "" {
		req.SessionID = h.cfg.GetUUID()
	}

	h.logger.Info("starting remote desktop session", "session_id", req.SessionID)

	permStatus := remotedesktop.GetPermissionStatus()
	h.logger.Info("permission status", "permissions", permStatus)

	sendCallback := func(msg []byte) error {
		h.SendRaw(json.RawMessage(msg))
		return nil
	}

	result := remotedesktop.StartSession(req.SessionID, sendCallback, h.logger)

	if result.Success {
		h.logger.Info("remote desktop session started successfully", "session_id", req.SessionID)
		h.SendRaw(map[string]interface{}{
			"action":     "remote_desktop_started",
			"session_id": req.SessionID,
			"monitors":   result.Monitors,
		})
	} else {
		h.logger.Error("remote desktop session failed to start",
			"session_id", req.SessionID,
			"error", result.Error,
			"permissions", permStatus,
		)
		h.SendRaw(map[string]interface{}{
			"action":      "remote_desktop_error",
			"error":       result.Error,
			"permissions": permStatus,
		})
	}

	return result, nil
}

type stopRemoteDesktopRequest struct {
	SessionID string `json:"session_id"`
}

func (h *Handler) handleStopRemoteDesktop(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req stopRemoteDesktopRequest
	if err := json.Unmarshal(data, &req); err != nil {
		req.SessionID = h.cfg.GetUUID()
	}

	if req.SessionID == "" {
		req.SessionID = h.cfg.GetUUID()
	}

	result := remotedesktop.StopSession(req.SessionID)

	h.SendRaw(map[string]interface{}{
		"action": "remote_desktop_stopped",
	})

	return result, nil
}

func (h *Handler) handleGetMonitors(ctx context.Context, data json.RawMessage) (interface{}, error) {
	result := remotedesktop.GetMonitors()

	h.SendRaw(map[string]interface{}{
		"action":   "monitors",
		"monitors": result["monitors"],
	})

	return result, nil
}

type remoteControlRequest struct {
	SessionID string  `json:"session_id"`
	Type      string  `json:"type"`
	Action    string  `json:"action"`
	X         float64 `json:"x"`
	Y         float64 `json:"y"`
	Button    string  `json:"button"`
	Delta     float64 `json:"delta"`
	DeltaX    float64 `json:"dx"`
	DeltaY    float64 `json:"dy"`
	Key       string  `json:"key"`
	Code      string  `json:"code"`
	MonitorID int     `json:"monitor_id"`
	Quality   string  `json:"quality"`
	Text      string  `json:"text"`
}

func (h *Handler) handleRemoteControl(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req remoteControlRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("parsing request: %w", err)
	}

	if req.SessionID == "" {
		req.SessionID = h.cfg.GetUUID()
	}

	event := remotedesktop.InputEvent{
		Type:      req.Type,
		Action:    req.Action,
		X:         req.X,
		Y:         req.Y,
		Button:    req.Button,
		Delta:     req.Delta,
		DeltaX:    req.DeltaX,
		DeltaY:    req.DeltaY,
		Key:       req.Key,
		Code:      req.Code,
		MonitorID: req.MonitorID,
		Quality:   req.Quality,
		Text:      req.Text,
	}

	return remotedesktop.HandleRemoteControl(req.SessionID, event), nil
}

type setQualityRequest struct {
	SessionID string `json:"session_id"`
	Quality   string `json:"quality"`
}

func (h *Handler) handleSetQuality(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req setQualityRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("parsing request: %w", err)
	}

	if req.SessionID == "" {
		req.SessionID = h.cfg.GetUUID()
	}

	return remotedesktop.SetQuality(req.SessionID, req.Quality), nil
}

type setMonitorRequest struct {
	SessionID string `json:"session_id"`
	MonitorID int    `json:"monitor_id"`
}

func (h *Handler) handleSetMonitor(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req setMonitorRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("parsing request: %w", err)
	}

	if req.SessionID == "" {
		req.SessionID = h.cfg.GetUUID()
	}

	return remotedesktop.SetMonitor(req.SessionID, req.MonitorID), nil
}

func (h *Handler) handleCheckRemoteDesktop(ctx context.Context, data json.RawMessage) (interface{}, error) {
	deps := remotedesktop.CheckDependencies()

	return map[string]interface{}{
		"available":    deps["all_required"],
		"dependencies": deps,
	}, nil
}
