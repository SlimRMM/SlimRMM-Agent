// Package handler provides remote desktop action handlers.
package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/i18n"
	"github.com/slimrmm/slimrmm-agent/internal/services/remotedesktop"
)

// registerRemoteDesktopHandlers registers all remote desktop action handlers.
func (h *Handler) registerRemoteDesktopHandlers() {
	h.handlers["install_remote_desktop"] = h.handleInstallRemoteDesktop
	h.handlers["uninstall_remote_desktop"] = h.handleUninstallRemoteDesktop
	h.handlers["get_remote_desktop_status"] = h.handleGetRemoteDesktopStatus
	h.handlers["remote_desktop_connect"] = h.handleRemoteDesktopConnect
	h.handlers["remote_desktop_disconnect"] = h.handleRemoteDesktopDisconnect
	h.handlers["remote_desktop_request_consent"] = h.handleRemoteDesktopRequestConsent
}

// installRemoteDesktopRequest is the payload for install_remote_desktop.
type installRemoteDesktopRequest struct {
	RelayServer string `json:"relay_server"`
	IDServer    string `json:"id_server"`
	PublicKey   string `json:"public_key"`
	Password    string `json:"password,omitempty"`
}

// handleInstallRemoteDesktop installs and configures RustDesk.
func (h *Handler) handleInstallRemoteDesktop(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if h.IsInMaintenance() {
		return nil, ErrMaintenanceActive
	}

	req, err := unmarshalRequest[installRemoteDesktopRequest](data)
	if err != nil {
		return nil, err
	}

	cfg := remotedesktop.Config{
		RelayServer: req.RelayServer,
		IDServer:    req.IDServer,
		PublicKey:   req.PublicKey,
		Password:    req.Password,
	}

	if err := h.remoteDesktopService.Install(ctx, cfg); err != nil {
		return nil, fmt.Errorf("installing remote desktop: %w", err)
	}

	status, err := h.remoteDesktopService.GetStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting remote desktop status after install: %w", err)
	}

	return status, nil
}

// handleUninstallRemoteDesktop removes RustDesk from the system.
func (h *Handler) handleUninstallRemoteDesktop(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if h.IsInMaintenance() {
		return nil, ErrMaintenanceActive
	}

	if err := h.remoteDesktopService.Uninstall(ctx); err != nil {
		return nil, fmt.Errorf("uninstalling remote desktop: %w", err)
	}

	return map[string]interface{}{
		"uninstalled": true,
	}, nil
}

// handleGetRemoteDesktopStatus returns the current RustDesk status.
func (h *Handler) handleGetRemoteDesktopStatus(ctx context.Context, data json.RawMessage) (interface{}, error) {
	status, err := h.remoteDesktopService.GetStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting remote desktop status: %w", err)
	}

	return status, nil
}

// handleRemoteDesktopConnect ensures RustDesk is running and returns connection info.
func (h *Handler) handleRemoteDesktopConnect(ctx context.Context, data json.RawMessage) (interface{}, error) {
	status, err := h.remoteDesktopService.GetStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting remote desktop status: %w", err)
	}

	if !status.Installed {
		return nil, fmt.Errorf("remote desktop is not installed")
	}

	if !status.Running {
		return nil, fmt.Errorf("remote desktop service is not running")
	}

	result := remotedesktop.ConnectResult{
		ID:     status.ID,
		Status: *status,
	}

	return result, nil
}

// handleRemoteDesktopDisconnect is a no-op; RustDesk sessions end naturally.
func (h *Handler) handleRemoteDesktopDisconnect(ctx context.Context, data json.RawMessage) (interface{}, error) {
	return map[string]interface{}{
		"disconnected": true,
	}, nil
}

// remoteDesktopConsentRequest is the payload for remote_desktop_request_consent.
type remoteDesktopConsentRequest struct {
	RequesterName string `json:"requester_name"`
}

// handleRemoteDesktopRequestConsent prompts the local user for consent.
func (h *Handler) handleRemoteDesktopRequestConsent(ctx context.Context, data json.RawMessage) (interface{}, error) {
	req, err := unmarshalRequest[remoteDesktopConsentRequest](data)
	if err != nil {
		return nil, err
	}

	if req.RequesterName == "" {
		return nil, fmt.Errorf("%s: requester_name is required", i18n.MsgInvalidRequest)
	}

	granted, err := h.remoteDesktopService.RequestConsent(ctx, req.RequesterName, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("requesting remote desktop consent: %w", err)
	}

	return map[string]interface{}{
		"granted": granted,
	}, nil
}
