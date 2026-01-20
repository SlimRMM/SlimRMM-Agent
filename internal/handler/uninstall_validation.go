// Package handler provides pre-uninstall validation handlers.
// All handlers delegate to the validation service layer for proper MVC separation.
package handler

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/slimrmm/slimrmm-agent/internal/services/validation"
)

// registerValidationHandlers registers validation handlers.
func (h *Handler) registerValidationHandlers() {
	h.handlers["validate_uninstall"] = h.handleValidateUninstall
	h.handlers["detect_file_locks"] = h.handleDetectFileLocks
	h.handlers["analyze_dependencies"] = h.handleAnalyzeDependencies
	h.handlers["stop_services"] = h.handleStopServices
}

// handleValidateUninstall validates if a package can be uninstalled.
// Delegates to the validation service layer for proper MVC separation.
func (h *Handler) handleValidateUninstall(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req validation.ValidationRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("validating uninstall via service layer",
		"installation_type", req.InstallationType,
		"package_identifier", req.PackageIdentifier,
	)

	// Delegate to validation service
	result, err := h.validationService.Validate(ctx, &req)
	if err != nil {
		return map[string]interface{}{
			"action": "validate_uninstall_result",
			"status": "error",
			"error":  err.Error(),
		}, nil
	}

	return map[string]interface{}{
		"action":     "validate_uninstall_result",
		"status":     "success",
		"validation": result,
	}, nil
}

// DependencyAnalysisRequest represents a request to analyze dependencies.
type DependencyAnalysisRequest struct {
	InstallationType  string `json:"installation_type"`
	PackageIdentifier string `json:"package_identifier"`
}

// handleAnalyzeDependencies analyzes package dependencies.
// Delegates to the validation service layer for proper MVC separation.
func (h *Handler) handleAnalyzeDependencies(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req DependencyAnalysisRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("analyzing dependencies via service layer",
		"installation_type", req.InstallationType,
		"package_identifier", req.PackageIdentifier,
	)

	// Delegate to validation service
	result, err := h.validationService.AnalyzeDependencies(ctx, req.InstallationType, req.PackageIdentifier)
	if err != nil {
		return map[string]interface{}{
			"action": "analyze_dependencies_result",
			"status": "error",
			"error":  err.Error(),
		}, nil
	}

	return map[string]interface{}{
		"action":   "analyze_dependencies_result",
		"status":   "success",
		"analysis": result,
	}, nil
}

// StopServicesRequest represents a request to stop services (handler format).
type StopServicesRequest struct {
	Services       []string `json:"services"`
	ForceKill      bool     `json:"force_kill"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
}

// handleStopServices stops services before uninstallation.
// Delegates to the validation service layer for proper MVC separation.
func (h *Handler) handleStopServices(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req StopServicesRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("stopping services via service layer",
		"services", req.Services,
		"force_kill", req.ForceKill,
	)

	// Convert to service request format
	serviceReq := &validation.StopServicesRequest{
		Services:       req.Services,
		ForceKill:      req.ForceKill,
		TimeoutSeconds: req.TimeoutSeconds,
	}

	// Delegate to validation service
	result, err := h.validationService.StopServices(ctx, serviceReq)
	if err != nil {
		return map[string]interface{}{
			"action": "stop_services_result",
			"status": "error",
			"error":  err.Error(),
		}, nil
	}

	return map[string]interface{}{
		"action": "stop_services_result",
		"status": "success",
		"result": result,
	}, nil
}
