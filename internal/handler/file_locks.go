// Package handler provides file-lock detection and resolution handlers.
// All handlers delegate to service layer for business logic (MVC pattern).
package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/services/models"
	"github.com/slimrmm/slimrmm-agent/internal/services/process"
)

// FileLock represents a file lock with detailed information.
type FileLock struct {
	Path        string `json:"path"`
	ProcessName string `json:"process_name"`
	PID         int    `json:"pid"`
	User        string `json:"user,omitempty"`
	LockType    string `json:"lock_type,omitempty"` // read, write, exclusive
	FileType    string `json:"file_type,omitempty"` // file, directory
	Command     string `json:"command,omitempty"`
}

// FileLockDetectionRequest represents a request to detect file locks.
type FileLockDetectionRequest struct {
	Paths          []string `json:"paths"`
	IncludeSubdirs bool     `json:"include_subdirs"`
}

// FileLockDetectionResponse represents the response for file lock detection.
type FileLockDetectionResponse struct {
	Locks         []FileLock `json:"locks"`
	HasLocks      bool       `json:"has_locks"`
	TotalLocks    int        `json:"total_locks"`
	AffectedPaths []string   `json:"affected_paths"`
}

// FileLockResolutionRequest represents a request to resolve file locks.
type FileLockResolutionRequest struct {
	Locks    []FileLock `json:"locks"`
	Strategy string     `json:"strategy"` // terminate, schedule, rename, skip
	Force    bool       `json:"force"`
}

// FileLockResolutionResult represents the result of resolving a file lock.
type FileLockResolutionResult struct {
	Lock      FileLock `json:"lock"`
	Strategy  string   `json:"strategy"`
	Success   bool     `json:"success"`
	Error     string   `json:"error,omitempty"`
	NewPath   string   `json:"new_path,omitempty"`  // For rename strategy
	Scheduled bool     `json:"scheduled,omitempty"` // For schedule strategy
}

// ProcessInfo represents information about a running process.
type ProcessInfo struct {
	Name string `json:"name"`
	PID  int    `json:"pid"`
	User string `json:"user,omitempty"`
	CPU  string `json:"cpu,omitempty"`
	Mem  string `json:"mem,omitempty"`
}

// BatchKillProcessesRequest represents a request to kill multiple processes.
type BatchKillProcessesRequest struct {
	PIDs          []int  `json:"pids"`
	Signal        string `json:"signal"` // TERM or KILL
	GracePeriodMs int    `json:"grace_period_ms"`
}

// registerFileLockHandlers registers file lock handlers.
func (h *Handler) registerFileLockHandlers() {
	h.handlers["resolve_file_locks"] = h.handleResolveFileLocks
	h.handlers["batch_kill_processes"] = h.handleBatchKillProcesses
	h.handlers["get_process_info"] = h.handleGetProcessInfo
	h.handlers["get_process_tree"] = h.handleGetProcessTree
}

// handleDetectFileLocks handles file lock detection requests.
// Delegates to FileLockService for business logic (MVC pattern).
func (h *Handler) handleDetectFileLocks(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req FileLockDetectionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("detecting file locks", "paths", req.Paths)

	// Expand paths
	expandedPaths := make([]string, len(req.Paths))
	for i, path := range req.Paths {
		expandedPaths[i] = expandPath(path)
	}

	// Delegate to service layer (MVC pattern)
	serviceLocks, err := h.softwareServices.FileLock.DetectLocks(ctx, expandedPaths)
	if err != nil {
		h.logger.Warn("error detecting locks", "error", err)
	}

	// Convert service model to handler response format
	response := &FileLockDetectionResponse{
		Locks:         make([]FileLock, 0, len(serviceLocks)),
		AffectedPaths: make([]string, 0),
	}

	affectedPathsMap := make(map[string]bool)
	for _, sl := range serviceLocks {
		response.Locks = append(response.Locks, FileLock{
			Path:        sl.Path,
			ProcessName: sl.Process,
			PID:         sl.PID,
			LockType:    sl.LockType,
		})
		if !affectedPathsMap[sl.Path] {
			response.AffectedPaths = append(response.AffectedPaths, sl.Path)
			affectedPathsMap[sl.Path] = true
		}
	}

	response.HasLocks = len(response.Locks) > 0
	response.TotalLocks = len(response.Locks)

	return map[string]interface{}{
		"action":   "detect_file_locks_result",
		"status":   "success",
		"response": response,
	}, nil
}

// handleResolveFileLocks handles file lock resolution requests.
// Delegates to FileLockService for business logic (MVC pattern).
func (h *Handler) handleResolveFileLocks(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req FileLockResolutionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("resolving file locks",
		"count", len(req.Locks),
		"strategy", req.Strategy,
		"force", req.Force,
	)

	// Convert handler types to service models
	resolutions := make([]models.FileLockResolution, len(req.Locks))
	for i, lock := range req.Locks {
		resolutions[i] = models.FileLockResolution{
			Lock: models.FileLockInfo{
				Path:     lock.Path,
				Process:  lock.ProcessName,
				PID:      lock.PID,
				LockType: lock.LockType,
			},
			Strategy:  req.Strategy,
			ForceKill: req.Force,
		}
	}

	// Delegate to service layer (MVC pattern)
	err := h.softwareServices.FileLock.ResolveLocks(ctx, resolutions)

	// Build results for response
	var results []FileLockResolutionResult
	for _, lock := range req.Locks {
		result := FileLockResolutionResult{
			Lock:     lock,
			Strategy: req.Strategy,
			Success:  err == nil,
		}
		if err != nil {
			result.Error = err.Error()
		}
		results = append(results, result)
	}

	// Count successes
	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}

	return map[string]interface{}{
		"action":        "resolve_file_locks_result",
		"status":        "success",
		"results":       results,
		"total":         len(results),
		"success_count": successCount,
		"failed_count":  len(results) - successCount,
	}, nil
}

// handleBatchKillProcesses handles batch process termination.
// Delegates to ProcessService for business logic (MVC pattern).
func (h *Handler) handleBatchKillProcesses(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req BatchKillProcessesRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	signal := req.Signal
	if signal == "" {
		signal = "TERM"
	}

	h.logger.Info("batch killing processes",
		"count", len(req.PIDs),
		"signal", signal,
	)

	var results []map[string]interface{}

	// First pass: send initial signal
	for _, pid := range req.PIDs {
		result := map[string]interface{}{
			"pid":    pid,
			"signal": signal,
		}

		signalType := process.SignalTerm
		if signal == "KILL" {
			signalType = process.SignalKill
		}

		if err := h.processService.SendSignal(ctx, pid, signalType); err != nil {
			result["initial_success"] = false
			result["error"] = err.Error()
		} else {
			result["initial_success"] = true
		}

		results = append(results, result)
	}

	// Wait for grace period
	gracePeriod := time.Duration(req.GracePeriodMs) * time.Millisecond
	if gracePeriod == 0 {
		gracePeriod = 2 * time.Second
	}
	time.Sleep(gracePeriod)

	// Second pass: check if processes terminated, force kill if needed
	for i, pid := range req.PIDs {
		if h.processService.IsProcessRunning(ctx, pid) {
			// Force kill
			if err := h.processService.SendSignal(ctx, pid, process.SignalKill); err != nil {
				results[i]["final_success"] = false
				results[i]["force_kill_error"] = err.Error()
			} else {
				results[i]["force_kill"] = true
				time.Sleep(100 * time.Millisecond)
				results[i]["final_success"] = !h.processService.IsProcessRunning(ctx, pid)
			}
		} else {
			results[i]["final_success"] = true
		}
	}

	// Count final successes
	successCount := 0
	for _, r := range results {
		if success, ok := r["final_success"].(bool); ok && success {
			successCount++
		}
	}

	return map[string]interface{}{
		"action":        "batch_kill_result",
		"status":        "success",
		"results":       results,
		"total":         len(results),
		"success_count": successCount,
	}, nil
}

// handleGetProcessInfo handles process info requests.
// Delegates to ProcessService for business logic (MVC pattern).
func (h *Handler) handleGetProcessInfo(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req struct {
		PID int `json:"pid"`
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	info, err := h.processService.GetProcessInfo(ctx, req.PID)
	if err != nil {
		return map[string]interface{}{
			"action": "process_info_result",
			"status": "error",
			"error":  err.Error(),
		}, nil
	}

	return map[string]interface{}{
		"action": "process_info_result",
		"status": "success",
		"info": ProcessInfo{
			Name: info.Name,
			PID:  info.PID,
			User: info.User,
			CPU:  info.CPU,
			Mem:  info.Mem,
		},
	}, nil
}

// handleGetProcessTree handles process tree requests.
// Delegates to ProcessService for business logic (MVC pattern).
func (h *Handler) handleGetProcessTree(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req struct {
		PID int `json:"pid"`
	}
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	children, err := h.processService.GetProcessTree(ctx, req.PID)
	if err != nil {
		return map[string]interface{}{
			"action": "process_tree_result",
			"status": "error",
			"error":  err.Error(),
		}, nil
	}

	return map[string]interface{}{
		"action":   "process_tree_result",
		"status":   "success",
		"pid":      req.PID,
		"children": children,
	}, nil
}
