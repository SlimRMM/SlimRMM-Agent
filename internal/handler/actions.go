// Package handler provides action handler implementations.
package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/actions"
	"github.com/slimrmm/slimrmm-agent/internal/helper"
	"github.com/slimrmm/slimrmm-agent/internal/logging"
	"github.com/slimrmm/slimrmm-agent/internal/osquery"
	"github.com/slimrmm/slimrmm-agent/internal/security/archive"
	"github.com/slimrmm/slimrmm-agent/internal/service"
	"github.com/slimrmm/slimrmm-agent/internal/updater"
	"github.com/slimrmm/slimrmm-agent/internal/winget"
	"github.com/slimrmm/slimrmm-agent/pkg/version"
)

// registerAllHandlers registers all action handlers.
// Handler names match Python agent for API compatibility.
func (h *Handler) registerHandlers() {
	// Basic - Python compatible names
	h.handlers["ping"] = h.handlePing
	h.handlers["heartbeat"] = h.handleHeartbeat
	h.handlers["system_stats"] = h.handleGetSystemStats     // Python: system_stats
	h.handlers["get_system_stats"] = h.handleGetSystemStats // Alias for compatibility

	// Commands
	h.handlers["custom_command"] = h.handleCustomCommand
	h.handlers["execute_script"] = h.handleExecuteScript

	// File operations - Python compatible names
	h.handlers["list_dir"] = h.handleListDir
	h.handlers["create_dir"] = h.handleCreateFolder    // Python: create_dir
	h.handlers["create_folder"] = h.handleCreateFolder // Alias
	h.handlers["delete_entry"] = h.handleDeleteEntry
	h.handlers["rename_entry"] = h.handleRenameEntry
	h.handlers["chmod"] = h.handleChmod
	h.handlers["chown"] = h.handleChown
	h.handlers["zip_entry"] = h.handleZipEntry
	h.handlers["unzip_entry"] = h.handleUnzipEntry

	// File transfer - Python compatible names
	h.handlers["start_upload"] = h.handleStartUpload
	h.handlers["upload_chunk"] = h.handleUploadChunk
	h.handlers["finish_upload"] = h.handleFinishUpload
	h.handlers["cancel_upload"] = h.handleCancelUpload
	h.handlers["download_file"] = h.handleDownloadFile
	h.handlers["download_chunk"] = h.handleDownloadChunk
	h.handlers["download_url"] = h.handleDownloadURL

	// Software
	h.handlers["get_software_inventory"] = h.handleGetSoftwareInventory
	h.handlers["get_available_updates"] = h.handleGetAvailableUpdates
	h.handlers["execute_patches"] = h.handleExecutePatches
	h.handlers["uninstall_software"] = h.handleUninstallSoftware
	h.handlers["install_software"] = h.handleInstallSoftware
	h.handlers["download_and_install_msi"] = h.handleDownloadAndInstallMSI

	// System control
	h.handlers["restart"] = h.handleRestart
	h.handlers["shutdown"] = h.handleShutdown
	h.handlers["cancel_shutdown"] = h.handleCancelShutdown

	// Service management
	h.handlers["list_services"] = h.handleListServices
	h.handlers["start_service"] = h.handleStartService
	h.handlers["stop_service"] = h.handleStopService
	h.handlers["restart_service"] = h.handleRestartService
	h.handlers["set_service_start_type"] = h.handleSetServiceStartType

	// Terminal - Python compatible names
	h.handlers["terminal"] = h.handleStartTerminal       // Python: terminal
	h.handlers["start_terminal"] = h.handleStartTerminal // Alias
	h.handlers["terminal_input"] = h.handleTerminalInput
	h.handlers["terminal_output"] = h.handleTerminalOutput
	h.handlers["terminal_resize"] = h.handleResizeTerminal
	h.handlers["terminal_stop"] = h.handleStopTerminal // Python: terminal_stop
	h.handlers["stop_terminal"] = h.handleStopTerminal // Alias

	// osquery - Python compatible names
	h.handlers["osquery"] = h.handleRunOsquery     // Python: osquery
	h.handlers["run_osquery"] = h.handleRunOsquery // Alias

	// Agent management - Python compatible names
	h.handlers["update_agent"] = h.handleUpdateAgent
	h.handlers["check_update"] = h.handleCheckUpdate     // Check for updates without installing
	h.handlers["update_osquery"] = h.handleUpdateOsquery // Python: update_osquery

	// Winget handlers (Windows only)
	h.handlers["install_winget"] = h.handleInstallWinget
	h.handlers["get_winget_status"] = h.handleGetWingetStatus
	h.handlers["execute_winget_policy"] = h.handleExecuteWingetPolicy
	h.handlers["execute_winget_install_policy"] = h.handleExecuteWingetInstallPolicy
	h.handlers["execute_winget_update"] = h.handleExecuteWingetUpdate
	h.handlers["execute_winget_updates"] = h.handleExecuteWingetUpdates

	// Software installation handlers (Windows only)
	h.registerSoftwareHandlers()

	// Software uninstallation handlers (all platforms)
	h.registerUninstallHandlers()

	// Proxmox handlers (only active on Proxmox hosts)
	h.registerProxmoxHandlers()

	// Remote desktop handlers
	h.registerRemoteDesktopHandlers()

	// Tamper protection handlers
	h.handlers["enable_tamper_protection"] = h.handleEnableTamperProtection
	h.handlers["disable_tamper_protection"] = h.handleDisableTamperProtection
	h.handlers["set_uninstall_key"] = h.handleSetUninstallKey
	h.handlers["get_tamper_status"] = h.handleGetTamperStatus
	h.handlers["install_watchdog"] = h.handleInstallWatchdog
	h.handlers["uninstall_watchdog"] = h.handleUninstallWatchdog

	// Docker handlers
	h.handlers["docker_info"] = h.handleDockerInfo
	h.handlers["docker_list_containers"] = h.handleDockerListContainers
	h.handlers["docker_container_action"] = h.handleDockerContainerAction
	h.handlers["docker_remove_container"] = h.handleDockerRemoveContainer
	h.handlers["docker_container_logs"] = h.handleDockerContainerLogs
	h.handlers["docker_container_stats"] = h.handleDockerContainerStats
	h.handlers["docker_inspect_container"] = h.handleDockerInspectContainer
	h.handlers["docker_exec"] = h.handleDockerExec
	h.handlers["docker_list_images"] = h.handleDockerListImages
	h.handlers["docker_remove_image"] = h.handleDockerRemoveImage
	h.handlers["docker_pull_image"] = h.handleDockerPullImage
	h.handlers["docker_list_volumes"] = h.handleDockerListVolumes
	h.handlers["docker_remove_volume"] = h.handleDockerRemoveVolume
	h.handlers["docker_list_networks"] = h.handleDockerListNetworks
	h.handlers["docker_compose_action"] = h.handleDockerComposeAction

	// Compliance handlers
	h.handlers["run_compliance_check"] = h.handleRunComplianceCheck

	// Agent logs handler
	h.handlers["pull_logs"] = h.handlePullLogs

	// Docker policy handlers
	h.handlers["docker_policy_execute"] = h.handleDockerPolicyExecute
	h.handlers["docker_prune_images"] = h.handleDockerPruneImages
	h.handlers["docker_prune_volumes"] = h.handleDockerPruneVolumes
	h.handlers["docker_prune_networks"] = h.handleDockerPruneNetworks
	h.handlers["docker_prune_all"] = h.handleDockerPruneAll
	h.handlers["docker_restart_unhealthy"] = h.handleDockerRestartUnhealthy
	h.handlers["docker_update_images"] = h.handleDockerUpdateImages
	h.handlers["docker_health_check"] = h.handleDockerHealthCheck
}

// Command handlers

type customCommandRequest struct {
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

func (h *Handler) handleCustomCommand(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req customCommandRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	timeout := time.Duration(req.Timeout) * time.Second
	if timeout == 0 {
		timeout = actions.DefaultCommandTimeout
	}

	return actions.ExecuteCommand(ctx, req.Command, timeout)
}

type executeScriptRequest struct {
	ExecutionID    string `json:"execution_id"`
	ScriptName     string `json:"script_name"`
	ScriptType     string `json:"script_type"`
	ScriptContent  string `json:"script_content"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

func (h *Handler) handleExecuteScript(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req executeScriptRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = actions.DefaultCommandTimeout
	}

	startedAt := time.Now()
	result, err := actions.ExecuteScript(ctx, req.ScriptType, req.ScriptContent, timeout)
	completedAt := time.Now()
	durationMs := completedAt.Sub(startedAt).Milliseconds()

	// Build response in format expected by backend
	response := map[string]interface{}{
		"execution_id": req.ExecutionID,
		"started_at":   startedAt.UTC().Format(time.RFC3339),
		"completed_at": completedAt.UTC().Format(time.RFC3339),
		"duration_ms":  durationMs,
	}

	if err != nil {
		response["status"] = "failed"
		response["exit_code"] = -1
		response["error_output"] = err.Error()
		response["output"] = ""
	} else if result != nil {
		response["status"] = "completed"
		response["exit_code"] = result.ExitCode
		response["output"] = result.Stdout
		response["error_output"] = result.Stderr
	}

	// Send as script_execution_result action
	h.SendRaw(map[string]interface{}{
		"action":       "script_execution_result",
		"execution_id": req.ExecutionID,
		"status":       response["status"],
		"exit_code":    response["exit_code"],
		"output":       response["output"],
		"error_output": response["error_output"],
		"started_at":   response["started_at"],
		"completed_at": response["completed_at"],
		"duration_ms":  response["duration_ms"],
	})

	return response, nil
}

// File operation handlers

type listDirRequest struct {
	Path string `json:"path"`
}

func (h *Handler) handleListDir(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req listDirRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	return actions.ListDirectory(req.Path)
}

type createFolderRequest struct {
	Path string `json:"path"`
	Mode string `json:"mode,omitempty"`
}

func (h *Handler) handleCreateFolder(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req createFolderRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if err := actions.CreateFolder(req.Path, 0755); err != nil {
		return nil, err
	}

	return map[string]string{"status": "created", "path": req.Path}, nil
}

type deleteEntryRequest struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive,omitempty"`
}

func (h *Handler) handleDeleteEntry(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req deleteEntryRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if err := actions.DeleteEntry(req.Path, req.Recursive); err != nil {
		return nil, err
	}

	return map[string]string{"status": "deleted", "path": req.Path}, nil
}

type renameEntryRequest struct {
	OldPath string `json:"old_path"`
	NewPath string `json:"new_path"`
}

func (h *Handler) handleRenameEntry(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req renameEntryRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if err := actions.RenameEntry(req.OldPath, req.NewPath); err != nil {
		return nil, err
	}

	return map[string]string{"status": "renamed", "old_path": req.OldPath, "new_path": req.NewPath}, nil
}

type chmodRequest struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

func (h *Handler) handleChmod(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req chmodRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if err := actions.Chmod(req.Path, req.Mode); err != nil {
		return nil, err
	}

	return map[string]string{"status": "changed", "path": req.Path, "mode": req.Mode}, nil
}

type chownRequest struct {
	Path  string `json:"path"`
	Owner string `json:"owner"`
	Group string `json:"group,omitempty"`
}

func (h *Handler) handleChown(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req chownRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if err := actions.Chown(req.Path, req.Owner, req.Group); err != nil {
		return nil, err
	}

	return map[string]string{"status": "changed", "path": req.Path, "owner": req.Owner}, nil
}

type zipEntryRequest struct {
	// Agent format
	SourcePath string `json:"source_path"`
	OutputPath string `json:"output_path,omitempty"`
	// Frontend format
	Path   string `json:"path"`
	Output string `json:"output,omitempty"`
}

func (h *Handler) handleZipEntry(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req zipEntryRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Support both frontend (path/output) and agent (source_path/output_path) formats
	sourcePath := req.SourcePath
	if sourcePath == "" {
		sourcePath = req.Path
	}
	outputPath := req.OutputPath
	if outputPath == "" {
		outputPath = req.Output
	}
	if outputPath == "" {
		outputPath = sourcePath + ".zip"
	}

	if err := archive.CreateZip(sourcePath, outputPath); err != nil {
		return nil, err
	}

	return map[string]string{"status": "zipped", "source": sourcePath, "output": outputPath}, nil
}

type unzipEntryRequest struct {
	// Agent format
	SourcePath string `json:"source_path"`
	OutputPath string `json:"output_path,omitempty"`
	// Frontend format
	Path   string `json:"path"`
	Output string `json:"output,omitempty"`
}

func (h *Handler) handleUnzipEntry(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req unzipEntryRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Support both frontend (path/output) and agent (source_path/output_path) formats
	sourcePath := req.SourcePath
	if sourcePath == "" {
		sourcePath = req.Path
	}
	outputPath := req.OutputPath
	if outputPath == "" {
		outputPath = req.Output
	}
	if outputPath == "" {
		// Remove .zip extension for output directory
		outputPath = sourcePath
		if len(outputPath) > 4 && outputPath[len(outputPath)-4:] == ".zip" {
			outputPath = outputPath[:len(outputPath)-4]
		}
	}

	limits := archive.DefaultLimits()
	if err := archive.ExtractZip(sourcePath, outputPath, limits); err != nil {
		return nil, err
	}

	return map[string]string{"status": "unzipped", "source": sourcePath, "output": outputPath}, nil
}

// Software handlers

func (h *Handler) handleGetSoftwareInventory(ctx context.Context, data json.RawMessage) (interface{}, error) {
	return actions.GetSoftwareInventory(ctx)
}

func (h *Handler) handleGetAvailableUpdates(ctx context.Context, data json.RawMessage) (interface{}, error) {
	return actions.GetAvailableUpdates(ctx)
}

// osquery handlers

type runOsqueryRequest struct {
	Query    string `json:"query"`
	ScanType string `json:"scan_type,omitempty"`
	Timeout  int    `json:"timeout,omitempty"`
}

func (h *Handler) handleRunOsquery(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req runOsqueryRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("received osquery request", "scan_type", req.ScanType, "query_len", len(req.Query))

	// Handle updates scan type specially (agent-side, no SQL)
	if req.ScanType == "updates" || (req.Query == "" && req.ScanType == "") {
		// If no query provided or scan_type is updates, use internal update checker
		h.logger.Info("starting updates scan")
		result, err := actions.GetAvailableUpdates(ctx)
		if err != nil {
			h.logger.Error("updates scan failed", "error", err)
			return nil, err
		}
		if result != nil {
			h.logger.Info("updates scan completed", "count", result.Count, "source", result.Source)
			// Update winget helper availability based on scan success
			if result.WingetHelperSuccess {
				h.SetWingetHelperAvailable(true)
			}
		}
		return result, nil
	}

	// If query is empty but scan_type is set, we can't run osquery
	if req.Query == "" {
		h.logger.Warn("empty query for scan_type", "scan_type", req.ScanType)
		return []interface{}{}, nil
	}

	client := osquery.New()
	if !client.IsAvailable() {
		// Osquery might be installing - wait for it with retries
		h.logger.Info("osquery not available, waiting for installation", "scan_type", req.ScanType)
		const maxRetries = 6
		const retryDelay = 5 * time.Second
	waitLoop:
		for i := 0; i < maxRetries; i++ {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(retryDelay):
				client = osquery.New()
				if client.IsAvailable() {
					h.logger.Info("osquery now available after waiting", "scan_type", req.ScanType, "attempts", i+1)
					break waitLoop
				}
			}
		}
		if !client.IsAvailable() {
			h.logger.Error("osquery not available after waiting", "scan_type", req.ScanType, "waited_seconds", maxRetries*int(retryDelay.Seconds()))
			return nil, fmt.Errorf("osquery not available")
		}
	}

	timeout := time.Duration(req.Timeout) * time.Second
	if timeout == 0 {
		timeout = osquery.DefaultTimeout
	}

	result, err := client.QueryWithTimeout(ctx, req.Query, timeout)
	if err != nil {
		h.logger.Error("osquery failed", "scan_type", req.ScanType, "error", err)
		return nil, err
	}

	h.logger.Info("osquery completed", "scan_type", req.ScanType, "rows", result.Count)
	return result, nil
}

// File transfer handlers

type startUploadRequest struct {
	SessionID string `json:"session_id"`
	Path      string `json:"path"`
	TotalSize int64  `json:"total_size"`
}

func (h *Handler) handleStartUpload(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req startUploadRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if err := h.uploadManager.StartUpload(req.SessionID, req.Path, req.TotalSize); err != nil {
		return nil, err
	}

	return map[string]string{"status": "started", "session_id": req.SessionID}, nil
}

type uploadChunkRequest struct {
	// Session-based upload (agent format)
	SessionID  string `json:"session_id"`
	ChunkIndex int    `json:"chunk_index"`
	// Simple upload (frontend format)
	Path   string `json:"path"`
	Offset int64  `json:"offset"`
	IsLast bool   `json:"is_last"`
	// Common field
	Data string `json:"data"` // Base64 encoded
}

func (h *Handler) handleUploadChunk(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req uploadChunkRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	chunkData, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		return nil, fmt.Errorf("decoding chunk data: %w", err)
	}

	// Check if using session-based upload or simple upload
	if req.SessionID != "" {
		// Session-based upload (agent format)
		if err := h.uploadManager.UploadChunk(req.SessionID, req.ChunkIndex, chunkData); err != nil {
			return nil, err
		}
		return map[string]interface{}{"status": "received", "chunk_index": req.ChunkIndex}, nil
	}

	// Simple upload (frontend format) - write directly to file
	if req.Path == "" {
		return nil, fmt.Errorf("path or session_id required")
	}

	var file *os.File
	if req.Offset == 0 {
		// First chunk - create new file
		file, err = os.Create(req.Path)
	} else {
		// Subsequent chunk - open for append
		file, err = os.OpenFile(req.Path, os.O_WRONLY|os.O_APPEND, 0644)
	}
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	if _, err := file.Write(chunkData); err != nil {
		return nil, fmt.Errorf("writing chunk: %w", err)
	}

	response := map[string]interface{}{
		"status": "received",
		"offset": req.Offset,
		"path":   req.Path,
	}

	if req.IsLast {
		response["status"] = "complete"
		// Send upload_complete action that frontend expects
		h.SendRaw(map[string]interface{}{
			"action":   "upload_complete",
			"path":     req.Path,
			"filename": filepath.Base(req.Path),
			"status":   "complete",
		})
	}

	return response, nil
}

type finishUploadRequest struct {
	SessionID string `json:"session_id"`
}

func (h *Handler) handleFinishUpload(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req finishUploadRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	return h.uploadManager.FinishUpload(req.SessionID)
}

type cancelUploadRequest struct {
	SessionID string `json:"session_id"`
}

func (h *Handler) handleCancelUpload(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req cancelUploadRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if err := h.uploadManager.CancelUpload(req.SessionID); err != nil {
		return nil, err
	}

	return map[string]string{"status": "cancelled", "session_id": req.SessionID}, nil
}

type downloadFileRequest struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset,omitempty"`
	Limit  int64  `json:"limit,omitempty"`
}

func (h *Handler) handleDownloadFile(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req downloadFileRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	result, err := actions.DownloadFile(req.Path, req.Offset, req.Limit)
	if err != nil {
		return nil, err
	}

	// For small files with content, send download_data action that frontend expects
	if result.Content != "" {
		h.SendRaw(map[string]interface{}{
			"action":   "download_data",
			"data":     result.Content,
			"filename": filepath.Base(req.Path),
		})
	}

	return result, nil
}

type downloadChunkRequest struct {
	Path       string `json:"path"`
	ChunkIndex int    `json:"chunk_index"`
}

func (h *Handler) handleDownloadChunk(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req downloadChunkRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	chunkData, err := actions.DownloadChunk(req.Path, req.ChunkIndex)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"path":        req.Path,
		"chunk_index": req.ChunkIndex,
		"data":        base64.StdEncoding.EncodeToString(chunkData),
	}, nil
}

type downloadURLRequest struct {
	URL      string `json:"url"`
	DestPath string `json:"dest_path"`
}

func (h *Handler) handleDownloadURL(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req downloadURLRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	return actions.DownloadURL(req.URL, req.DestPath)
}

// System control handlers

type systemControlRequest struct {
	Force bool `json:"force,omitempty"`
	Delay int  `json:"delay,omitempty"`
}

func (h *Handler) handleRestart(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req systemControlRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if err := actions.RestartSystem(ctx, req.Force, req.Delay); err != nil {
		return nil, err
	}

	return map[string]string{"status": "restart_initiated"}, nil
}

func (h *Handler) handleShutdown(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req systemControlRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if err := actions.ShutdownSystem(ctx, req.Force, req.Delay); err != nil {
		return nil, err
	}

	return map[string]string{"status": "shutdown_initiated"}, nil
}

func (h *Handler) handleCancelShutdown(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if err := actions.CancelShutdown(ctx); err != nil {
		return nil, err
	}

	return map[string]string{"status": "shutdown_cancelled"}, nil
}

type rebootConfig struct {
	Enabled      bool   `json:"enabled"`
	Condition    string `json:"condition"`
	DelayMinutes int    `json:"delay_minutes"`
	NotifyUser   bool   `json:"notify_user"`
}

type executePatchesRequest struct {
	ExecutionID string `json:"execution_id"`
	PolicyID    string `json:"policy_id"`
	Patches     []struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Category string `json:"category"`
	} `json:"patches"`
	Categories     []string     `json:"categories,omitempty"`
	RebootConfig   rebootConfig `json:"reboot_config"`
	TimeoutSeconds int          `json:"timeout_seconds,omitempty"`
}

func (h *Handler) handleExecutePatches(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req executePatchesRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	startedAt := time.Now()
	result, err := actions.ExecutePatches(ctx, req.Categories, req.RebootConfig.Enabled)
	completedAt := time.Now()
	durationMs := completedAt.Sub(startedAt).Milliseconds()

	// Build response in format expected by backend
	response := map[string]interface{}{
		"action":       "patch_execution_result",
		"execution_id": req.ExecutionID,
		"duration_ms":  durationMs,
	}

	if err != nil {
		response["status"] = "failed"
		response["error_output"] = err.Error()
		response["output"] = ""
		response["patches_installed"] = []string{}
		response["patches_failed"] = []string{}
	} else if result != nil {
		response["status"] = "completed"
		response["output"] = result.Stdout
		response["error_output"] = result.Stderr
		// For now, we don't track individual patches
		response["patches_installed"] = []string{}
		response["patches_failed"] = []string{}
		response["reboot_required"] = req.RebootConfig.Enabled
	}

	h.SendRaw(response)
	return response, nil
}

type uninstallSoftwareRequest struct {
	PackageName string `json:"package_name"`
}

func (h *Handler) handleUninstallSoftware(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req uninstallSoftwareRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	return actions.UninstallSoftware(ctx, req.PackageName)
}

// Terminal handlers

type startTerminalRequest struct {
	TerminalID string `json:"terminal_id"`
	Rows       uint16 `json:"rows,omitempty"`
	Cols       uint16 `json:"cols,omitempty"`
}

// defaultTerminalID is used when frontend doesn't provide a terminal_id
const defaultTerminalID = "default"

func (h *Handler) handleStartTerminal(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req startTerminalRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Use default terminal ID if not provided (frontend compatibility)
	terminalID := req.TerminalID
	if terminalID == "" {
		terminalID = defaultTerminalID
	}

	term, err := h.terminalManager.StartTerminal(terminalID)
	if err != nil {
		return nil, err
	}

	// Set initial size if provided
	if req.Rows > 0 && req.Cols > 0 {
		term.Resize(req.Rows, req.Cols)
	}

	// Start output streaming goroutine
	go h.streamTerminalOutput(terminalID)

	return map[string]string{"status": "started", "terminal_id": terminalID}, nil
}

// streamTerminalOutput continuously sends terminal output to the backend.
// Format matches Python agent: UTF-8 decoded string in "data" field.
func (h *Handler) streamTerminalOutput(terminalID string) {
	outputChan, err := h.terminalManager.GetOutput(terminalID)
	if err != nil {
		return
	}

	for data := range outputChan {
		if len(data) == 0 {
			continue
		}

		// Send output as UTF-8 string (matching Python agent format)
		// Replace invalid UTF-8 sequences to prevent encoding errors
		output := sanitizeUTF8(data)

		h.SendRaw(map[string]interface{}{
			"action":      "terminal_output",
			"terminal_id": terminalID,
			"data":        output, // Python uses "data" field
			"running":     h.terminalManager.IsRunning(terminalID),
		})
	}

	// Notify that terminal has closed
	h.SendRaw(map[string]interface{}{
		"action":      "terminal_output",
		"terminal_id": terminalID,
		"data":        "",
		"running":     false,
		"closed":      true,
	})
}

// sanitizeUTF8 converts bytes to a valid UTF-8 string,
// replacing invalid sequences with the replacement character.
func sanitizeUTF8(data []byte) string {
	// strings.ToValidUTF8 replaces invalid UTF-8 with replacement char
	return strings.ToValidUTF8(string(data), "\uFFFD")
}

type terminalInputRequest struct {
	TerminalID string `json:"terminal_id"`
	Input      string `json:"input"`
	Data       string `json:"data"` // Python compatibility: uses "data" field
	IsBase64   bool   `json:"is_base64,omitempty"`
}

func (h *Handler) handleTerminalInput(ctx context.Context, data json.RawMessage) (interface{}, error) {
	h.logger.Debug("handleTerminalInput called", "raw_data", string(data))

	var req terminalInputRequest
	if err := json.Unmarshal(data, &req); err != nil {
		h.logger.Error("failed to unmarshal terminal input", "error", err)
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Use default terminal ID if not provided (frontend compatibility)
	terminalID := req.TerminalID
	if terminalID == "" {
		terminalID = defaultTerminalID
	}

	// Support both "input" (Go) and "data" (Python) fields
	inputData := req.Input
	if inputData == "" {
		inputData = req.Data
	}

	h.logger.Debug("terminal input parsed",
		"terminal_id", terminalID,
		"input", inputData,
		"input_len", len(inputData),
		"is_base64", req.IsBase64)

	var err error
	if req.IsBase64 {
		// Decode base64 input for raw bytes (special keys, etc.)
		rawData, decErr := base64.StdEncoding.DecodeString(inputData)
		if decErr != nil {
			return nil, fmt.Errorf("decoding base64 input: %w", decErr)
		}
		err = h.terminalManager.SendInputRaw(terminalID, rawData)
	} else {
		err = h.terminalManager.SendInput(terminalID, inputData)
	}

	if err != nil {
		h.logger.Error("failed to send terminal input", "error", err)
		return nil, err
	}

	h.logger.Debug("terminal input sent successfully")
	return map[string]string{"status": "sent"}, nil
}

type terminalOutputRequest struct {
	TerminalID string `json:"terminal_id"`
	MaxBytes   int    `json:"max_bytes,omitempty"`
}

func (h *Handler) handleTerminalOutput(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req terminalOutputRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	maxBytes := req.MaxBytes
	if maxBytes == 0 {
		maxBytes = 32768 // 32 KB default
	}

	output, err := h.terminalManager.ReadOutput(ctx, req.TerminalID, maxBytes)
	if err != nil {
		return nil, err
	}

	// Return as UTF-8 string in "data" field to match Python agent format
	return map[string]interface{}{
		"terminal_id": req.TerminalID,
		"data":        sanitizeUTF8(output),
		"running":     h.terminalManager.IsRunning(req.TerminalID),
	}, nil
}

type resizeTerminalRequest struct {
	TerminalID string `json:"terminal_id"`
	Rows       uint16 `json:"rows"`
	Cols       uint16 `json:"cols"`
}

func (h *Handler) handleResizeTerminal(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req resizeTerminalRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Use default terminal ID if not provided
	terminalID := req.TerminalID
	if terminalID == "" {
		terminalID = defaultTerminalID
	}

	if err := h.terminalManager.ResizeTerminal(terminalID, req.Rows, req.Cols); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"status":      "resized",
		"terminal_id": terminalID,
		"rows":        req.Rows,
		"cols":        req.Cols,
	}, nil
}

type stopTerminalRequest struct {
	TerminalID string `json:"terminal_id"`
}

func (h *Handler) handleStopTerminal(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req stopTerminalRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Use default terminal ID if not provided
	terminalID := req.TerminalID
	if terminalID == "" {
		terminalID = defaultTerminalID
	}

	if err := h.terminalManager.StopTerminal(terminalID); err != nil {
		return nil, err
	}

	return map[string]string{"status": "stopped", "terminal_id": terminalID}, nil
}

// Agent update handlers

type updateAgentRequest struct {
	URL     string `json:"url,omitempty"`
	Version string `json:"version,omitempty"`
	Hash    string `json:"hash,omitempty"`
	Force   bool   `json:"force,omitempty"`
}

func (h *Handler) handleUpdateAgent(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req updateAgentRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Check for available updates
	info, err := h.updater.CheckForUpdate(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking for update: %w", err)
	}

	if info == nil && !req.Force {
		return map[string]interface{}{
			"status":  "up_to_date",
			"message": "already running the latest version",
		}, nil
	}

	// If we have update info from GitHub (or forced update with URL)
	if info == nil && req.URL != "" {
		// Use provided URL for forced update
		info = &updater.UpdateInfo{
			Version:     req.Version,
			DownloadURL: req.URL,
		}
	}

	if info == nil {
		return map[string]interface{}{
			"status":  "up_to_date",
			"message": "no update available",
		}, nil
	}

	// Perform the update (this will handle maintenance mode)
	result, err := h.updater.PerformUpdate(ctx, info)
	if err != nil {
		return map[string]interface{}{
			"status":      "failed",
			"error":       err.Error(),
			"rolled_back": result != nil && result.RolledBack,
		}, nil
	}

	return map[string]interface{}{
		"status":       "updated",
		"old_version":  result.OldVersion,
		"new_version":  result.NewVersion,
		"restart":      result.RestartNeeded,
		"message":      "agent updated successfully",
	}, nil
}

// handleCheckUpdate checks for available updates without installing.
func (h *Handler) handleCheckUpdate(ctx context.Context, data json.RawMessage) (interface{}, error) {
	info, err := h.updater.CheckForUpdate(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking for update: %w", err)
	}

	if info == nil {
		return map[string]interface{}{
			"available":       false,
			"current_version": version.Version,
		}, nil
	}

	return map[string]interface{}{
		"available":       true,
		"current_version": version.Version,
		"new_version":     info.Version,
		"download_url":    info.DownloadURL,
		"size":            info.Size,
	}, nil
}

// handleUpdateOsquery installs or updates osquery.
func (h *Handler) handleUpdateOsquery(ctx context.Context, data json.RawMessage) (interface{}, error) {
	client := osquery.New()

	// Check if already installed
	if client.IsAvailable() {
		return map[string]interface{}{
			"status":    "already_installed",
			"available": true,
			"message":   "osquery is already installed",
		}, nil
	}

	// Install osquery based on platform
	if err := osquery.Install(ctx); err != nil {
		return nil, fmt.Errorf("installing osquery: %w", err)
	}

	return map[string]interface{}{
		"status":  "installed",
		"message": "osquery installed successfully",
	}, nil
}

// Service management handlers

// handleListServices lists all system services.
func (h *Handler) handleListServices(ctx context.Context, data json.RawMessage) (interface{}, error) {
	mgr := service.New()
	if mgr == nil {
		return nil, fmt.Errorf("service management not supported on this platform")
	}

	services, err := mgr.List()
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"services": services,
		"count":    len(services),
	}, nil
}

type serviceActionRequest struct {
	Name string `json:"name"`
}

// handleStartService starts a system service.
func (h *Handler) handleStartService(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req serviceActionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if req.Name == "" {
		return nil, fmt.Errorf("service name is required")
	}

	mgr := service.New()
	if mgr == nil {
		return nil, fmt.Errorf("service management not supported on this platform")
	}

	if err := mgr.Start(req.Name); err != nil {
		return nil, err
	}

	return map[string]string{"status": "started", "service": req.Name}, nil
}

// handleStopService stops a system service.
func (h *Handler) handleStopService(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req serviceActionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if req.Name == "" {
		return nil, fmt.Errorf("service name is required")
	}

	mgr := service.New()
	if mgr == nil {
		return nil, fmt.Errorf("service management not supported on this platform")
	}

	if err := mgr.Stop(req.Name); err != nil {
		return nil, err
	}

	return map[string]string{"status": "stopped", "service": req.Name}, nil
}

// handleRestartService restarts a system service.
func (h *Handler) handleRestartService(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req serviceActionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if req.Name == "" {
		return nil, fmt.Errorf("service name is required")
	}

	mgr := service.New()
	if mgr == nil {
		return nil, fmt.Errorf("service management not supported on this platform")
	}

	if err := mgr.Restart(req.Name); err != nil {
		return nil, err
	}

	return map[string]string{"status": "restarted", "service": req.Name}, nil
}

type setServiceStartTypeRequest struct {
	Name      string `json:"name"`
	StartType string `json:"start_type"` // auto, manual, disabled
}

// handleSetServiceStartType changes the startup type of a system service.
func (h *Handler) handleSetServiceStartType(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req setServiceStartTypeRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if req.Name == "" {
		return nil, fmt.Errorf("service name is required")
	}

	if req.StartType == "" {
		return nil, fmt.Errorf("start_type is required (auto, manual, or disabled)")
	}

	mgr := service.New()
	if mgr == nil {
		return nil, fmt.Errorf("service management not supported on this platform")
	}

	if err := mgr.SetStartType(req.Name, req.StartType); err != nil {
		return nil, err
	}

	return map[string]string{"status": "changed", "service": req.Name, "start_type": req.StartType}, nil
}

// Tamper protection handlers

type enableTamperProtectionRequest struct {
	UninstallKey string `json:"uninstall_key,omitempty"`
	Watchdog     bool   `json:"watchdog,omitempty"`
	AlertEnabled bool   `json:"alert_enabled,omitempty"`
}

func (h *Handler) handleEnableTamperProtection(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req enableTamperProtectionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("enabling tamper protection",
		"watchdog_requested", req.Watchdog,
		"alerts_enabled", req.AlertEnabled,
		"uninstall_key_provided", req.UninstallKey != "",
	)

	// Enable tamper protection in config
	h.cfg.SetTamperProtection(true)
	h.cfg.SetTamperAlertEnabled(req.AlertEnabled)

	// Set uninstall key if provided
	if req.UninstallKey != "" {
		hash := h.tamperProtection.SetUninstallKey(req.UninstallKey)
		h.cfg.SetUninstallKeyHash(hash)
		h.logger.Info("uninstall key configured during tamper protection enable")
	}

	// Install watchdog if requested
	if req.Watchdog {
		if err := h.installWatchdog(); err != nil {
			h.logger.Warn("failed to install watchdog", "error", err)
		} else {
			h.cfg.SetWatchdogEnabled(true)
			h.logger.Info("watchdog service installed and enabled")
		}
	}

	// Save config
	if err := h.cfg.Save(); err != nil {
		return nil, fmt.Errorf("saving config: %w", err)
	}

	// Start tamper protection
	if h.tamperProtection != nil {
		h.tamperProtection.Start()
	}

	h.logger.Info("tamper protection enabled successfully",
		"watchdog_enabled", h.cfg.IsWatchdogEnabled(),
		"alerts_enabled", h.cfg.IsTamperAlertEnabled(),
	)

	return map[string]interface{}{
		"status":           "enabled",
		"watchdog":         h.cfg.IsWatchdogEnabled(),
		"alert_enabled":    h.cfg.IsTamperAlertEnabled(),
		"uninstall_key_set": h.cfg.GetUninstallKeyHash() != "",
	}, nil
}

type disableTamperProtectionRequest struct {
	UninstallKey string `json:"uninstall_key"`
}

func (h *Handler) handleDisableTamperProtection(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req disableTamperProtectionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("attempting to disable tamper protection",
		"uninstall_key_provided", req.UninstallKey != "",
	)

	// Validate uninstall key if set
	if h.tamperProtection != nil {
		if err := h.tamperProtection.ValidateUninstallKey(req.UninstallKey); err != nil {
			h.logger.Warn("failed to disable tamper protection: invalid uninstall key")
			return nil, fmt.Errorf("unauthorized: %w", err)
		}
	}

	// Stop tamper protection
	if h.tamperProtection != nil {
		h.tamperProtection.Stop()
		h.logger.Info("tamper protection monitoring stopped")
	}

	// Uninstall watchdog
	if h.cfg.IsWatchdogEnabled() {
		if err := h.uninstallWatchdog(); err != nil {
			h.logger.Warn("failed to uninstall watchdog", "error", err)
		} else {
			h.logger.Info("watchdog service uninstalled")
		}
	}

	// Disable in config
	h.cfg.SetTamperProtection(false)
	h.cfg.SetWatchdogEnabled(false)
	h.cfg.SetTamperAlertEnabled(false)

	// Save config
	if err := h.cfg.Save(); err != nil {
		return nil, fmt.Errorf("saving config: %w", err)
	}

	h.logger.Info("tamper protection disabled successfully")

	return map[string]string{"status": "disabled"}, nil
}

type setUninstallKeyRequest struct {
	CurrentKey string `json:"current_key,omitempty"`
	NewKey     string `json:"new_key"`
}

func (h *Handler) handleSetUninstallKey(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req setUninstallKeyRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	hadPreviousKey := h.cfg.GetUninstallKeyHash() != ""
	h.logger.Info("attempting to set uninstall key", "has_previous_key", hadPreviousKey)

	// Validate current key if one exists
	if hadPreviousKey {
		if h.tamperProtection != nil {
			if err := h.tamperProtection.ValidateUninstallKey(req.CurrentKey); err != nil {
				h.logger.Warn("failed to set uninstall key: invalid current key")
				return nil, fmt.Errorf("unauthorized: current key invalid")
			}
		}
	}

	// Set new key
	if req.NewKey == "" {
		return nil, fmt.Errorf("new key is required")
	}

	hash := h.tamperProtection.SetUninstallKey(req.NewKey)
	h.cfg.SetUninstallKeyHash(hash)

	if err := h.cfg.Save(); err != nil {
		return nil, fmt.Errorf("saving config: %w", err)
	}

	if hadPreviousKey {
		h.logger.Info("uninstall key updated successfully")
	} else {
		h.logger.Info("uninstall key configured successfully")
	}

	return map[string]string{"status": "key_updated"}, nil
}

func (h *Handler) handleGetTamperStatus(ctx context.Context, data json.RawMessage) (interface{}, error) {
	return map[string]interface{}{
		"enabled":           h.cfg.IsTamperProtectionEnabled(),
		"watchdog":          h.cfg.IsWatchdogEnabled(),
		"alert_enabled":     h.cfg.IsTamperAlertEnabled(),
		"uninstall_key_set": h.cfg.GetUninstallKeyHash() != "",
	}, nil
}

func (h *Handler) handleInstallWatchdog(ctx context.Context, data json.RawMessage) (interface{}, error) {
	h.logger.Info("installing watchdog service")

	if err := h.installWatchdog(); err != nil {
		h.logger.Error("failed to install watchdog service", "error", err)
		return nil, err
	}

	h.cfg.SetWatchdogEnabled(true)
	if err := h.cfg.Save(); err != nil {
		return nil, fmt.Errorf("saving config: %w", err)
	}

	h.logger.Info("watchdog service installed and enabled successfully")

	return map[string]string{"status": "watchdog_installed"}, nil
}

func (h *Handler) handleUninstallWatchdog(ctx context.Context, data json.RawMessage) (interface{}, error) {
	h.logger.Info("attempting to uninstall watchdog service")

	// Validate uninstall key if tamper protection is enabled
	if h.cfg.IsTamperProtectionEnabled() && h.cfg.GetUninstallKeyHash() != "" {
		var req struct {
			UninstallKey string `json:"uninstall_key"`
		}
		if err := json.Unmarshal(data, &req); err == nil && req.UninstallKey != "" {
			if h.tamperProtection != nil {
				if err := h.tamperProtection.ValidateUninstallKey(req.UninstallKey); err != nil {
					h.logger.Warn("failed to uninstall watchdog: invalid uninstall key")
					return nil, fmt.Errorf("unauthorized: %w", err)
				}
			}
		} else {
			h.logger.Warn("failed to uninstall watchdog: uninstall key required but not provided")
			return nil, fmt.Errorf("uninstall key required when tamper protection is enabled")
		}
	}

	if err := h.uninstallWatchdog(); err != nil {
		h.logger.Error("failed to uninstall watchdog service", "error", err)
		return nil, err
	}

	h.cfg.SetWatchdogEnabled(false)
	if err := h.cfg.Save(); err != nil {
		return nil, fmt.Errorf("saving config: %w", err)
	}

	h.logger.Info("watchdog service uninstalled successfully")

	return map[string]string{"status": "watchdog_uninstalled"}, nil
}

// Docker handlers

func (h *Handler) handleDockerInfo(ctx context.Context, data json.RawMessage) (interface{}, error) {
	return actions.GetDockerInfo(ctx)
}

type dockerListContainersRequest struct {
	All bool `json:"all"`
}

func (h *Handler) handleDockerListContainers(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req dockerListContainersRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	return actions.ListDockerContainers(ctx, req.All)
}

type dockerContainerActionRequest struct {
	ContainerID string `json:"container_id"`
	Action      string `json:"action"`
}

func (h *Handler) handleDockerContainerAction(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req dockerContainerActionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if err := actions.DockerContainerAction(ctx, req.ContainerID, req.Action); err != nil {
		return nil, fmt.Errorf("docker container action %s failed: %w", req.Action, err)
	}

	return map[string]string{"status": "success", "action": req.Action, "container_id": req.ContainerID}, nil
}

type dockerRemoveContainerRequest struct {
	ContainerID string `json:"container_id"`
	Force       bool   `json:"force"`
}

func (h *Handler) handleDockerRemoveContainer(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req dockerRemoveContainerRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if err := actions.RemoveDockerContainer(ctx, req.ContainerID, req.Force); err != nil {
		return nil, fmt.Errorf("remove docker container failed: %w", err)
	}

	return map[string]string{"status": "removed", "container_id": req.ContainerID}, nil
}

type dockerContainerLogsRequest struct {
	ContainerID string `json:"container_id"`
	Tail        int    `json:"tail"`
	Timestamps  bool   `json:"timestamps"`
}

func (h *Handler) handleDockerContainerLogs(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req dockerContainerLogsRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	return actions.GetDockerContainerLogs(ctx, req.ContainerID, req.Tail, req.Timestamps)
}

type dockerContainerStatsRequest struct {
	ContainerID string `json:"container_id"`
}

func (h *Handler) handleDockerContainerStats(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req dockerContainerStatsRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	return actions.GetDockerContainerStats(ctx, req.ContainerID)
}

type dockerInspectContainerRequest struct {
	ContainerID string `json:"container_id"`
}

func (h *Handler) handleDockerInspectContainer(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req dockerInspectContainerRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	return actions.InspectDockerContainer(ctx, req.ContainerID)
}

type dockerExecRequest struct {
	ContainerID string   `json:"container_id"`
	Command     []string `json:"command"`
	Timeout     int      `json:"timeout"`
}

func (h *Handler) handleDockerExec(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req dockerExecRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	timeout := time.Duration(req.Timeout) * time.Second
	if timeout == 0 {
		timeout = actions.DefaultCommandTimeout
	}

	return actions.ExecInDockerContainer(ctx, req.ContainerID, req.Command, timeout)
}

func (h *Handler) handleDockerListImages(ctx context.Context, data json.RawMessage) (interface{}, error) {
	return actions.ListDockerImages(ctx)
}

type dockerRemoveImageRequest struct {
	ImageID string `json:"image_id"`
	Force   bool   `json:"force"`
}

func (h *Handler) handleDockerRemoveImage(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req dockerRemoveImageRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if err := actions.RemoveDockerImage(ctx, req.ImageID, req.Force); err != nil {
		return nil, fmt.Errorf("remove docker image failed: %w", err)
	}

	return map[string]string{"status": "removed", "image_id": req.ImageID}, nil
}

type dockerPullImageRequest struct {
	ImageName string `json:"image_name"`
}

func (h *Handler) handleDockerPullImage(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req dockerPullImageRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if err := actions.PullDockerImage(ctx, req.ImageName); err != nil {
		return nil, fmt.Errorf("pull docker image failed: %w", err)
	}

	return map[string]string{"status": "pulled", "image_name": req.ImageName}, nil
}

func (h *Handler) handleDockerListVolumes(ctx context.Context, data json.RawMessage) (interface{}, error) {
	return actions.ListDockerVolumes(ctx)
}

type dockerRemoveVolumeRequest struct {
	VolumeName string `json:"volume_name"`
	Force      bool   `json:"force"`
}

func (h *Handler) handleDockerRemoveVolume(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req dockerRemoveVolumeRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if err := actions.RemoveDockerVolume(ctx, req.VolumeName, req.Force); err != nil {
		return nil, fmt.Errorf("remove docker volume failed: %w", err)
	}

	return map[string]string{"status": "removed", "volume_name": req.VolumeName}, nil
}

func (h *Handler) handleDockerListNetworks(ctx context.Context, data json.RawMessage) (interface{}, error) {
	return actions.ListDockerNetworks(ctx)
}

type dockerComposeActionRequest struct {
	ProjectPath string `json:"project_path"`
	Action      string `json:"action"`
}

func (h *Handler) handleDockerComposeAction(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req dockerComposeActionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if err := actions.DockerComposeAction(ctx, req.ProjectPath, req.Action); err != nil {
		return nil, fmt.Errorf("docker compose action %s failed: %w", req.Action, err)
	}

	return map[string]string{"status": "success", "action": req.Action, "project_path": req.ProjectPath}, nil
}

// Docker policy handlers

type dockerPolicyExecuteRequest struct {
	ExecutionID string                 `json:"execution_id"`
	PolicyID    string                 `json:"policy_id"`
	Config      map[string]interface{} `json:"config"`
}

func (h *Handler) handleDockerPolicyExecute(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req dockerPolicyExecuteRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	action := ""
	if a, ok := req.Config["action"].(string); ok {
		action = a
	}

	startedAt := time.Now()
	var result interface{}
	var err error

	switch action {
	case "prune_images":
		danglingOnly := getBool(req.Config, "prune_dangling_only")
		olderThan := getIntVal(req.Config, "prune_until_hours")
		result, err = actions.PruneDockerImages(ctx, danglingOnly, olderThan)
	case "prune_volumes":
		result, err = actions.PruneDockerVolumes(ctx)
	case "prune_networks":
		result, err = actions.PruneDockerNetworks(ctx)
	case "prune_all":
		danglingOnly := getBool(req.Config, "prune_dangling_only")
		olderThan := getIntVal(req.Config, "prune_until_hours")
		result, err = actions.PruneDockerSystem(ctx, danglingOnly, olderThan)
	case "restart_unhealthy":
		timeout := getIntVal(req.Config, "restart_timeout_seconds")
		if timeout == 0 {
			timeout = 30
		}
		maxRetries := getIntVal(req.Config, "restart_max_retries")
		if maxRetries == 0 {
			maxRetries = 3
		}
		result, err = actions.RestartUnhealthyContainers(ctx, timeout, maxRetries)
	case "update_images":
		pullLatest := getBool(req.Config, "update_pull_latest")
		recreate := getBool(req.Config, "update_recreate_containers")
		result, err = actions.UpdateDockerImages(ctx, pullLatest, recreate)
	case "container_health_check":
		result, err = actions.GetDockerHealthCheck(ctx)
	default:
		err = fmt.Errorf("unknown docker policy action: %s", action)
	}

	completedAt := time.Now()
	durationMs := completedAt.Sub(startedAt).Milliseconds()

	response := map[string]interface{}{
		"action":       "docker_policy_result",
		"execution_id": req.ExecutionID,
		"policy_id":    req.PolicyID,
		"duration_ms":  durationMs,
		"started_at":   startedAt.UTC().Format(time.RFC3339),
		"completed_at": completedAt.UTC().Format(time.RFC3339),
	}

	if err != nil {
		response["status"] = "failed"
		response["error"] = err.Error()
	} else {
		response["status"] = "completed"
		response["result"] = result
	}

	h.SendRaw(response)
	return response, nil
}

type dockerPruneRequest struct {
	DanglingOnly   bool `json:"dangling_only"`
	OlderThanHours int  `json:"older_than_hours"`
}

func (h *Handler) handleDockerPruneImages(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req dockerPruneRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	return actions.PruneDockerImages(ctx, req.DanglingOnly, req.OlderThanHours)
}

func (h *Handler) handleDockerPruneVolumes(ctx context.Context, data json.RawMessage) (interface{}, error) {
	return actions.PruneDockerVolumes(ctx)
}

func (h *Handler) handleDockerPruneNetworks(ctx context.Context, data json.RawMessage) (interface{}, error) {
	return actions.PruneDockerNetworks(ctx)
}

func (h *Handler) handleDockerPruneAll(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req dockerPruneRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	return actions.PruneDockerSystem(ctx, req.DanglingOnly, req.OlderThanHours)
}

type dockerRestartUnhealthyRequest struct {
	Timeout    int `json:"timeout"`
	MaxRetries int `json:"max_retries"`
}

func (h *Handler) handleDockerRestartUnhealthy(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req dockerRestartUnhealthyRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	if req.Timeout == 0 {
		req.Timeout = 30
	}
	if req.MaxRetries == 0 {
		req.MaxRetries = 3
	}
	return actions.RestartUnhealthyContainers(ctx, req.Timeout, req.MaxRetries)
}

type dockerUpdateImagesRequest struct {
	PullLatest          bool `json:"pull_latest"`
	RecreateContainers  bool `json:"recreate_containers"`
}

func (h *Handler) handleDockerUpdateImages(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req dockerUpdateImagesRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	return actions.UpdateDockerImages(ctx, req.PullLatest, req.RecreateContainers)
}

func (h *Handler) handleDockerHealthCheck(ctx context.Context, data json.RawMessage) (interface{}, error) {
	return actions.GetDockerHealthCheck(ctx)
}

// Helper functions for config parsing
func getBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func getIntVal(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
	}
	return 0
}

// Compliance check handlers

type complianceCheckRequest struct {
	PolicyID  string            `json:"policy_id"`
	RequestID string            `json:"request_id,omitempty"`
	Checks    []complianceCheck `json:"checks"`
}

type complianceCheck struct {
	CheckID            string      `json:"check_id"`
	CisID              string      `json:"cis_id"`
	CheckType          string      `json:"check_type"`
	Query              string      `json:"query"`
	ExpectedResult     interface{} `json:"expected_result"`
	ComparisonOperator string      `json:"comparison_operator"`
}

type complianceCheckResult struct {
	CheckID     string      `json:"check_id"`
	Status      string      `json:"status"` // passed, failed, error, skipped
	ActualValue interface{} `json:"actual_value,omitempty"`
	Details     string      `json:"details,omitempty"`
}

func (h *Handler) handleRunComplianceCheck(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req complianceCheckRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid compliance check request: %w", err)
	}

	h.logger.Info("running compliance checks",
		"policy_id", req.PolicyID,
		"check_count", len(req.Checks),
	)

	results := make([]complianceCheckResult, 0, len(req.Checks))
	client := osquery.New()
	osqueryAvailable := client.IsAvailable()

	for _, check := range req.Checks {
		result := complianceCheckResult{
			CheckID: check.CheckID,
		}

		// Handle different check types
		switch check.CheckType {
		case "osquery":
			if !osqueryAvailable {
				result.Status = "error"
				result.Details = "osquery not available on this system"
				results = append(results, result)
				continue
			}

			if check.Query == "" {
				result.Status = "error"
				result.Details = "no query provided"
				results = append(results, result)
				continue
			}

			// Execute osquery
			queryResult, err := client.QueryWithTimeout(ctx, check.Query, osquery.DefaultTimeout)
			if err != nil {
				result.Status = "error"
				result.Details = fmt.Sprintf("osquery error: %v", err)
				results = append(results, result)
				continue
			}

			result.ActualValue = queryResult

			// Compare with expected result - pass only the Rows, not the full QueryResult
			passed, details := h.compareComplianceResult(queryResult.Rows, check.ExpectedResult, check.ComparisonOperator)
			if passed {
				result.Status = "passed"
				result.Details = details
			} else {
				result.Status = "failed"
				result.Details = details
			}

		case "command":
			// For command-based checks, execute the command and check exit code
			if check.Query == "" {
				result.Status = "error"
				result.Details = "no command provided"
				results = append(results, result)
				continue
			}

			cmdResult, err := actions.ExecuteCommand(ctx, check.Query, 30*time.Second)
			if err != nil {
				result.Status = "error"
				result.Details = fmt.Sprintf("command error: %v", err)
				results = append(results, result)
				continue
			}

			result.ActualValue = cmdResult

			// Check if command succeeded (exit code 0 usually means pass)
			if cmdResult.ExitCode == 0 {
				result.Status = "passed"
				result.Details = "command executed successfully"
			} else {
				result.Status = "failed"
				result.Details = fmt.Sprintf("command exited with code %d", cmdResult.ExitCode)
			}

		case "registry":
			// Windows registry check
			if check.Query == "" {
				result.Status = "error"
				result.Details = "no registry path provided"
				results = append(results, result)
				continue
			}

			regResult, err := actions.ReadRegistryValue(check.Query)
			if err != nil {
				// Registry value not found - this might be expected for some checks
				result.Status = "failed"
				result.ActualValue = nil
				result.Details = fmt.Sprintf("registry error: %v", err)
				results = append(results, result)
				continue
			}

			result.ActualValue = regResult.Value

			// Compare with expected result
			passed, details := h.compareRegistryResult(regResult.Value, check.ExpectedResult, check.ComparisonOperator)
			if passed {
				result.Status = "passed"
				result.Details = details
			} else {
				result.Status = "failed"
				result.Details = details
			}

		default:
			result.Status = "skipped"
			result.Details = fmt.Sprintf("unsupported check type: %s", check.CheckType)
		}

		results = append(results, result)
	}

	// Send results back to backend
	response := map[string]interface{}{
		"action":    "compliance_check_result",
		"policy_id": req.PolicyID,
		"results":   results,
	}
	if req.RequestID != "" {
		response["request_id"] = req.RequestID
	}

	h.SendRaw(response)

	h.logger.Info("compliance checks completed",
		"policy_id", req.PolicyID,
		"results_count", len(results),
	)

	return response, nil
}

// compareComplianceResult compares the actual result with the expected result.
func (h *Handler) compareComplianceResult(actual interface{}, expected interface{}, operator string) (bool, string) {
	if expected == nil {
		return true, "no expected result specified"
	}

	// Convert actual to []map[string]interface{} if it's osquery result
	var actualRows []map[string]interface{}

	switch v := actual.(type) {
	case []map[string]interface{}:
		actualRows = v
	case []map[string]string:
		// osquery returns []map[string]string - convert to interface{}
		actualRows = make([]map[string]interface{}, len(v))
		for i, row := range v {
			converted := make(map[string]interface{}, len(row))
			for k, val := range row {
				converted[k] = val
			}
			actualRows[i] = converted
		}
	case []interface{}:
		// Try to convert from []interface{}
		actualRows = make([]map[string]interface{}, 0, len(v))
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				actualRows = append(actualRows, m)
			}
		}
	default:
		return false, fmt.Sprintf("unexpected actual type: %T", actual)
	}

	switch operator {
	case "equals", "eq", "":
		// Check if any row matches the expected result
		expectedMap, ok := expected.(map[string]interface{})
		if !ok {
			return false, "expected result is not a valid map"
		}

		for _, row := range actualRows {
			if h.mapsMatch(row, expectedMap) {
				return true, "result matches expected value"
			}
		}
		return false, "no matching result found"

	case "not_equals", "ne", "neq":
		expectedMap, ok := expected.(map[string]interface{})
		if !ok {
			return false, "expected result is not a valid map"
		}

		for _, row := range actualRows {
			if h.mapsMatch(row, expectedMap) {
				return false, "result matches value that should not match"
			}
		}
		return true, "no matching result found (expected)"

	case "exists", "not_empty":
		if len(actualRows) > 0 {
			return true, fmt.Sprintf("found %d matching rows", len(actualRows))
		}
		return false, "no results found"

	case "not_exists", "empty":
		if len(actualRows) == 0 {
			return true, "no results found (expected)"
		}
		return false, fmt.Sprintf("found %d rows when none expected", len(actualRows))

	case "contains":
		expectedMap, ok := expected.(map[string]interface{})
		if !ok {
			return false, "expected result is not a valid map"
		}

		for _, row := range actualRows {
			if h.mapContains(row, expectedMap) {
				return true, "result contains expected values"
			}
		}
		return false, "no result contains expected values"

	case "gte", ">=":
		// Compare numeric values
		return h.compareNumeric(actualRows, expected, ">=")

	case "lte", "<=":
		return h.compareNumeric(actualRows, expected, "<=")

	case "gt", ">":
		return h.compareNumeric(actualRows, expected, ">")

	case "lt", "<":
		return h.compareNumeric(actualRows, expected, "<")

	default:
		return false, fmt.Sprintf("unsupported comparison operator: %s", operator)
	}
}

// mapsMatch checks if all keys in expected exist in actual with matching values.
func (h *Handler) mapsMatch(actual, expected map[string]interface{}) bool {
	for key, expectedVal := range expected {
		actualVal, exists := actual[key]
		if !exists {
			return false
		}
		if !h.valuesEqual(actualVal, expectedVal) {
			return false
		}
	}
	return true
}

// mapContains checks if actual contains all key-value pairs from expected.
func (h *Handler) mapContains(actual, expected map[string]interface{}) bool {
	return h.mapsMatch(actual, expected)
}

// valuesEqual compares two values for equality, handling type conversions.
func (h *Handler) valuesEqual(a, b interface{}) bool {
	// Handle nil cases
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// Convert to strings for comparison (osquery returns strings)
	aStr := fmt.Sprintf("%v", a)
	bStr := fmt.Sprintf("%v", b)
	return aStr == bStr
}

// compareNumeric compares numeric values from query results.
func (h *Handler) compareNumeric(rows []map[string]interface{}, expected interface{}, op string) (bool, string) {
	expectedMap, ok := expected.(map[string]interface{})
	if !ok {
		return false, "expected result is not a valid map"
	}

	for key, expectedVal := range expectedMap {
		for _, row := range rows {
			if actualVal, exists := row[key]; exists {
				passed, err := h.compareNumbers(actualVal, expectedVal, op)
				if err != nil {
					return false, err.Error()
				}
				if passed {
					return true, fmt.Sprintf("%s %s %v: passed", key, op, expectedVal)
				}
				return false, fmt.Sprintf("%s %s %v: actual value is %v", key, op, expectedVal, actualVal)
			}
		}
	}
	return false, "key not found in results"
}

// compareNumbers compares two numbers with the given operator.
func (h *Handler) compareNumbers(a, b interface{}, op string) (bool, error) {
	aFloat, err := toFloat64(a)
	if err != nil {
		return false, err
	}
	bFloat, err := toFloat64(b)
	if err != nil {
		return false, err
	}

	switch op {
	case ">=", "gte":
		return aFloat >= bFloat, nil
	case "<=", "lte":
		return aFloat <= bFloat, nil
	case ">", "gt":
		return aFloat > bFloat, nil
	case "<", "lt":
		return aFloat < bFloat, nil
	default:
		return false, fmt.Errorf("unsupported numeric operator: %s", op)
	}
}

// toFloat64 converts a value to float64.
func toFloat64(v interface{}) (float64, error) {
	switch n := v.(type) {
	case float64:
		return n, nil
	case float32:
		return float64(n), nil
	case int:
		return float64(n), nil
	case int64:
		return float64(n), nil
	case int32:
		return float64(n), nil
	case string:
		var f float64
		_, err := fmt.Sscanf(n, "%f", &f)
		if err != nil {
			return 0, fmt.Errorf("cannot convert %q to number", n)
		}
		return f, nil
	default:
		return 0, fmt.Errorf("cannot convert %T to number", v)
	}
}

// compareRegistryResult compares a registry value with the expected value.
func (h *Handler) compareRegistryResult(actual interface{}, expected interface{}, operator string) (bool, string) {
	if expected == nil {
		return true, "no expected result specified"
	}

	// Convert expected to string for comparison
	expectedStr := fmt.Sprintf("%v", expected)

	// Convert actual to string for comparison
	actualStr := fmt.Sprintf("%v", actual)

	switch operator {
	case "equals", "eq", "":
		if actualStr == expectedStr {
			return true, fmt.Sprintf("registry value %q matches expected %q", actualStr, expectedStr)
		}
		return false, fmt.Sprintf("registry value %q does not match expected %q", actualStr, expectedStr)

	case "not_equals", "ne", "neq":
		if actualStr != expectedStr {
			return true, fmt.Sprintf("registry value %q does not equal %q (expected)", actualStr, expectedStr)
		}
		return false, fmt.Sprintf("registry value %q equals %q but should not", actualStr, expectedStr)

	case "contains":
		if strings.Contains(actualStr, expectedStr) {
			return true, fmt.Sprintf("registry value contains %q", expectedStr)
		}
		return false, fmt.Sprintf("registry value %q does not contain %q", actualStr, expectedStr)

	case "exists", "not_empty":
		if actual != nil && actualStr != "" {
			return true, fmt.Sprintf("registry value exists: %q", actualStr)
		}
		return false, "registry value is empty or does not exist"

	case "not_exists", "empty":
		if actual == nil || actualStr == "" {
			return true, "registry value does not exist (expected)"
		}
		return false, fmt.Sprintf("registry value exists (%q) but should not", actualStr)

	case "gte", ">=":
		actualFloat, err1 := toFloat64(actual)
		expectedFloat, err2 := toFloat64(expected)
		if err1 != nil || err2 != nil {
			return false, "cannot compare non-numeric values with >= operator"
		}
		if actualFloat >= expectedFloat {
			return true, fmt.Sprintf("registry value %v >= %v", actualFloat, expectedFloat)
		}
		return false, fmt.Sprintf("registry value %v < %v", actualFloat, expectedFloat)

	case "lte", "<=":
		actualFloat, err1 := toFloat64(actual)
		expectedFloat, err2 := toFloat64(expected)
		if err1 != nil || err2 != nil {
			return false, "cannot compare non-numeric values with <= operator"
		}
		if actualFloat <= expectedFloat {
			return true, fmt.Sprintf("registry value %v <= %v", actualFloat, expectedFloat)
		}
		return false, fmt.Sprintf("registry value %v > %v", actualFloat, expectedFloat)

	case "gt", ">":
		actualFloat, err1 := toFloat64(actual)
		expectedFloat, err2 := toFloat64(expected)
		if err1 != nil || err2 != nil {
			return false, "cannot compare non-numeric values with > operator"
		}
		if actualFloat > expectedFloat {
			return true, fmt.Sprintf("registry value %v > %v", actualFloat, expectedFloat)
		}
		return false, fmt.Sprintf("registry value %v <= %v", actualFloat, expectedFloat)

	case "lt", "<":
		actualFloat, err1 := toFloat64(actual)
		expectedFloat, err2 := toFloat64(expected)
		if err1 != nil || err2 != nil {
			return false, "cannot compare non-numeric values with < operator"
		}
		if actualFloat < expectedFloat {
			return true, fmt.Sprintf("registry value %v < %v", actualFloat, expectedFloat)
		}
		return false, fmt.Sprintf("registry value %v >= %v", actualFloat, expectedFloat)

	default:
		return false, fmt.Sprintf("unsupported comparison operator: %s", operator)
	}
}

// Agent logs handler

type pullLogsRequest struct {
	AfterTimestamp string `json:"after_timestamp,omitempty"`
	Limit          int    `json:"limit,omitempty"`
}

func (h *Handler) handlePullLogs(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req pullLogsRequest
	if err := json.Unmarshal(data, &req); err != nil {
		// Ignore parse errors, use defaults
	}

	limit := req.Limit
	if limit <= 0 || limit > 10000 {
		limit = 1000 // Default to 1000 logs
	}

	// Parse after_timestamp if provided
	var afterTime time.Time
	if req.AfterTimestamp != "" {
		if t, err := time.Parse(time.RFC3339, req.AfterTimestamp); err == nil {
			afterTime = t
		}
	}

	h.logger.Info("pulling logs", "after_timestamp", req.AfterTimestamp, "limit", limit)

	logs, err := actions.ReadAgentLogs(ctx, afterTime, limit)
	if err != nil {
		h.logger.Error("failed to read agent logs", "error", err)
		return nil, err
	}

	h.logger.Info("logs read successfully", "count", len(logs))

	// Mark current log file as uploaded for rotation tracking
	logging.MarkCurrentLogUploaded()

	return map[string]interface{}{
		"logs": logs,
	}, nil
}

// Winget handlers (Windows only)

// handleGetWingetStatus returns the current winget installation status.
func (h *Handler) handleGetWingetStatus(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if runtime.GOOS != "windows" {
		return map[string]interface{}{
			"available":    false,
			"message":      "winget is only available on Windows",
			"system_level": false,
		}, nil
	}

	client := winget.GetDefault()
	status := client.GetStatus()

	return map[string]interface{}{
		"available":    status.Available,
		"version":      status.Version,
		"binary_path":  status.BinaryPath,
		"system_level": status.SystemLevel,
	}, nil
}

// handleInstallWinget installs winget on Windows.
func (h *Handler) handleInstallWinget(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if runtime.GOOS != "windows" {
		return map[string]interface{}{
			"status":  "unsupported",
			"message": "winget is only available on Windows",
		}, nil
	}

	client := winget.GetDefault()

	// Check if already installed
	if client.IsAvailable() {
		return map[string]interface{}{
			"status":       "already_installed",
			"available":    true,
			"version":      client.GetVersion(),
			"binary_path":  client.GetBinaryPath(),
			"system_level": client.GetStatus().SystemLevel,
			"message":      "winget is already installed",
		}, nil
	}

	h.logger.Info("installing winget")

	// Install winget
	if err := client.Install(ctx); err != nil {
		h.logger.Error("failed to install winget", "error", err)
		return map[string]interface{}{
			"status":  "failed",
			"message": fmt.Sprintf("installation failed: %v", err),
		}, nil
	}

	// Refresh and get new status with retries
	// After Add-AppxProvisionedPackage, the binary may not be immediately available
	if !client.RefreshWithRetry(5, 2*time.Second) {
		h.logger.Warn("winget installation completed but binary not found after retries")
		return map[string]interface{}{
			"status":    "installed_pending",
			"available": false,
			"message":   "winget installed but not yet available, may require system restart",
		}, nil
	}

	status := client.GetStatus()

	h.logger.Info("winget installation completed",
		"available", status.Available,
		"version", status.Version,
	)

	return map[string]interface{}{
		"status":       "installed",
		"available":    status.Available,
		"version":      status.Version,
		"binary_path":  status.BinaryPath,
		"system_level": status.SystemLevel,
		"message":      "winget installed successfully",
	}, nil
}

// Winget Policy Handler

type wingetPolicyRequest struct {
	ExecutionID            string   `json:"execution_id"`
	PolicyID               string   `json:"policy_id"`
	PolicyName             string   `json:"policy_name"`
	FilterMode             string   `json:"filter_mode"`      // all, whitelist, blacklist
	PackageFilters         []string `json:"package_filters"`  // Package IDs for filter
	Reboot                 bool     `json:"reboot"`
	TimeoutSeconds         int      `json:"timeout_seconds"`
	MaxConcurrent          int      `json:"max_concurrent"`
	RollbackEnabled        bool     `json:"rollback_enabled"`
	ExcludeSystemComponents bool    `json:"exclude_system_components"`
}

type wingetUpdateResult struct {
	PackageID   string `json:"package_id"`
	PackageName string `json:"package_name"`
	OldVersion  string `json:"old_version"`
	NewVersion  string `json:"new_version"`
	Status      string `json:"status"` // success, failed, skipped
	Error       string `json:"error,omitempty"`
}

func (h *Handler) handleExecuteWingetPolicy(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if runtime.GOOS != "windows" {
		return map[string]interface{}{
			"status": "failed",
			"error":  "winget is only available on Windows",
		}, nil
	}

	var req wingetPolicyRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("executing winget policy",
		"execution_id", req.ExecutionID,
		"policy_id", req.PolicyID,
		"filter_mode", req.FilterMode,
	)

	// Check if winget is available
	client := winget.GetDefault()
	if !client.IsAvailable() {
		response := map[string]interface{}{
			"action":       "winget_policy_result",
			"execution_id": req.ExecutionID,
			"policy_id":    req.PolicyID,
			"status":       "failed",
			"error":        "winget is not available on this system",
		}
		h.SendRaw(response)
		return response, nil
	}

	startedAt := time.Now()

	// Set timeout
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Get available updates
	updateList, err := actions.GetAvailableUpdates(ctx)
	if err != nil {
		h.logger.Error("failed to get available updates", "error", err)
		response := map[string]interface{}{
			"action":       "winget_policy_result",
			"execution_id": req.ExecutionID,
			"policy_id":    req.PolicyID,
			"status":       "failed",
			"error":        fmt.Sprintf("failed to get updates: %v", err),
			"started_at":   startedAt.UTC().Format(time.RFC3339),
			"completed_at": time.Now().UTC().Format(time.RFC3339),
		}
		h.SendRaw(response)
		return response, nil
	}

	// Filter updates to only winget updates
	var wingetUpdates []actions.Update
	for _, u := range updateList.Updates {
		if u.Source == "winget" {
			wingetUpdates = append(wingetUpdates, u)
		}
	}

	// Apply filter mode
	var updatesToProcess []actions.Update
	switch req.FilterMode {
	case "whitelist":
		// Only update packages in the filter list
		filterSet := make(map[string]bool)
		for _, id := range req.PackageFilters {
			filterSet[strings.ToLower(id)] = true
		}
		for _, u := range wingetUpdates {
			if filterSet[strings.ToLower(u.KB)] { // KB contains package ID for winget
				updatesToProcess = append(updatesToProcess, u)
			}
		}
	case "blacklist":
		// Update all packages except those in the filter list
		filterSet := make(map[string]bool)
		for _, id := range req.PackageFilters {
			filterSet[strings.ToLower(id)] = true
		}
		for _, u := range wingetUpdates {
			if !filterSet[strings.ToLower(u.KB)] {
				updatesToProcess = append(updatesToProcess, u)
			}
		}
	default: // "all"
		updatesToProcess = wingetUpdates
	}

	if len(updatesToProcess) == 0 {
		h.logger.Info("no updates to process after filtering")
		response := map[string]interface{}{
			"action":         "winget_policy_result",
			"execution_id":   req.ExecutionID,
			"policy_id":      req.PolicyID,
			"status":         "completed",
			"total_packages": 0,
			"succeeded":      0,
			"failed":         0,
			"results":        []wingetUpdateResult{},
			"started_at":     startedAt.UTC().Format(time.RFC3339),
			"completed_at":   time.Now().UTC().Format(time.RFC3339),
			"duration_ms":    time.Since(startedAt).Milliseconds(),
		}
		h.SendRaw(response)
		return response, nil
	}

	// Execute updates
	var results []wingetUpdateResult
	var succeeded, failed int
	wingetPath := client.GetBinaryPath()

	for i, update := range updatesToProcess {
		// Send progress
		h.SendRaw(map[string]interface{}{
			"action":          "winget_policy_progress",
			"execution_id":    req.ExecutionID,
			"policy_id":       req.PolicyID,
			"current_package": update.Name,
			"current_index":   i + 1,
			"total_packages":  len(updatesToProcess),
		})

		// Execute winget upgrade for this package
		result := h.executeWingetUpgrade(ctx, wingetPath, update)
		results = append(results, result)

		if result.Status == "success" {
			succeeded++
		} else {
			failed++
		}

		// Send progress with result
		h.SendRaw(map[string]interface{}{
			"action":          "winget_policy_progress",
			"execution_id":    req.ExecutionID,
			"policy_id":       req.PolicyID,
			"current_package": update.Name,
			"current_index":   i + 1,
			"total_packages":  len(updatesToProcess),
			"package_status":  result.Status,
		})
	}

	completedAt := time.Now()
	durationMs := completedAt.Sub(startedAt).Milliseconds()

	// Determine overall status
	status := "completed"
	if failed > 0 && succeeded == 0 {
		status = "failed"
	} else if failed > 0 {
		status = "partial"
	}

	response := map[string]interface{}{
		"action":         "winget_policy_result",
		"execution_id":   req.ExecutionID,
		"policy_id":      req.PolicyID,
		"status":         status,
		"total_packages": len(updatesToProcess),
		"succeeded":      succeeded,
		"failed":         failed,
		"results":        results,
		"started_at":     startedAt.UTC().Format(time.RFC3339),
		"completed_at":   completedAt.UTC().Format(time.RFC3339),
		"duration_ms":    durationMs,
	}

	// Handle reboot if requested
	if req.Reboot && succeeded > 0 {
		response["reboot_scheduled"] = true
		h.ScheduleReboot("winget policy execution")
	}

	h.SendRaw(response)
	h.logger.Info("winget policy execution completed",
		"execution_id", req.ExecutionID,
		"status", status,
		"succeeded", succeeded,
		"failed", failed,
	)

	return response, nil
}

// wingetInstallPolicyRequest represents a winget install policy request.
type wingetInstallPolicyRequest struct {
	ExecutionID     string                  `json:"execution_id"`
	PolicyID        string                  `json:"policy_id"`
	PolicyName      string                  `json:"policy_name"`
	Packages        []wingetPackageToInstall `json:"packages"`
	InstallScope    string                  `json:"install_scope"`
	Silent          bool                    `json:"silent"`
	SkipIfInstalled bool                    `json:"skip_if_installed"`
	Reboot          bool                    `json:"reboot"`
	TimeoutSeconds  int                     `json:"timeout_seconds"`
	MaxConcurrent   int                     `json:"max_concurrent"`
}

type wingetPackageToInstall struct {
	PackageID   string  `json:"package_id"`
	PackageName *string `json:"package_name"`
	Version     *string `json:"version"`
}

type wingetInstallResult struct {
	PackageID   string `json:"package_id"`
	PackageName string `json:"package_name"`
	Status      string `json:"status"`
	ExitCode    int    `json:"exit_code"`
	Output      string `json:"output,omitempty"`
	Error       string `json:"error,omitempty"`
}

// handleExecuteWingetInstallPolicy handles installing software via winget policy.
func (h *Handler) handleExecuteWingetInstallPolicy(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if runtime.GOOS != "windows" {
		return map[string]interface{}{
			"status": "failed",
			"error":  "winget is only available on Windows",
		}, nil
	}

	var req wingetInstallPolicyRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("executing winget install policy",
		"execution_id", req.ExecutionID,
		"policy_id", req.PolicyID,
		"policy_name", req.PolicyName,
		"packages_count", len(req.Packages),
	)

	// Check if winget is available
	client := winget.GetDefault()
	if !client.IsAvailable() {
		response := map[string]interface{}{
			"action":       "winget_install_policy_result",
			"execution_id": req.ExecutionID,
			"policy_id":    req.PolicyID,
			"status":       "failed",
			"error":        "winget is not available on this system",
		}
		h.SendRaw(response)
		return response, nil
	}

	if len(req.Packages) == 0 {
		response := map[string]interface{}{
			"action":       "winget_install_policy_result",
			"execution_id": req.ExecutionID,
			"policy_id":    req.PolicyID,
			"status":       "completed",
			"message":      "no packages to install",
		}
		h.SendRaw(response)
		return response, nil
	}

	startedAt := time.Now()

	// Set timeout
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	wingetPath := client.GetBinaryPath()
	scope := req.InstallScope
	if scope == "" {
		scope = "machine"
	}

	var results []wingetInstallResult
	var succeeded, failed, skipped int

	for i, pkg := range req.Packages {
		packageName := pkg.PackageID
		if pkg.PackageName != nil && *pkg.PackageName != "" {
			packageName = *pkg.PackageName
		}

		// Send progress
		h.SendRaw(map[string]interface{}{
			"action":          "winget_install_policy_progress",
			"execution_id":    req.ExecutionID,
			"policy_id":       req.PolicyID,
			"current_package": packageName,
			"package_id":      pkg.PackageID,
			"current_index":   i + 1,
			"total_packages":  len(req.Packages),
		})

		// Check if already installed (if skip_if_installed is true)
		if req.SkipIfInstalled {
			checkCmd := exec.CommandContext(ctx, wingetPath, "list", "--id", pkg.PackageID, "--accept-source-agreements")
			checkOutput, _ := checkCmd.CombinedOutput()
			if strings.Contains(string(checkOutput), pkg.PackageID) {
				h.logger.Info("package already installed, skipping", "package_id", pkg.PackageID)
				results = append(results, wingetInstallResult{
					PackageID:   pkg.PackageID,
					PackageName: packageName,
					Status:      "skipped",
					Output:      "already installed",
				})
				skipped++
				continue
			}
		}

		// Build install command
		args := []string{
			"install",
			"--id", pkg.PackageID,
			"--scope", scope,
			"--accept-source-agreements",
			"--accept-package-agreements",
			"--disable-interactivity",
		}

		if req.Silent {
			args = append(args, "--silent")
		}

		if pkg.Version != nil && *pkg.Version != "" {
			args = append(args, "--version", *pkg.Version)
		}

		// Execute install
		cmd := exec.CommandContext(ctx, wingetPath, args...)
		output, err := cmd.CombinedOutput()

		result := wingetInstallResult{
			PackageID:   pkg.PackageID,
			PackageName: packageName,
			Output:      string(output),
		}

		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				result.ExitCode = exitErr.ExitCode()
			} else {
				result.ExitCode = -1
			}
			result.Status = "failed"
			result.Error = err.Error()
			failed++
			h.logger.Error("package installation failed",
				"package_id", pkg.PackageID,
				"exit_code", result.ExitCode,
				"error", err,
			)
		} else {
			result.Status = "success"
			result.ExitCode = 0
			succeeded++
			h.logger.Info("package installed successfully", "package_id", pkg.PackageID)
		}

		results = append(results, result)

		// Send progress with result
		h.SendRaw(map[string]interface{}{
			"action":          "winget_install_policy_progress",
			"execution_id":    req.ExecutionID,
			"policy_id":       req.PolicyID,
			"current_package": packageName,
			"package_id":      pkg.PackageID,
			"current_index":   i + 1,
			"total_packages":  len(req.Packages),
			"package_status":  result.Status,
		})
	}

	completedAt := time.Now()
	durationMs := completedAt.Sub(startedAt).Milliseconds()

	// Determine overall status
	status := "completed"
	if failed > 0 && succeeded == 0 {
		status = "failed"
	} else if failed > 0 {
		status = "partial"
	}

	response := map[string]interface{}{
		"action":         "winget_install_policy_result",
		"execution_id":   req.ExecutionID,
		"policy_id":      req.PolicyID,
		"status":         status,
		"total_packages": len(req.Packages),
		"succeeded":      succeeded,
		"failed":         failed,
		"skipped":        skipped,
		"results":        results,
		"started_at":     startedAt.UTC().Format(time.RFC3339),
		"completed_at":   completedAt.UTC().Format(time.RFC3339),
		"duration_ms":    durationMs,
	}

	// Handle reboot if requested
	if req.Reboot && succeeded > 0 {
		response["reboot_scheduled"] = true
		h.ScheduleReboot("winget install policy execution")
	}

	h.SendRaw(response)
	h.logger.Info("winget install policy execution completed",
		"execution_id", req.ExecutionID,
		"status", status,
		"succeeded", succeeded,
		"failed", failed,
		"skipped", skipped,
	)

	return response, nil
}

// executeWingetUpgrade runs winget upgrade for a single package.
func (h *Handler) executeWingetUpgrade(ctx context.Context, wingetPath string, update actions.Update) wingetUpdateResult {
	result := wingetUpdateResult{
		PackageID:   update.KB, // KB contains the package ID for winget updates
		PackageName: update.Name,
		OldVersion:  update.CurrentVer,
		NewVersion:  update.Version,
	}

	// Run winget upgrade --id <package_id>
	cmd := exec.CommandContext(ctx, wingetPath, "upgrade",
		"--id", update.KB,
		"--accept-source-agreements",
		"--accept-package-agreements",
		"--disable-interactivity",
		"--silent",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check for specific exit codes
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			// 0x8A150011 = No applicable upgrade found (already up to date)
			if exitCode == 0x8A150011 || exitCode == -1978335215 {
				result.Status = "skipped"
				result.Error = "already up to date"
				return result
			}
		}
		result.Status = "failed"
		result.Error = fmt.Sprintf("upgrade failed: %v - %s", err, string(output))
		h.logger.Error("winget upgrade failed",
			"package", update.KB,
			"error", err,
			"output", string(output),
		)
		return result
	}

	result.Status = "success"
	h.logger.Info("winget upgrade succeeded",
		"package", update.KB,
		"old_version", update.CurrentVer,
		"new_version", update.Version,
	)
	return result
}

// Manual Winget Update Handlers

// wingetManualUpdateRequest is the request for single package update.
type wingetManualUpdateRequest struct {
	ExecutionID    string `json:"execution_id"`
	PackageID      string `json:"package_id"`
	PackageName    string `json:"package_name,omitempty"`
	Reboot         bool   `json:"reboot"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// wingetManualUpdatesRequest is the request for bulk update.
type wingetManualUpdatesRequest struct {
	ExecutionID    string   `json:"execution_id"`
	PackageIDs     []string `json:"package_ids"` // empty = update all
	Reboot         bool     `json:"reboot"`
	TimeoutSeconds int      `json:"timeout_seconds"`
}

// handleExecuteWingetUpdate handles single package winget update.
// It first tries user context via helper, then falls back to system context.
func (h *Handler) handleExecuteWingetUpdate(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if runtime.GOOS != "windows" {
		return map[string]interface{}{
			"status": "failed",
			"error":  "winget is only available on Windows",
		}, nil
	}

	var req wingetManualUpdateRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("executing winget single package update",
		"execution_id", req.ExecutionID,
		"package_id", req.PackageID,
	)

	// Check if winget is available
	wingetClient := winget.GetDefault()
	if !wingetClient.IsAvailable() {
		response := map[string]interface{}{
			"action":       "winget_update_result",
			"execution_id": req.ExecutionID,
			"status":       "failed",
			"error":        "winget is not available on this system",
		}
		h.SendRaw(response)
		return response, nil
	}

	startedAt := time.Now()
	wingetPath := wingetClient.GetBinaryPath()

	// First try user context via helper (for per-user installed packages)
	h.logger.Info("trying winget update in user context first", "package_id", req.PackageID)
	h.SendRaw(map[string]interface{}{
		"action":       "winget_update_output",
		"execution_id": req.ExecutionID,
		"output":       "Trying user context...\n",
	})

	helperClient, helperErr := helper.GetManager().Acquire()
	if helperErr == nil {
		defer helper.GetManager().Release()

		result, err := helperClient.UpgradeWingetPackage(wingetPath, req.PackageID)
		if err == nil && result != nil {
			// Check if user context succeeded
			if result.Success {
				h.SendRaw(map[string]interface{}{
					"action":       "winget_update_output",
					"execution_id": req.ExecutionID,
					"output":       result.Output,
				})

				response := map[string]interface{}{
					"action":       "winget_update_result",
					"execution_id": req.ExecutionID,
					"status":       "completed",
					"package_id":   req.PackageID,
					"package_name": req.PackageName,
					"output":       result.Output,
					"context":      "user",
					"started_at":   startedAt.UTC().Format(time.RFC3339),
					"completed_at": time.Now().UTC().Format(time.RFC3339),
					"duration_ms":  time.Since(startedAt).Milliseconds(),
				}

				if req.Reboot {
					response["reboot_scheduled"] = true
					h.ScheduleReboot("winget update")
				}

				h.SendRaw(response)
				h.logger.Info("winget update completed via user context",
					"execution_id", req.ExecutionID,
					"package_id", req.PackageID,
				)

				// Trigger a rescan of available updates so the frontend can refresh the list
				go h.triggerUpdatesRescan(ctx)

				return response, nil
			}

			// Check for "no installed package" error - means we should try system context
			if winget.IsPackageNotFound(result.ExitCode) ||
				strings.Contains(strings.ToLower(result.Output), "no installed package") {
				h.logger.Info("package not found in user context, trying system context", "package_id", req.PackageID)
				h.SendRaw(map[string]interface{}{
					"action":       "winget_update_output",
					"execution_id": req.ExecutionID,
					"output":       "Not found in user context, trying system context...\n",
				})
			} else {
				// User context failed for other reason
				response := map[string]interface{}{
					"action":       "winget_update_result",
					"execution_id": req.ExecutionID,
					"status":       "failed",
					"package_id":   req.PackageID,
					"package_name": req.PackageName,
					"output":       result.Output,
					"error":        result.Error,
					"context":      "user",
					"started_at":   startedAt.UTC().Format(time.RFC3339),
					"completed_at": time.Now().UTC().Format(time.RFC3339),
					"duration_ms":  time.Since(startedAt).Milliseconds(),
				}
				// Include winget log if available
				if result.WingetLog != "" {
					response["winget_log"] = result.WingetLog
					h.logger.Info("winget log retrieved", "log_length", len(result.WingetLog))
				}
				h.SendRaw(response)
				h.logger.Error("winget update failed in user context",
					"execution_id", req.ExecutionID,
					"package_id", req.PackageID,
					"error", result.Error,
				)
				return response, nil
			}
		}
	} else {
		h.logger.Debug("helper not available, trying system context directly", "error", helperErr)
	}

	// Fall back to system context (original behavior)
	h.logger.Info("trying winget update in system context", "package_id", req.PackageID)

	// Set timeout
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Run winget upgrade in system context
	cmd := exec.CommandContext(ctx, wingetPath, "upgrade",
		"--id", req.PackageID,
		"--accept-source-agreements",
		"--accept-package-agreements",
		"--disable-interactivity",
		"--silent",
	)

	// Stream output
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	var outputBuffer strings.Builder
	var errorBuffer strings.Builder

	if err := cmd.Start(); err != nil {
		response := map[string]interface{}{
			"action":       "winget_update_result",
			"execution_id": req.ExecutionID,
			"status":       "failed",
			"package_id":   req.PackageID,
			"package_name": req.PackageName,
			"error":        fmt.Sprintf("failed to start winget: %v", err),
			"context":      "system",
			"started_at":   startedAt.UTC().Format(time.RFC3339),
			"completed_at": time.Now().UTC().Format(time.RFC3339),
			"duration_ms":  time.Since(startedAt).Milliseconds(),
		}
		h.SendRaw(response)
		return response, nil
	}

	// Stream stdout in goroutine
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				chunk := string(buf[:n])
				outputBuffer.WriteString(chunk)
				h.SendRaw(map[string]interface{}{
					"action":       "winget_update_output",
					"execution_id": req.ExecutionID,
					"output":       chunk,
				})
			}
			if err != nil {
				break
			}
		}
	}()

	// Stream stderr in goroutine
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				chunk := string(buf[:n])
				errorBuffer.WriteString(chunk)
				h.SendRaw(map[string]interface{}{
					"action":       "winget_update_output",
					"execution_id": req.ExecutionID,
					"output":       chunk,
				})
			}
			if err != nil {
				break
			}
		}
	}()

	err := cmd.Wait()
	completedAt := time.Now()
	durationMs := completedAt.Sub(startedAt).Milliseconds()

	status := "completed"
	errorMsg := ""

	if err != nil {
		// Check for specific exit codes
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			// 0x8A150011 = No applicable upgrade found (already up to date)
			if exitCode == 0x8A150011 || exitCode == -1978335215 {
				status = "completed"
				errorMsg = "already up to date"
			} else {
				status = "failed"
				errorMsg = fmt.Sprintf("upgrade failed with exit code %d: %v", exitCode, err)
			}
		} else {
			status = "failed"
			errorMsg = fmt.Sprintf("upgrade failed: %v", err)
		}
	}

	response := map[string]interface{}{
		"action":       "winget_update_result",
		"execution_id": req.ExecutionID,
		"status":       status,
		"package_id":   req.PackageID,
		"package_name": req.PackageName,
		"output":       outputBuffer.String(),
		"error_output": errorBuffer.String(),
		"error":        errorMsg,
		"context":      "system", // System context fallback
		"started_at":   startedAt.UTC().Format(time.RFC3339),
		"completed_at": completedAt.UTC().Format(time.RFC3339),
		"duration_ms":  durationMs,
	}

	// Handle reboot if requested and successful
	if req.Reboot && status == "completed" {
		response["reboot_scheduled"] = true
		h.ScheduleReboot("winget update")
	}

	h.SendRaw(response)

	if status == "failed" {
		h.logger.Error("winget single package update failed",
			"execution_id", req.ExecutionID,
			"package_id", req.PackageID,
			"error", errorMsg,
			"output", outputBuffer.String(),
			"error_output", errorBuffer.String(),
		)
	} else {
		h.logger.Info("winget single package update completed",
			"execution_id", req.ExecutionID,
			"package_id", req.PackageID,
			"status", status,
		)
	}

	// Trigger a rescan of available updates so the frontend can refresh the list
	go h.triggerUpdatesRescan(ctx)

	return response, nil
}

// handleExecuteWingetUpdates handles bulk winget update.
func (h *Handler) handleExecuteWingetUpdates(ctx context.Context, data json.RawMessage) (interface{}, error) {
	if runtime.GOOS != "windows" {
		return map[string]interface{}{
			"status": "failed",
			"error":  "winget is only available on Windows",
		}, nil
	}

	var req wingetManualUpdatesRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("executing winget bulk update",
		"execution_id", req.ExecutionID,
		"package_count", len(req.PackageIDs),
	)

	// Check if winget is available
	client := winget.GetDefault()
	if !client.IsAvailable() {
		response := map[string]interface{}{
			"action":       "winget_updates_result",
			"execution_id": req.ExecutionID,
			"status":       "failed",
			"error":        "winget is not available on this system",
		}
		h.SendRaw(response)
		return response, nil
	}

	startedAt := time.Now()

	// Set timeout
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 60 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	wingetPath := client.GetBinaryPath()

	// Determine packages to update
	var packagesToUpdate []string

	if len(req.PackageIDs) == 0 {
		// Get all available winget updates
		updateList, err := actions.GetAvailableUpdates(ctx)
		if err != nil {
			response := map[string]interface{}{
				"action":       "winget_updates_result",
				"execution_id": req.ExecutionID,
				"status":       "failed",
				"error":        fmt.Sprintf("failed to get updates: %v", err),
				"started_at":   startedAt.UTC().Format(time.RFC3339),
				"completed_at": time.Now().UTC().Format(time.RFC3339),
			}
			h.SendRaw(response)
			return response, nil
		}

		for _, u := range updateList.Updates {
			if u.Source == "winget" && u.KB != "" {
				packagesToUpdate = append(packagesToUpdate, u.KB)
			}
		}
	} else {
		packagesToUpdate = req.PackageIDs
	}

	if len(packagesToUpdate) == 0 {
		response := map[string]interface{}{
			"action":         "winget_updates_result",
			"execution_id":   req.ExecutionID,
			"status":         "completed",
			"total_packages": 0,
			"succeeded":      0,
			"failed":         0,
			"results":        []wingetUpdateResult{},
			"started_at":     startedAt.UTC().Format(time.RFC3339),
			"completed_at":   time.Now().UTC().Format(time.RFC3339),
			"duration_ms":    time.Since(startedAt).Milliseconds(),
		}
		h.SendRaw(response)
		return response, nil
	}

	// Execute updates
	var results []wingetUpdateResult
	var succeeded, failed int

	for i, packageID := range packagesToUpdate {
		// Send progress
		h.SendRaw(map[string]interface{}{
			"action":       "winget_updates_progress",
			"execution_id": req.ExecutionID,
			"current":      i + 1,
			"total":        len(packagesToUpdate),
			"package_id":   packageID,
			"status":       "running",
		})

		// Execute upgrade
		result := h.executeWingetUpgradeByID(ctx, wingetPath, packageID, req.ExecutionID)
		results = append(results, result)

		if result.Status == "success" {
			succeeded++
		} else if result.Status != "skipped" {
			failed++
		}

		// Send progress with result
		h.SendRaw(map[string]interface{}{
			"action":       "winget_updates_progress",
			"execution_id": req.ExecutionID,
			"current":      i + 1,
			"total":        len(packagesToUpdate),
			"package_id":   packageID,
			"status":       result.Status,
		})
	}

	completedAt := time.Now()
	durationMs := completedAt.Sub(startedAt).Milliseconds()

	// Determine overall status
	status := "completed"
	if failed > 0 && succeeded == 0 {
		status = "failed"
	} else if failed > 0 {
		status = "partial"
	}

	response := map[string]interface{}{
		"action":           "winget_updates_result",
		"execution_id":     req.ExecutionID,
		"status":           status,
		"total_packages":   len(packagesToUpdate),
		"succeeded":        succeeded,
		"failed":           failed,
		"results":          results,
		"started_at":       startedAt.UTC().Format(time.RFC3339),
		"completed_at":     completedAt.UTC().Format(time.RFC3339),
		"duration_ms":      durationMs,
		"reboot_scheduled": false,
	}

	// Handle reboot if requested and at least one update succeeded
	if req.Reboot && succeeded > 0 {
		response["reboot_scheduled"] = true
		h.ScheduleReboot("winget bulk update")
	}

	h.SendRaw(response)

	if status == "failed" {
		h.logger.Error("winget bulk update failed",
			"execution_id", req.ExecutionID,
			"status", status,
			"succeeded", succeeded,
			"failed", failed,
		)
	} else {
		h.logger.Info("winget bulk update completed",
			"execution_id", req.ExecutionID,
			"status", status,
			"succeeded", succeeded,
			"failed", failed,
		)
	}

	// Trigger a rescan of available updates so the frontend can refresh the list
	go h.triggerUpdatesRescan(ctx)

	return response, nil
}

// executeWingetUpgradeByID runs winget upgrade for a single package by ID.
func (h *Handler) executeWingetUpgradeByID(ctx context.Context, wingetPath, packageID, executionID string) wingetUpdateResult {
	result := wingetUpdateResult{
		PackageID:   packageID,
		PackageName: packageID, // Use ID as name if not known
	}

	// Run winget upgrade
	cmd := exec.CommandContext(ctx, wingetPath, "upgrade",
		"--id", packageID,
		"--accept-source-agreements",
		"--accept-package-agreements",
		"--disable-interactivity",
		"--silent",
	)

	// Stream output
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	var outputBuffer strings.Builder

	if err := cmd.Start(); err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to start winget: %v", err)
		return result
	}

	// Stream stdout
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				chunk := string(buf[:n])
				outputBuffer.WriteString(chunk)
				h.SendRaw(map[string]interface{}{
					"action":       "winget_update_output",
					"execution_id": executionID,
					"output":       chunk,
				})
			}
			if err != nil {
				break
			}
		}
	}()

	// Stream stderr
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				chunk := string(buf[:n])
				outputBuffer.WriteString(chunk)
				h.SendRaw(map[string]interface{}{
					"action":       "winget_update_output",
					"execution_id": executionID,
					"output":       chunk,
				})
			}
			if err != nil {
				break
			}
		}
	}()

	err := cmd.Wait()

	if err != nil {
		// Check for specific exit codes
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			// 0x8A150011 = No applicable upgrade found (already up to date)
			if exitCode == 0x8A150011 || exitCode == -1978335215 {
				result.Status = "skipped"
				result.Error = "already up to date"
				return result
			}
		}
		result.Status = "failed"
		result.Error = fmt.Sprintf("upgrade failed: %v - %s", err, outputBuffer.String())
		h.logger.Error("winget upgrade failed",
			"package", packageID,
			"error", err,
		)
		return result
	}

	result.Status = "success"
	h.logger.Info("winget upgrade succeeded",
		"package", packageID,
	)
	return result
}

// triggerUpdatesRescan performs a rescan of available updates after winget operations
// and sends the result to the backend so the UI can be refreshed.
func (h *Handler) triggerUpdatesRescan(ctx context.Context) {
	h.logger.Info("triggering updates rescan after winget operation")

	// Use a fresh context with timeout for the rescan
	rescanCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	result, err := actions.GetAvailableUpdates(rescanCtx)
	if err != nil {
		h.logger.Error("updates rescan failed", "error", err)
		return
	}

	if result == nil {
		h.logger.Warn("updates rescan returned nil result")
		return
	}

	h.logger.Info("updates rescan completed", "count", result.Count, "source", result.Source)

	// Send the updated list to the backend
	h.SendRaw(map[string]interface{}{
		"action":    "run_osquery",
		"scan_type": "updates",
		"data":      result,
	})
}
