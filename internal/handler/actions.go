// Package handler provides action handler implementations.
package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/actions"
	"github.com/slimrmm/slimrmm-agent/internal/osquery"
	"github.com/slimrmm/slimrmm-agent/internal/security/archive"
)

// registerAllHandlers registers all action handlers.
func (h *Handler) registerHandlers() {
	// Basic
	h.handlers["ping"] = h.handlePing
	h.handlers["heartbeat"] = h.handleHeartbeat
	h.handlers["get_system_stats"] = h.handleGetSystemStats

	// Commands
	h.handlers["custom_command"] = h.handleCustomCommand
	h.handlers["execute_script"] = h.handleExecuteScript

	// File operations
	h.handlers["list_dir"] = h.handleListDir
	h.handlers["create_folder"] = h.handleCreateFolder
	h.handlers["delete_entry"] = h.handleDeleteEntry
	h.handlers["rename_entry"] = h.handleRenameEntry
	h.handlers["chmod"] = h.handleChmod
	h.handlers["chown"] = h.handleChown
	h.handlers["zip_entry"] = h.handleZipEntry
	h.handlers["unzip_entry"] = h.handleUnzipEntry

	// File transfer
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

	// System control
	h.handlers["restart"] = h.handleRestart
	h.handlers["shutdown"] = h.handleShutdown
	h.handlers["cancel_shutdown"] = h.handleCancelShutdown

	// Terminal
	h.handlers["start_terminal"] = h.handleStartTerminal
	h.handlers["terminal_input"] = h.handleTerminalInput
	h.handlers["terminal_output"] = h.handleTerminalOutput
	h.handlers["stop_terminal"] = h.handleStopTerminal

	// osquery
	h.handlers["run_osquery"] = h.handleRunOsquery

	// Agent update
	h.handlers["update_agent"] = h.handleUpdateAgent
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
	SourcePath string `json:"source_path"`
	OutputPath string `json:"output_path,omitempty"`
}

func (h *Handler) handleZipEntry(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req zipEntryRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	outputPath := req.OutputPath
	if outputPath == "" {
		outputPath = req.SourcePath + ".zip"
	}

	if err := archive.CreateZip(req.SourcePath, outputPath); err != nil {
		return nil, err
	}

	return map[string]string{"status": "zipped", "source": req.SourcePath, "output": outputPath}, nil
}

type unzipEntryRequest struct {
	SourcePath string `json:"source_path"`
	OutputPath string `json:"output_path,omitempty"`
}

func (h *Handler) handleUnzipEntry(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req unzipEntryRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	outputPath := req.OutputPath
	if outputPath == "" {
		// Remove .zip extension for output directory
		outputPath = req.SourcePath
		if len(outputPath) > 4 && outputPath[len(outputPath)-4:] == ".zip" {
			outputPath = outputPath[:len(outputPath)-4]
		}
	}

	limits := archive.DefaultLimits()
	if err := archive.ExtractZip(req.SourcePath, outputPath, limits); err != nil {
		return nil, err
	}

	return map[string]string{"status": "unzipped", "source": req.SourcePath, "output": outputPath}, nil
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

	// Handle updates scan type specially (agent-side, no SQL)
	if req.ScanType == "updates" || (req.Query == "" && req.ScanType == "") {
		// If no query provided or scan_type is updates, use internal update checker
		return actions.GetAvailableUpdates(ctx)
	}

	// If query is empty but scan_type is set, we can't run osquery
	if req.Query == "" {
		return []interface{}{}, nil
	}

	client := osquery.New()
	if !client.IsAvailable() {
		return nil, fmt.Errorf("osquery not available")
	}

	timeout := time.Duration(req.Timeout) * time.Second
	if timeout == 0 {
		timeout = osquery.DefaultTimeout
	}

	return client.QueryWithTimeout(ctx, req.Query, timeout)
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
	SessionID  string `json:"session_id"`
	ChunkIndex int    `json:"chunk_index"`
	Data       string `json:"data"` // Base64 encoded
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

	if err := h.uploadManager.UploadChunk(req.SessionID, req.ChunkIndex, chunkData); err != nil {
		return nil, err
	}

	return map[string]interface{}{"status": "received", "chunk_index": req.ChunkIndex}, nil
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

	return actions.DownloadFile(req.Path, req.Offset, req.Limit)
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
	ExecutionID    string       `json:"execution_id"`
	PolicyID       string       `json:"policy_id"`
	Patches        []struct {
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
}

func (h *Handler) handleStartTerminal(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req startTerminalRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	_, err := h.terminalManager.StartTerminal(req.TerminalID)
	if err != nil {
		return nil, err
	}

	return map[string]string{"status": "started", "terminal_id": req.TerminalID}, nil
}

type terminalInputRequest struct {
	TerminalID string `json:"terminal_id"`
	Input      string `json:"input"`
}

func (h *Handler) handleTerminalInput(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req terminalInputRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	if err := h.terminalManager.SendInput(req.TerminalID, req.Input); err != nil {
		return nil, err
	}

	return map[string]string{"status": "sent"}, nil
}

type terminalOutputRequest struct {
	TerminalID string `json:"terminal_id"`
	MaxLines   int    `json:"max_lines,omitempty"`
}

func (h *Handler) handleTerminalOutput(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req terminalOutputRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	maxLines := req.MaxLines
	if maxLines == 0 {
		maxLines = 100
	}

	lines, err := h.terminalManager.ReadOutput(ctx, req.TerminalID, maxLines)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"terminal_id": req.TerminalID,
		"lines":       lines,
		"running":     h.terminalManager.IsRunning(req.TerminalID),
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

	if err := h.terminalManager.StopTerminal(req.TerminalID); err != nil {
		return nil, err
	}

	return map[string]string{"status": "stopped", "terminal_id": req.TerminalID}, nil
}

// Agent update handler

type updateAgentRequest struct {
	URL     string `json:"url"`
	Version string `json:"version"`
	Hash    string `json:"hash,omitempty"`
}

func (h *Handler) handleUpdateAgent(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req updateAgentRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Download the new agent binary
	result, err := actions.DownloadURL(req.URL, "/tmp/slimrmm-agent-update")
	if err != nil {
		return nil, fmt.Errorf("downloading update: %w", err)
	}

	// Verify hash if provided
	if req.Hash != "" && result.Hash != req.Hash {
		return nil, fmt.Errorf("hash mismatch: expected %s, got %s", req.Hash, result.Hash)
	}

	return map[string]interface{}{
		"status":  "downloaded",
		"version": req.Version,
		"hash":    result.Hash,
		"message": "agent update downloaded, restart required",
	}, nil
}
