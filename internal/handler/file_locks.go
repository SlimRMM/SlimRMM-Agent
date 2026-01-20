// Package handler provides file-lock detection and resolution functions.
// Delegates to DefaultFileLockService for business logic (MVC pattern).
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/services/models"
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
	Lock       FileLock `json:"lock"`
	Strategy   string   `json:"strategy"`
	Success    bool     `json:"success"`
	Error      string   `json:"error,omitempty"`
	NewPath    string   `json:"new_path,omitempty"` // For rename strategy
	Scheduled  bool     `json:"scheduled,omitempty"` // For schedule strategy
}

// ProcessInfo represents information about a running process.
type ProcessInfo struct {
	Name string `json:"name"`
	PID  int    `json:"pid"`
	User string `json:"user,omitempty"`
	CPU  string `json:"cpu,omitempty"`
	Mem  string `json:"mem,omitempty"`
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

// =============================================================================
// Unix (macOS/Linux) File Lock Detection
// =============================================================================

// detectUnixFileLocks detects file locks using lsof.
func detectUnixFileLocks(ctx context.Context, path string, includeSubdirs bool) ([]FileLock, error) {
	var locks []FileLock

	// Check if path exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return locks, nil
	}

	// Use lsof to detect locks
	var args []string
	if includeSubdirs {
		args = []string{"+D", path}
	} else {
		args = []string{path}
	}

	cmd := exec.CommandContext(ctx, "lsof", args...)
	output, _ := cmd.Output()

	// Parse lsof output
	// Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i == 0 || line == "" { // Skip header
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		pid, _ := strconv.Atoi(fields[1])
		lock := FileLock{
			Command:     fields[0],
			ProcessName: fields[0],
			PID:         pid,
			User:        fields[2],
			LockType:    parseLockType(fields[3]),
			FileType:    fields[4],
			Path:        fields[len(fields)-1],
		}

		locks = append(locks, lock)
	}

	return locks, nil
}

// parseLockType converts lsof FD field to lock type.
func parseLockType(fd string) string {
	fd = strings.ToLower(fd)
	switch {
	case strings.Contains(fd, "r"):
		return "read"
	case strings.Contains(fd, "w"):
		return "write"
	case strings.Contains(fd, "u"):
		return "read_write"
	default:
		return "unknown"
	}
}

// =============================================================================
// Windows File Lock Detection
// =============================================================================

// detectWindowsFileLocks detects file locks using PowerShell and handles.
func detectWindowsFileLocks(ctx context.Context, path string, includeSubdirs bool) ([]FileLock, error) {
	var locks []FileLock

	// Check if path exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return locks, nil
	}

	// First, try using PowerShell to find processes with handles
	psScript := `
$targetPath = '%s'
Get-Process | ForEach-Object {
    $proc = $_
    try {
        $proc.Modules | Where-Object { $_.FileName -like "$targetPath*" } |
        ForEach-Object {
            [PSCustomObject]@{
                ProcessName = $proc.ProcessName
                ProcessId = $proc.Id
                Path = $_.FileName
            }
        }
    } catch {}
} | ConvertTo-Json -Compress
`

	script := fmt.Sprintf(psScript, strings.ReplaceAll(path, `\`, `\\`))
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.Output()
	if err == nil && len(output) > 0 {
		// Parse JSON output
		var results []struct {
			ProcessName string `json:"ProcessName"`
			ProcessId   int    `json:"ProcessId"`
			Path        string `json:"Path"`
		}

		if err := json.Unmarshal(output, &results); err == nil {
			for _, r := range results {
				locks = append(locks, FileLock{
					ProcessName: r.ProcessName,
					PID:         r.ProcessId,
					Path:        r.Path,
					LockType:    "unknown",
				})
			}
		}
	}

	// Additionally check for open file handles using a WMI query
	wmiScript := `
$targetPath = '%s'
Get-WmiObject -Query "SELECT * FROM CIM_ProcessExecutable" |
Where-Object { $_.Antecedent -like "*$targetPath*" } |
ForEach-Object {
    $proc = [wmi]$_.Dependent
    [PSCustomObject]@{
        ProcessName = $proc.Name
        ProcessId = $proc.ProcessId
        Path = ($_.Antecedent -split '"')[1]
    }
} | ConvertTo-Json -Compress
`
	script = fmt.Sprintf(wmiScript, strings.ReplaceAll(path, `\`, `\\`))
	cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err = cmd.Output()
	if err == nil && len(output) > 0 {
		var results []struct {
			ProcessName string `json:"ProcessName"`
			ProcessId   int    `json:"ProcessId"`
			Path        string `json:"Path"`
		}

		if err := json.Unmarshal(output, &results); err == nil {
			for _, r := range results {
				// Avoid duplicates
				isDuplicate := false
				for _, existing := range locks {
					if existing.PID == r.ProcessId && existing.Path == r.Path {
						isDuplicate = true
						break
					}
				}
				if !isDuplicate {
					locks = append(locks, FileLock{
						ProcessName: r.ProcessName,
						PID:         r.ProcessId,
						Path:        r.Path,
						LockType:    "unknown",
					})
				}
			}
		}
	}

	return locks, nil
}

// =============================================================================
// File Lock Resolution
// =============================================================================

// registerFileLockHandlers registers file lock handlers.
func (h *Handler) registerFileLockHandlers() {
	h.handlers["resolve_file_locks"] = h.handleResolveFileLocks
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

// resolveLockByTerminating terminates the process holding the lock.
func (h *Handler) resolveLockByTerminating(ctx context.Context, lock FileLock, force bool) FileLockResolutionResult {
	result := FileLockResolutionResult{
		Lock:     lock,
		Strategy: "terminate",
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		if force {
			cmd = exec.CommandContext(ctx, "taskkill", "/PID", strconv.Itoa(lock.PID), "/F")
		} else {
			cmd = exec.CommandContext(ctx, "taskkill", "/PID", strconv.Itoa(lock.PID))
		}
	} else {
		signal := "TERM"
		if force {
			signal = "KILL"
		}
		cmd = exec.CommandContext(ctx, "kill", fmt.Sprintf("-%s", signal), strconv.Itoa(lock.PID))
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("failed to terminate process: %s", stderr.String())
	} else {
		result.Success = true

		// Wait a moment for the process to terminate
		time.Sleep(500 * time.Millisecond)

		// Verify process is gone
		if isProcessRunning(lock.PID) {
			result.Success = false
			result.Error = "process still running after termination attempt"
		}
	}

	return result
}

// resolveLockByScheduling schedules deletion on next reboot (Windows only).
func (h *Handler) resolveLockByScheduling(ctx context.Context, lock FileLock) FileLockResolutionResult {
	result := FileLockResolutionResult{
		Lock:     lock,
		Strategy: "schedule",
	}

	if runtime.GOOS != "windows" {
		result.Success = false
		result.Error = "scheduled deletion only supported on Windows"
		return result
	}

	// Use MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT
	psScript := fmt.Sprintf(`
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class FileUtil {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
    public const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;
}
"@
[FileUtil]::MoveFileEx("%s", $null, [FileUtil]::MOVEFILE_DELAY_UNTIL_REBOOT)
`, strings.ReplaceAll(lock.Path, `\`, `\\`))

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("failed to schedule deletion: %s", stderr.String())
	} else {
		result.Success = true
		result.Scheduled = true
	}

	return result
}

// resolveLockByRenaming renames the locked file.
func (h *Handler) resolveLockByRenaming(ctx context.Context, lock FileLock) FileLockResolutionResult {
	result := FileLockResolutionResult{
		Lock:     lock,
		Strategy: "rename",
	}

	// Generate new name with .old extension and timestamp
	timestamp := time.Now().Format("20060102_150405")
	newPath := fmt.Sprintf("%s.old_%s", lock.Path, timestamp)

	if err := os.Rename(lock.Path, newPath); err != nil {
		result.Success = false
		result.Error = fmt.Sprintf("failed to rename: %v", err)
	} else {
		result.Success = true
		result.NewPath = newPath
	}

	return result
}

// isProcessRunning checks if a process is still running.
func isProcessRunning(pid int) bool {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/FO", "CSV", "/NH")
		output, err := cmd.Output()
		if err != nil {
			return false
		}
		return strings.Contains(string(output), strconv.Itoa(pid))
	}

	// Unix: Check if process exists
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// On Unix, FindProcess always succeeds. We need to send signal 0 to check.
	if runtime.GOOS != "windows" {
		cmd := exec.Command("kill", "-0", strconv.Itoa(pid))
		return cmd.Run() == nil
	}

	return process != nil
}

// =============================================================================
// Batch Lock Operations
// =============================================================================

// BatchKillProcessesRequest represents a request to kill multiple processes.
type BatchKillProcessesRequest struct {
	PIDs          []int  `json:"pids"`
	Signal        string `json:"signal"` // TERM or KILL
	GracePeriodMs int    `json:"grace_period_ms"`
}

// handleBatchKillProcesses handles batch process termination.
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

		if err := sendSignalToProcess(pid, signal); err != nil {
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
		if isProcessRunning(pid) {
			// Force kill
			if err := sendSignalToProcess(pid, "KILL"); err != nil {
				results[i]["final_success"] = false
				results[i]["force_kill_error"] = err.Error()
			} else {
				results[i]["force_kill"] = true
				time.Sleep(100 * time.Millisecond)
				results[i]["final_success"] = !isProcessRunning(pid)
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

// sendSignalToProcess sends a signal to a process.
func sendSignalToProcess(pid int, signal string) error {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		if signal == "KILL" {
			cmd = exec.Command("taskkill", "/PID", strconv.Itoa(pid), "/F")
		} else {
			cmd = exec.Command("taskkill", "/PID", strconv.Itoa(pid))
		}
	} else {
		cmd = exec.Command("kill", fmt.Sprintf("-%s", signal), strconv.Itoa(pid))
	}

	return cmd.Run()
}

// =============================================================================
// File Lock Monitor
// =============================================================================

// WaitForLocksRelease waits for file locks to be released.
func WaitForLocksRelease(ctx context.Context, paths []string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	checkInterval := 500 * time.Millisecond

	for time.Now().Before(deadline) {
		allClear := true

		for _, path := range paths {
			var locks []FileLock
			var err error

			switch runtime.GOOS {
			case "darwin", "linux":
				locks, err = detectUnixFileLocks(ctx, path, false)
			case "windows":
				locks, err = detectWindowsFileLocks(ctx, path, false)
			}

			if err != nil {
				continue
			}

			if len(locks) > 0 {
				allClear = false
				break
			}
		}

		if allClear {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(checkInterval):
			continue
		}
	}

	return fmt.Errorf("timeout waiting for locks to be released")
}

// GetFileHandleCount returns the number of open handles for a path.
func GetFileHandleCount(ctx context.Context, path string) int {
	var locks []FileLock
	var err error

	switch runtime.GOOS {
	case "darwin", "linux":
		locks, err = detectUnixFileLocks(ctx, path, true)
	case "windows":
		locks, err = detectWindowsFileLocks(ctx, path, true)
	}

	if err != nil {
		return -1
	}

	return len(locks)
}

// =============================================================================
// Process Utilities
// =============================================================================

// GetProcessInfo returns detailed information about a process.
func GetProcessInfo(ctx context.Context, pid int) (*ProcessInfo, error) {
	info := &ProcessInfo{PID: pid}

	switch runtime.GOOS {
	case "darwin", "linux":
		// Use ps to get process info
		cmd := exec.CommandContext(ctx, "ps", "-p", strconv.Itoa(pid), "-o", "comm=,user=,%cpu=,%mem=")
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("process not found: %d", pid)
		}

		fields := strings.Fields(string(output))
		if len(fields) >= 1 {
			info.Name = fields[0]
		}
		if len(fields) >= 2 {
			info.User = fields[1]
		}
		if len(fields) >= 3 {
			info.CPU = fields[2]
		}
		if len(fields) >= 4 {
			info.Mem = fields[3]
		}

	case "windows":
		// Use wmic or tasklist
		cmd := exec.CommandContext(ctx, "wmic", "process", "where",
			fmt.Sprintf("processid=%d", pid), "get", "name,commandline", "/format:list")
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("process not found: %d", pid)
		}

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Name=") {
				info.Name = strings.TrimPrefix(line, "Name=")
				info.Name = strings.TrimSpace(info.Name)
			}
		}
	}

	return info, nil
}

// GetProcessTree returns all child processes of a given PID.
func GetProcessTree(ctx context.Context, pid int) ([]int, error) {
	var children []int

	switch runtime.GOOS {
	case "darwin", "linux":
		// Use pgrep to find child processes
		cmd := exec.CommandContext(ctx, "pgrep", "-P", strconv.Itoa(pid))
		output, _ := cmd.Output()

		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			if childPID, err := strconv.Atoi(strings.TrimSpace(line)); err == nil {
				children = append(children, childPID)
				// Recursively get grandchildren
				grandchildren, _ := GetProcessTree(ctx, childPID)
				children = append(children, grandchildren...)
			}
		}

	case "windows":
		// Use wmic to find child processes
		cmd := exec.CommandContext(ctx, "wmic", "process", "where",
			fmt.Sprintf("ParentProcessId=%d", pid), "get", "ProcessId", "/format:list")
		output, _ := cmd.Output()

		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "ProcessId=") {
				pidStr := strings.TrimPrefix(line, "ProcessId=")
				pidStr = strings.TrimSpace(pidStr)
				if childPID, err := strconv.Atoi(pidStr); err == nil {
					children = append(children, childPID)
					grandchildren, _ := GetProcessTree(ctx, childPID)
					children = append(children, grandchildren...)
				}
			}
		}
	}

	return children, nil
}

// KillProcessTree kills a process and all its children.
func KillProcessTree(ctx context.Context, pid int, force bool) error {
	// Get all children first
	children, _ := GetProcessTree(ctx, pid)

	// Kill children first (in reverse order to kill grandchildren before children)
	for i := len(children) - 1; i >= 0; i-- {
		signal := "TERM"
		if force {
			signal = "KILL"
		}
		sendSignalToProcess(children[i], signal)
	}

	// Wait a moment
	time.Sleep(100 * time.Millisecond)

	// Kill the parent process
	signal := "TERM"
	if force {
		signal = "KILL"
	}
	return sendSignalToProcess(pid, signal)
}
