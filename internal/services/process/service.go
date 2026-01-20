// Package process provides process management services.
package process

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// DefaultProcessService implements ProcessService.
type DefaultProcessService struct {
	logger *slog.Logger
}

// NewProcessService creates a new process service.
func NewProcessService(logger *slog.Logger) *DefaultProcessService {
	return &DefaultProcessService{logger: logger}
}

// GetProcessInfo returns detailed information about a process.
func (s *DefaultProcessService) GetProcessInfo(ctx context.Context, pid int) (*ProcessInfo, error) {
	info := &ProcessInfo{PID: pid}

	switch runtime.GOOS {
	case "darwin", "linux":
		return s.getUnixProcessInfo(ctx, pid, info)
	case "windows":
		return s.getWindowsProcessInfo(ctx, pid, info)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// getUnixProcessInfo gets process info on Unix systems.
func (s *DefaultProcessService) getUnixProcessInfo(ctx context.Context, pid int, info *ProcessInfo) (*ProcessInfo, error) {
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

	return info, nil
}

// getWindowsProcessInfo gets process info on Windows.
func (s *DefaultProcessService) getWindowsProcessInfo(ctx context.Context, pid int, info *ProcessInfo) (*ProcessInfo, error) {
	cmd := exec.CommandContext(ctx, "wmic", "process", "where",
		fmt.Sprintf("processid=%d", pid), "get", "name,commandline", "/format:list")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("process not found: %d", pid)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Name=") {
			info.Name = strings.TrimPrefix(line, "Name=")
		}
		if strings.HasPrefix(line, "CommandLine=") {
			info.Command = strings.TrimPrefix(line, "CommandLine=")
		}
	}

	return info, nil
}

// GetProcessTree returns all child processes of a given PID.
func (s *DefaultProcessService) GetProcessTree(ctx context.Context, pid int) ([]int, error) {
	switch runtime.GOOS {
	case "darwin", "linux":
		return s.getUnixProcessTree(ctx, pid)
	case "windows":
		return s.getWindowsProcessTree(ctx, pid)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// getUnixProcessTree gets process tree on Unix systems.
func (s *DefaultProcessService) getUnixProcessTree(ctx context.Context, pid int) ([]int, error) {
	var children []int

	cmd := exec.CommandContext(ctx, "pgrep", "-P", strconv.Itoa(pid))
	output, _ := cmd.Output()

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if childPID, err := strconv.Atoi(line); err == nil {
			children = append(children, childPID)
			grandchildren, _ := s.getUnixProcessTree(ctx, childPID)
			children = append(children, grandchildren...)
		}
	}

	return children, nil
}

// getWindowsProcessTree gets process tree on Windows.
func (s *DefaultProcessService) getWindowsProcessTree(ctx context.Context, pid int) ([]int, error) {
	var children []int

	cmd := exec.CommandContext(ctx, "wmic", "process", "where",
		fmt.Sprintf("ParentProcessId=%d", pid), "get", "ProcessId", "/format:list")
	output, _ := cmd.Output()

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ProcessId=") {
			pidStr := strings.TrimPrefix(line, "ProcessId=")
			pidStr = strings.TrimSpace(pidStr)
			if childPID, err := strconv.Atoi(pidStr); err == nil {
				children = append(children, childPID)
				grandchildren, _ := s.getWindowsProcessTree(ctx, childPID)
				children = append(children, grandchildren...)
			}
		}
	}

	return children, nil
}

// IsProcessRunning checks if a process is still running.
func (s *DefaultProcessService) IsProcessRunning(ctx context.Context, pid int) bool {
	if runtime.GOOS == "windows" {
		cmd := exec.CommandContext(ctx, "tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/FO", "CSV", "/NH")
		output, err := cmd.Output()
		if err != nil {
			return false
		}
		return strings.Contains(string(output), strconv.Itoa(pid))
	}

	// Unix: Check if process exists using signal 0
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// On Unix, FindProcess always succeeds. Send signal 0 to check.
	cmd := exec.CommandContext(ctx, "kill", "-0", strconv.Itoa(pid))
	err = cmd.Run()
	return err == nil && process != nil
}

// SendSignal sends a signal to a process.
func (s *DefaultProcessService) SendSignal(ctx context.Context, pid int, signal Signal) error {
	s.logger.Debug("sending signal to process", "pid", pid, "signal", signal)

	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		if signal == SignalKill {
			cmd = exec.CommandContext(ctx, "taskkill", "/PID", strconv.Itoa(pid), "/F")
		} else {
			cmd = exec.CommandContext(ctx, "taskkill", "/PID", strconv.Itoa(pid))
		}
	} else {
		cmd = exec.CommandContext(ctx, "kill", fmt.Sprintf("-%s", signal), strconv.Itoa(pid))
	}

	return cmd.Run()
}

// KillProcess terminates a process.
func (s *DefaultProcessService) KillProcess(ctx context.Context, pid int, force bool) error {
	s.logger.Info("killing process", "pid", pid, "force", force)

	signal := SignalTerm
	if force {
		signal = SignalKill
	}

	if err := s.SendSignal(ctx, pid, signal); err != nil {
		return err
	}

	// Wait for process to terminate
	time.Sleep(500 * time.Millisecond)

	if s.IsProcessRunning(ctx, pid) {
		if !force {
			// Try force kill
			return s.SendSignal(ctx, pid, SignalKill)
		}
		return fmt.Errorf("process %d still running after kill", pid)
	}

	return nil
}

// KillProcessTree kills a process and all its children.
func (s *DefaultProcessService) KillProcessTree(ctx context.Context, pid int, force bool) error {
	s.logger.Info("killing process tree", "pid", pid, "force", force)

	// Get all children first
	children, _ := s.GetProcessTree(ctx, pid)

	signal := SignalTerm
	if force {
		signal = SignalKill
	}

	// Kill children first (in reverse order to kill grandchildren before children)
	for i := len(children) - 1; i >= 0; i-- {
		if err := s.SendSignal(ctx, children[i], signal); err != nil {
			s.logger.Warn("failed to kill child process", "pid", children[i], "error", err)
		}
	}

	// Wait a moment
	time.Sleep(100 * time.Millisecond)

	// Kill the parent process
	return s.SendSignal(ctx, pid, signal)
}
