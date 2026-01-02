// Package actions provides action handlers for agent commands.
package actions

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/security/sandbox"
)

const (
	DefaultCommandTimeout = 60 * time.Second
	MaxOutputSize         = 1024 * 1024 // 1 MB
)

// CommandResult contains the result of a command execution.
type CommandResult struct {
	Command  string `json:"command"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Duration int64  `json:"duration_ms"`
}

// ScriptResult contains the result of a script execution.
type ScriptResult struct {
	ScriptType string `json:"script_type"`
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	Duration   int64  `json:"duration_ms"`
}

// ExecuteCommand executes a whitelisted command.
func ExecuteCommand(ctx context.Context, command string, timeout time.Duration) (*CommandResult, error) {
	// Validate command against whitelist
	if err := sandbox.ValidateCommand(command); err != nil {
		return nil, fmt.Errorf("command validation failed: %w", err)
	}

	if timeout == 0 {
		timeout = DefaultCommandTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", command)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	result := &CommandResult{
		Command:  command,
		ExitCode: 0,
		Stdout:   truncateOutput(stdout.String()),
		Stderr:   truncateOutput(stderr.String()),
		Duration: time.Since(start).Milliseconds(),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else if ctx.Err() == context.DeadlineExceeded {
			result.ExitCode = -1
			result.Stderr = "command timed out"
		} else {
			result.ExitCode = -1
			result.Stderr = err.Error()
		}
	}

	return result, nil
}

// ExecuteScript executes a script with the specified interpreter.
func ExecuteScript(ctx context.Context, scriptType, script string, timeout time.Duration) (*ScriptResult, error) {
	if timeout == 0 {
		timeout = DefaultCommandTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()

	var cmd *exec.Cmd
	switch strings.ToLower(scriptType) {
	case "bash", "sh":
		if runtime.GOOS == "windows" {
			return nil, fmt.Errorf("bash not available on Windows")
		}
		cmd = exec.CommandContext(ctx, "bash", "-c", script)
	case "powershell", "ps1":
		if runtime.GOOS != "windows" {
			// Try pwsh on non-Windows
			cmd = exec.CommandContext(ctx, "pwsh", "-NoProfile", "-NonInteractive", "-Command", script)
		} else {
			cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
		}
	case "python", "python3":
		cmd = exec.CommandContext(ctx, "python3", "-c", script)
	default:
		return nil, fmt.Errorf("unsupported script type: %s", scriptType)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	result := &ScriptResult{
		ScriptType: scriptType,
		ExitCode:   0,
		Stdout:     truncateOutput(stdout.String()),
		Stderr:     truncateOutput(stderr.String()),
		Duration:   time.Since(start).Milliseconds(),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else if ctx.Err() == context.DeadlineExceeded {
			result.ExitCode = -1
			result.Stderr = "script timed out"
		} else {
			result.ExitCode = -1
			result.Stderr = err.Error()
		}
	}

	return result, nil
}

// truncateOutput truncates output to MaxOutputSize.
func truncateOutput(s string) string {
	if len(s) > MaxOutputSize {
		return s[:MaxOutputSize] + "\n... [truncated]"
	}
	return s
}

// GetShell returns the default shell for the current OS.
func GetShell() string {
	if runtime.GOOS == "windows" {
		return "cmd"
	}
	return "/bin/sh"
}
