// Package actions provides action handlers for agent commands.
package actions

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/security/sandbox"
)

const (
	// DefaultCommandTimeout is the default timeout for command execution.
	DefaultCommandTimeout = 60 * time.Second
	// MaxOutputSize is the maximum output size before truncation (1 MB).
	MaxOutputSize = 1024 * 1024
)

// CommandResult contains the result of a command execution.
type CommandResult struct {
	Command     string `json:"command"`
	ExitCode    int    `json:"exit_code"`
	Stdout      string `json:"stdout"`
	Stderr      string `json:"stderr"`
	Duration    int64  `json:"duration_ms"`
	IsSensitive bool   `json:"is_sensitive,omitempty"`
}

// ScriptResult contains the result of a script execution.
type ScriptResult struct {
	ScriptType string `json:"script_type"`
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	Duration   int64  `json:"duration_ms"`
}

// ExecuteCommand executes a whitelisted command with comprehensive security validation.
func ExecuteCommand(ctx context.Context, command string, timeout time.Duration) (*CommandResult, error) {
	return ExecuteCommandWithAuth(ctx, command, timeout, "")
}

// ExecuteCommandWithAuth executes a command with optional authorization token.
// This is required for sensitive commands that need server authorization.
func ExecuteCommandWithAuth(ctx context.Context, command string, timeout time.Duration, authToken string) (*CommandResult, error) {
	// Sanitize command first
	command = sandbox.SanitizeCommand(command)

	// Validate command with comprehensive checks
	validation, err := sandbox.ValidateCommandWithAuth(command, authToken)
	if err != nil {
		switch {
		case errors.Is(err, sandbox.ErrCommandBlocked):
			return nil, fmt.Errorf("command blocked: %s", validation.BlockReason)
		case errors.Is(err, sandbox.ErrDangerousPattern):
			return nil, fmt.Errorf("dangerous pattern detected: %s", validation.BlockReason)
		case errors.Is(err, sandbox.ErrSensitiveCommand):
			return nil, fmt.Errorf("sensitive command requires authorization: %s", command)
		case errors.Is(err, sandbox.ErrCommandNotAllowed):
			return nil, fmt.Errorf("command not in whitelist: %s", extractBaseCommand(command))
		case errors.Is(err, sandbox.ErrEmptyCommand):
			return nil, errors.New("empty command")
		default:
			return nil, fmt.Errorf("command validation failed: %w", err)
		}
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

	err = cmd.Run()

	result := &CommandResult{
		Command:     command,
		ExitCode:    0,
		Stdout:      truncateOutput(stdout.String()),
		Stderr:      truncateOutput(stderr.String()),
		Duration:    time.Since(start).Milliseconds(),
		IsSensitive: validation.IsSensitive,
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else if ctx.Err() == context.DeadlineExceeded {
			result.ExitCode = -1
			result.Stderr = fmt.Sprintf("command timed out after %v", timeout)
		} else {
			result.ExitCode = -1
			result.Stderr = err.Error()
		}
	}

	return result, nil
}

// ExecuteScript executes a script with the specified interpreter.
// Scripts bypass the command whitelist but are logged and monitored.
func ExecuteScript(ctx context.Context, scriptType, script string, timeout time.Duration) (*ScriptResult, error) {
	if timeout == 0 {
		timeout = DefaultCommandTimeout
	}

	// Basic script validation - check for dangerous patterns in the script content
	if containsDangerousScriptPattern(script) {
		return nil, errors.New("script contains potentially dangerous patterns")
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()

	var cmd *exec.Cmd
	switch strings.ToLower(scriptType) {
	case "bash":
		if runtime.GOOS == "windows" {
			return nil, errors.New("bash not available on Windows")
		}
		cmd = exec.CommandContext(ctx, "bash", "-c", script)
	case "sh":
		if runtime.GOOS == "windows" {
			return nil, errors.New("sh not available on Windows")
		}
		cmd = exec.CommandContext(ctx, "sh", "-c", script)
	case "powershell", "ps1":
		if runtime.GOOS != "windows" {
			// Try pwsh on non-Windows (PowerShell Core)
			cmd = exec.CommandContext(ctx, "pwsh", "-NoProfile", "-NonInteractive", "-Command", script)
		} else {
			cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
		}
	case "python", "python3":
		interpreter := "python3"
		if runtime.GOOS == "windows" {
			interpreter = "python"
		}
		cmd = exec.CommandContext(ctx, interpreter, "-c", script)
	case "cmd", "batch":
		if runtime.GOOS != "windows" {
			return nil, errors.New("cmd/batch not available on non-Windows")
		}
		cmd = exec.CommandContext(ctx, "cmd", "/C", script)
	default:
		return nil, fmt.Errorf("unsupported script type: %s (supported: bash, sh, powershell, python, python3, cmd)", scriptType)
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
			result.Stderr = fmt.Sprintf("script timed out after %v", timeout)
		} else {
			result.ExitCode = -1
			result.Stderr = err.Error()
		}
	}

	return result, nil
}

// containsDangerousScriptPattern checks for dangerous patterns in script content.
func containsDangerousScriptPattern(script string) bool {
	dangerousPatterns := []string{
		"rm -rf /",
		"rm -fr /",
		":(){:|:&};:",           // Fork bomb
		"dd if=/dev/zero of=/", // Disk wipe
		"mkfs.",                 // Format filesystem
		"> /dev/sda",            // Overwrite disk
		"chmod -R 777 /",
	}

	lowerScript := strings.ToLower(script)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerScript, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// truncateOutput truncates output to MaxOutputSize.
func truncateOutput(s string) string {
	if len(s) > MaxOutputSize {
		return s[:MaxOutputSize] + "\n... [output truncated at 1 MB]"
	}
	return s
}

// extractBaseCommand extracts the base command from a full command string.
func extractBaseCommand(command string) string {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

// GetShell returns the default shell for the current OS.
func GetShell() string {
	if runtime.GOOS == "windows" {
		return "cmd"
	}
	// Check for common shells
	shells := []string{"/bin/bash", "/bin/zsh", "/bin/sh"}
	for _, shell := range shells {
		if _, err := exec.LookPath(shell); err == nil {
			return shell
		}
	}
	return "/bin/sh"
}

// GetShellArgs returns the shell arguments for executing a command.
func GetShellArgs() []string {
	if runtime.GOOS == "windows" {
		return []string{"/C"}
	}
	return []string{"-c"}
}
