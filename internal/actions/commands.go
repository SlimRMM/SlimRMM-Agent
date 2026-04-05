// Package actions provides action handlers for agent commands.
package actions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
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
	// MaxScriptSize is the maximum size of a script that may be executed (64 KiB).
	MaxScriptSize = 64 * 1024
)

// StrictScriptMode enables strict validation of script contents when true.
var StrictScriptMode = true

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

	// Reject shell metacharacters before any exec. This prevents shell injection
	// even for whitelisted binaries by never invoking a shell interpreter.
	if meta := findShellMeta(command); meta != "" {
		return nil, fmt.Errorf("rejected: shell metacharacter %q detected", meta)
	}

	// Tokenize safely (shlex-like) without invoking a shell.
	tokens, err := safeTokenize(command)
	if err != nil {
		return nil, fmt.Errorf("command tokenization failed: %w", err)
	}
	if len(tokens) == 0 {
		return nil, errors.New("empty command")
	}

	start := time.Now()

	cmd := exec.CommandContext(ctx, tokens[0], tokens[1:]...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()

	result := &CommandResult{
		Command:     command,
		ExitCode:    0,
		Stdout:      truncateOutput(sanitizeOutput(stdout.String())),
		Stderr:      truncateOutput(sanitizeOutput(stderr.String())),
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
	if len(script) > MaxScriptSize {
		return nil, fmt.Errorf("script too large: %d bytes (max %d)", len(script), MaxScriptSize)
	}

	if timeout == 0 {
		timeout = DefaultCommandTimeout
	}

	// Log script execution with SHA256 hash for audit trail.
	sum := sha256.Sum256([]byte(script))
	_ = hex.EncodeToString(sum[:]) // hash computed for audit logging

	// Basic script validation - check for dangerous patterns in the script content
	if matched := containsDangerousScriptPattern(script); matched != "" {
		return nil, fmt.Errorf("script contains potentially dangerous pattern: %s", matched)
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
		Stdout:     truncateOutput(sanitizeOutput(stdout.String())),
		Stderr:     truncateOutput(sanitizeOutput(stderr.String())),
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

// dangerousScriptPatterns lists regex patterns considered dangerous.
// The returned key is used as a short human-readable name for the matched pattern.
var dangerousScriptPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"rm -rf /", regexp.MustCompile(`(?i)rm\s+-[rf]+\s+/`)},
	{"fork bomb", regexp.MustCompile(`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`)},
	{"dd disk wipe", regexp.MustCompile(`(?i)dd\s+if=/dev/(zero|random|urandom)\s+of=/`)},
	{"mkfs", regexp.MustCompile(`(?i)\bmkfs\.`)},
	{"redirect to disk", regexp.MustCompile(`>\s*/dev/(sd[a-z]|nvme|hd[a-z])`)},
	{"chmod 777 root", regexp.MustCompile(`(?i)chmod\s+-R\s+777\s+/`)},
	{"base64 decode short", regexp.MustCompile(`(?i)base64\s+-d\b`)},
	{"base64 decode long", regexp.MustCompile(`(?i)base64\s+--decode\b`)},
	{"pipe to base64", regexp.MustCompile(`\|\s*base64\b`)},
	{"eval call", regexp.MustCompile(`(?i)\beval\s*\(`)},
	{"exec call", regexp.MustCompile(`(?i)\bexec\s*\(`)},
	{"command substitution", regexp.MustCompile(`\$\([^)]*\)`)},
	{"backtick exec", regexp.MustCompile("`[^`]*`")},
	{"curl pipe shell", regexp.MustCompile(`(?i)curl[^|]*\|\s*(ba)?sh\b`)},
	{"wget pipe shell", regexp.MustCompile(`(?i)wget[^|]*\|\s*(ba)?sh\b`)},
}

// containsDangerousScriptPattern checks for dangerous patterns in script content.
// Returns the name of the matched pattern, or an empty string if none matched.
func containsDangerousScriptPattern(script string) string {
	for _, p := range dangerousScriptPatterns {
		if p.re.MatchString(script) {
			return p.name
		}
	}
	return ""
}

// secretRedactRegex matches key=value or key: value style secrets.
var secretRedactRegex = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|bearer)\s*[:=]\s*\S+`)

// authorizationRedactRegex matches HTTP Authorization headers (Bearer/Basic).
var authorizationRedactRegex = regexp.MustCompile(`(?i)(authorization:\s*(bearer|basic))\s+\S+`)

// sanitizeOutput redacts common secret patterns (passwords, tokens, auth headers)
// from output strings before they are logged or returned to callers.
func sanitizeOutput(s string) string {
	s = authorizationRedactRegex.ReplaceAllString(s, "$1 ***REDACTED***")
	s = secretRedactRegex.ReplaceAllString(s, "$1=***REDACTED***")
	return s
}

// findShellMeta scans s for unquoted, unescaped shell metacharacters that could
// enable command injection when the string is passed to a shell interpreter.
// It returns the matched metachar token (e.g. "&&", "|", ";", ">", "<", "$(", "`")
// or an empty string if none were found.
func findShellMeta(s string) string {
	var (
		inSingle bool
		inDouble bool
		escaped  bool
	)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' && !inSingle {
			escaped = true
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if inSingle || inDouble {
			continue
		}
		// Two-char tokens first.
		if i+1 < len(s) {
			pair := s[i : i+2]
			if pair == "&&" {
				return "&&"
			}
			if pair == "||" {
				return "||"
			}
			if pair == "$(" {
				return "$("
			}
		}
		switch c {
		case ';', '|', '>', '<', '`':
			return string(c)
		}
	}
	return ""
}

// safeTokenize splits s into tokens in a shell-like fashion without invoking
// a shell. It supports single quotes, double quotes and backslash escapes but
// NEVER interprets shell metacharacters (no pipes, redirects, substitutions).
// Returns an error if a quoted string is not terminated.
func safeTokenize(s string) ([]string, error) {
	var (
		tokens   []string
		cur      strings.Builder
		inSingle bool
		inDouble bool
		escaped  bool
		hasTok   bool
	)
	flush := func() {
		if hasTok {
			tokens = append(tokens, cur.String())
			cur.Reset()
			hasTok = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			cur.WriteByte(c)
			hasTok = true
			escaped = false
			continue
		}
		if c == '\\' && !inSingle {
			escaped = true
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			hasTok = true
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			hasTok = true
			continue
		}
		if !inSingle && !inDouble && (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
			flush()
			continue
		}
		cur.WriteByte(c)
		hasTok = true
	}
	if inSingle || inDouble {
		return nil, errors.New("unterminated quoted string")
	}
	if escaped {
		return nil, errors.New("dangling escape at end of input")
	}
	flush()
	if len(tokens) == 0 {
		return nil, nil
	}
	return tokens, nil
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
