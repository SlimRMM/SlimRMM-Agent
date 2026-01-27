// Package safecmd provides memory-safe command execution wrappers.
//
// The standard exec.Cmd.Output() and CombinedOutput() methods load the entire
// command output into memory, which can cause memory exhaustion (DoS) if a
// malicious or misconfigured command produces gigabytes of output.
//
// This package provides wrappers that enforce a maximum output size limit,
// preventing memory exhaustion attacks.
package safecmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
)

// DefaultMaxOutputSize is the default maximum output size (10 MB).
const DefaultMaxOutputSize = 10 * 1024 * 1024

// MaxOutputSize is the maximum allowed output limit (100 MB).
const MaxOutputSize = 100 * 1024 * 1024

// ErrOutputTooLarge is returned when command output exceeds the size limit.
var ErrOutputTooLarge = errors.New("command output exceeds size limit")

// Config holds configuration for safe command execution.
type Config struct {
	// MaxOutput is the maximum allowed output size in bytes.
	// Default is DefaultMaxOutputSize (10 MB).
	MaxOutput int64
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		MaxOutput: DefaultMaxOutputSize,
	}
}

// Output runs the command and returns its standard output with a size limit.
// If the output exceeds the size limit, ErrOutputTooLarge is returned.
func Output(cmd *exec.Cmd, cfg Config) ([]byte, error) {
	return OutputContext(context.Background(), cmd, cfg)
}

// OutputContext runs the command with context and returns its standard output with a size limit.
func OutputContext(ctx context.Context, cmd *exec.Cmd, cfg Config) ([]byte, error) {
	if cfg.MaxOutput <= 0 {
		cfg.MaxOutput = DefaultMaxOutputSize
	}
	if cfg.MaxOutput > MaxOutputSize {
		cfg.MaxOutput = MaxOutputSize
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting command: %w", err)
	}

	// Use LimitReader to prevent memory exhaustion
	limitedReader := io.LimitReader(stdout, cfg.MaxOutput+1) // +1 to detect overflow
	var buf bytes.Buffer
	n, readErr := io.Copy(&buf, limitedReader)

	// Wait for command to finish
	waitErr := cmd.Wait()

	// Check for context cancellation
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Check if output was truncated (exceeded limit)
	if n > cfg.MaxOutput {
		return buf.Bytes()[:cfg.MaxOutput], fmt.Errorf("%w: got at least %d bytes, limit is %d",
			ErrOutputTooLarge, n, cfg.MaxOutput)
	}

	if readErr != nil {
		return buf.Bytes(), fmt.Errorf("reading stdout: %w", readErr)
	}

	if waitErr != nil {
		return buf.Bytes(), waitErr
	}

	return buf.Bytes(), nil
}

// CombinedOutput runs the command and returns its combined stdout and stderr with a size limit.
func CombinedOutput(cmd *exec.Cmd, cfg Config) ([]byte, error) {
	return CombinedOutputContext(context.Background(), cmd, cfg)
}

// CombinedOutputContext runs the command with context and returns combined output with a size limit.
func CombinedOutputContext(ctx context.Context, cmd *exec.Cmd, cfg Config) ([]byte, error) {
	if cfg.MaxOutput <= 0 {
		cfg.MaxOutput = DefaultMaxOutputSize
	}
	if cfg.MaxOutput > MaxOutputSize {
		cfg.MaxOutput = MaxOutputSize
	}

	// For combined output, we need to redirect stderr to stdout
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdout pipe: %w", err)
	}

	// Create a pipe for stderr that writes to a limited buffer
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting command: %w", err)
	}

	// Read both stdout and stderr with combined size limit
	var buf bytes.Buffer
	multiReader := io.MultiReader(stdout, stderrPipe)
	limitedReader := io.LimitReader(multiReader, cfg.MaxOutput+1)
	n, readErr := io.Copy(&buf, limitedReader)

	// Wait for command to finish
	waitErr := cmd.Wait()

	// Check for context cancellation
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Check if output was truncated
	if n > cfg.MaxOutput {
		return buf.Bytes()[:cfg.MaxOutput], fmt.Errorf("%w: got at least %d bytes, limit is %d",
			ErrOutputTooLarge, n, cfg.MaxOutput)
	}

	if readErr != nil {
		return buf.Bytes(), fmt.Errorf("reading output: %w", readErr)
	}

	if waitErr != nil {
		return buf.Bytes(), waitErr
	}

	return buf.Bytes(), nil
}

// Run runs the command with output size limits and returns stdout, stderr, and error.
// This is useful when you need both outputs separately.
func Run(cmd *exec.Cmd, cfg Config) (stdout, stderr []byte, err error) {
	return RunContext(context.Background(), cmd, cfg)
}

// RunContext runs the command with context and returns stdout, stderr, and error.
func RunContext(ctx context.Context, cmd *exec.Cmd, cfg Config) (stdout, stderr []byte, err error) {
	if cfg.MaxOutput <= 0 {
		cfg.MaxOutput = DefaultMaxOutputSize
	}
	if cfg.MaxOutput > MaxOutputSize {
		cfg.MaxOutput = MaxOutputSize
	}

	// Set up pipes
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("creating stdout pipe: %w", err)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("creating stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("starting command: %w", err)
	}

	// Read both with size limits (split limit between stdout and stderr)
	halfLimit := cfg.MaxOutput / 2

	var stdoutBuf, stderrBuf bytes.Buffer

	// Read stdout
	stdoutLimited := io.LimitReader(stdoutPipe, halfLimit+1)
	stdoutN, stdoutErr := io.Copy(&stdoutBuf, stdoutLimited)

	// Read stderr
	stderrLimited := io.LimitReader(stderrPipe, halfLimit+1)
	stderrN, stderrErr := io.Copy(&stderrBuf, stderrLimited)

	// Wait for command to finish
	waitErr := cmd.Wait()

	// Check for context cancellation
	if ctx.Err() != nil {
		return stdoutBuf.Bytes(), stderrBuf.Bytes(), ctx.Err()
	}

	// Check for truncation
	if stdoutN > halfLimit || stderrN > halfLimit {
		return stdoutBuf.Bytes(), stderrBuf.Bytes(), fmt.Errorf("%w: stdout=%d bytes, stderr=%d bytes, limit=%d per stream",
			ErrOutputTooLarge, stdoutN, stderrN, halfLimit)
	}

	if stdoutErr != nil {
		return stdoutBuf.Bytes(), stderrBuf.Bytes(), fmt.Errorf("reading stdout: %w", stdoutErr)
	}

	if stderrErr != nil {
		return stdoutBuf.Bytes(), stderrBuf.Bytes(), fmt.Errorf("reading stderr: %w", stderrErr)
	}

	return stdoutBuf.Bytes(), stderrBuf.Bytes(), waitErr
}

// OutputString runs the command and returns output as a string.
func OutputString(cmd *exec.Cmd, cfg Config) (string, error) {
	out, err := Output(cmd, cfg)
	return string(out), err
}

// CombinedOutputString runs the command and returns combined output as a string.
func CombinedOutputString(cmd *exec.Cmd, cfg Config) (string, error) {
	out, err := CombinedOutput(cmd, cfg)
	return string(out), err
}
