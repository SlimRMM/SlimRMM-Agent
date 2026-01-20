//go:build windows
// +build windows

package winget

import (
	"context"
	"os/exec"
	"strings"
)

// executeWingetCommand executes a winget command with the given arguments.
func (c *Client) executeWingetCommand(ctx context.Context, args ...string) (string, error) {
	c.mu.RLock()
	binaryPath := c.binaryPath
	c.mu.RUnlock()

	if binaryPath == "" {
		return "", ErrWingetNotAvailable
	}

	cmd := exec.CommandContext(ctx, binaryPath, args...)
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// extractExitCode extracts the exit code from an exec error.
func extractExitCode(err error) (int, bool) {
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), true
	}
	return 0, false
}
