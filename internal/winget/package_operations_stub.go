//go:build !windows
// +build !windows

package winget

import (
	"context"
)

// executeWingetCommand is a stub for non-Windows platforms.
func (c *Client) executeWingetCommand(ctx context.Context, args ...string) (string, error) {
	return "", ErrNotWindows
}

// extractExitCode is a stub for non-Windows platforms.
func extractExitCode(err error) (int, bool) {
	return 0, false
}
