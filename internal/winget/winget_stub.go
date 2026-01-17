//go:build !windows
// +build !windows

package winget

import (
	"context"
	"log/slog"
)

// findWingetBinary returns empty on non-Windows platforms.
func findWingetBinary() string {
	return ""
}

// getWingetVersion returns empty on non-Windows platforms.
func getWingetVersion(binaryPath string) string {
	return ""
}

// isSystemLevelInstall returns false on non-Windows platforms.
func isSystemLevelInstall(binaryPath string) bool {
	return false
}

// install returns an error on non-Windows platforms.
func (c *Client) install(ctx context.Context) error {
	return ErrNotWindows
}

// ensureSystemOnly is a no-op on non-Windows platforms.
func (c *Client) ensureSystemOnly(ctx context.Context, logger *slog.Logger) error {
	return nil
}

// update is a no-op on non-Windows platforms.
func (c *Client) update(ctx context.Context) error {
	return nil
}

// checkAndUpdate is a no-op on non-Windows platforms.
func (c *Client) checkAndUpdate(ctx context.Context, logger *slog.Logger) (bool, error) {
	return false, nil
}

// detectPowerShell7AndModule returns false on non-Windows platforms.
func detectPowerShell7AndModule() (ps7Available bool, moduleAvailable bool) {
	return false, false
}
