//go:build !windows
// +build !windows

package winget

import "context"

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
