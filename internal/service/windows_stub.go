//go:build !windows
// +build !windows

// Package service provides a stub for Windows service management on non-Windows platforms.
package service

// newWindowsManager returns nil on non-Windows platforms.
func newWindowsManager() Manager {
	return nil
}
