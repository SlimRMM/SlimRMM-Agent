//go:build !darwin

package remotedesktop

import (
	"log/slog"
)

// TriggerScreenRecordingPermission is a no-op on non-macOS platforms.
func TriggerScreenRecordingPermission() bool {
	return true
}

// CheckScreenRecordingPermission always returns true on non-macOS platforms.
func CheckScreenRecordingPermission() bool {
	return true
}

// RequestScreenRecordingPermission always returns true on non-macOS platforms.
func RequestScreenRecordingPermission() bool {
	return true
}

// CheckAccessibilityPermission always returns true on non-macOS platforms.
func CheckAccessibilityPermission() bool {
	return true
}

// RequestAccessibilityPermission is a no-op on non-macOS platforms.
func RequestAccessibilityPermission() {
	// No-op on non-macOS platforms
}

// InitializePermissions is a no-op on non-macOS platforms.
func InitializePermissions(logger *slog.Logger) {
	// No special permissions needed on Linux/Windows
	if logger != nil {
		logger.Debug("no special permissions required on this platform")
	}
}

// GetPermissionStatus returns all permissions as granted on non-macOS platforms.
func GetPermissionStatus() map[string]bool {
	return map[string]bool{
		"screen_recording": true,
		"accessibility":    true,
	}
}
