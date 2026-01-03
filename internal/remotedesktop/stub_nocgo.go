//go:build !cgo

// Package remotedesktop provides WebRTC-based screen sharing and remote control.
// This file provides stub implementations when CGO is disabled.
package remotedesktop

import (
	"log/slog"
)

const errCGODisabled = "remote desktop requires CGO to be enabled"

// Session stub for non-CGO builds.
type Session struct{}

// HasDisplayServer always returns false when CGO is disabled.
func HasDisplayServer() bool {
	return false
}

// CheckDependencies returns all features as unavailable when CGO is disabled.
func CheckDependencies() map[string]bool {
	return map[string]bool{
		"screen_capture": false,
		"webrtc":         false,
		"input_control":  false,
		"clipboard":      false,
		"display_server": false,
		"all_required":   false,
		"full_control":   false,
		"cgo_enabled":    false,
	}
}

// GetMonitors returns an error when CGO is disabled.
func GetMonitors() map[string]interface{} {
	return map[string]interface{}{
		"success":  false,
		"error":    errCGODisabled,
		"monitors": []Monitor{},
	}
}

// StartSession returns an error when CGO is disabled.
func StartSession(sessionID string, sendCallback SendCallback, logger *slog.Logger) *StartResult {
	return &StartResult{
		Success: false,
		Error:   errCGODisabled,
	}
}

// StopSession returns an error when CGO is disabled.
func StopSession(sessionID string) map[string]interface{} {
	return map[string]interface{}{
		"success": false,
		"error":   errCGODisabled,
	}
}

// HandleAnswer returns an error when CGO is disabled.
func HandleAnswer(sessionID string, answer SessionDescription) map[string]interface{} {
	return map[string]interface{}{
		"success": false,
		"error":   errCGODisabled,
	}
}

// HandleICECandidate returns an error when CGO is disabled.
func HandleICECandidate(sessionID string, candidate ICECandidate) map[string]interface{} {
	return map[string]interface{}{
		"success": false,
		"error":   errCGODisabled,
	}
}

// HandleRemoteControl returns an error when CGO is disabled.
func HandleRemoteControl(sessionID string, event InputEvent) map[string]interface{} {
	return map[string]interface{}{
		"success": false,
		"error":   errCGODisabled,
	}
}

// SetQuality returns an error when CGO is disabled.
func SetQuality(sessionID string, quality string) map[string]interface{} {
	return map[string]interface{}{
		"success": false,
		"error":   errCGODisabled,
	}
}

// SetMonitor returns an error when CGO is disabled.
func SetMonitor(sessionID string, monitorID int) map[string]interface{} {
	return map[string]interface{}{
		"success": false,
		"error":   errCGODisabled,
	}
}

// StopAllSessions is a no-op when CGO is disabled.
func StopAllSessions() {}

// InitializePermissions is a no-op when CGO is disabled.
func InitializePermissions(logger *slog.Logger) {}

// GetPermissionStatus returns all permissions as unavailable when CGO is disabled.
func GetPermissionStatus() map[string]bool {
	return map[string]bool{
		"screen_recording": false,
		"accessibility":    false,
		"cgo_enabled":      false,
	}
}

// CheckScreenRecordingPermission returns false when CGO is disabled.
func CheckScreenRecordingPermission() bool {
	return false
}

// CheckAccessibilityPermission returns false when CGO is disabled.
func CheckAccessibilityPermission() bool {
	return false
}

// RequestScreenRecordingPermission returns false when CGO is disabled.
func RequestScreenRecordingPermission() bool {
	return false
}

// RequestAccessibilityPermission is a no-op when CGO is disabled.
func RequestAccessibilityPermission() {}

// TriggerScreenRecordingPermission returns false when CGO is disabled.
func TriggerScreenRecordingPermission() bool {
	return false
}
