//go:build cgo

// Package remotedesktop provides WebRTC-based screen sharing and remote control.
package remotedesktop

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"sync"
)

var (
	activeSessions = make(map[string]*Session)
	sessionsMu     sync.RWMutex
)

// HasDisplayServer checks if a display server is available.
func HasDisplayServer() bool {
	switch runtime.GOOS {
	case "darwin", "windows":
		// macOS and Windows always have a display available
		return true

	case "linux":
		// Check for Wayland
		if os.Getenv("WAYLAND_DISPLAY") != "" {
			return true
		}

		// Check for X11
		display := os.Getenv("DISPLAY")
		if display != "" {
			// Try to verify X11 is actually running
			cmd := exec.Command("xset", "q")
			if err := cmd.Run(); err == nil {
				return true
			}
			// If xset fails but DISPLAY is set, assume X is running
			return true
		}

		return false

	default:
		return false
	}
}

// CheckDependencies returns availability of remote desktop features.
func CheckDependencies() map[string]bool {
	displayAvailable := HasDisplayServer()

	return map[string]bool{
		"screen_capture": displayAvailable,
		"webrtc":         true,
		"input_control":  displayAvailable,
		"clipboard":      displayAvailable,
		"display_server": displayAvailable,
		"all_required":   displayAvailable,
		"full_control":   displayAvailable,
	}
}

// GetMonitors returns list of available monitors.
func GetMonitors() map[string]interface{} {
	if !HasDisplayServer() {
		return map[string]interface{}{
			"success":  false,
			"error":    "No display server (X11/Wayland) available. Remote desktop requires a graphical environment.",
			"monitors": []Monitor{},
		}
	}

	capture, err := NewScreenCapture()
	if err != nil {
		return map[string]interface{}{
			"success":  false,
			"error":    err.Error(),
			"monitors": []Monitor{},
		}
	}
	defer capture.Close()

	return map[string]interface{}{
		"success":  true,
		"monitors": capture.GetMonitors(),
	}
}

// StartSession starts a new remote desktop session.
func StartSession(sessionID string, sendCallback SendCallback, logger *slog.Logger) *StartResult {
	if !HasDisplayServer() {
		return &StartResult{
			Success: false,
			Error:   "No display server (X11/Wayland) available. Remote desktop requires a graphical environment.",
		}
	}

	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	// Stop existing session if any
	if existing, ok := activeSessions[sessionID]; ok {
		existing.Stop()
		delete(activeSessions, sessionID)
	}

	// Create new session
	session, err := NewSession(sessionID, sendCallback, logger)
	if err != nil {
		return &StartResult{
			Success: false,
			Error:   fmt.Sprintf("creating session: %v", err),
		}
	}

	result, err := session.Start()
	if err != nil {
		session.Stop()
		return &StartResult{
			Success: false,
			Error:   err.Error(),
		}
	}

	activeSessions[sessionID] = session

	return result
}

// StopSession stops a remote desktop session.
func StopSession(sessionID string) map[string]interface{} {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	session, ok := activeSessions[sessionID]
	if !ok {
		return map[string]interface{}{
			"success": false,
			"error":   "session not found",
		}
	}

	session.Stop()
	delete(activeSessions, sessionID)

	return map[string]interface{}{"success": true}
}

// HandleAnswer handles WebRTC answer from frontend.
func HandleAnswer(sessionID string, answer SessionDescription) map[string]interface{} {
	sessionsMu.RLock()
	session, ok := activeSessions[sessionID]
	sessionsMu.RUnlock()

	if !ok {
		return map[string]interface{}{
			"success": false,
			"error":   "session not found",
		}
	}

	if err := session.HandleAnswer(answer); err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	return map[string]interface{}{"success": true}
}

// HandleICECandidate handles ICE candidate from frontend.
func HandleICECandidate(sessionID string, candidate ICECandidate) map[string]interface{} {
	sessionsMu.RLock()
	session, ok := activeSessions[sessionID]
	sessionsMu.RUnlock()

	if !ok {
		return map[string]interface{}{
			"success": false,
			"error":   "session not found",
		}
	}

	if err := session.HandleICECandidate(candidate); err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	return map[string]interface{}{"success": true}
}

// HandleRemoteControl handles remote control input from frontend.
func HandleRemoteControl(sessionID string, event InputEvent) map[string]interface{} {
	sessionsMu.RLock()
	session, ok := activeSessions[sessionID]
	sessionsMu.RUnlock()

	if !ok {
		return map[string]interface{}{
			"success": false,
			"error":   "session not found",
		}
	}

	session.handleInput(event)

	return map[string]interface{}{"success": true}
}

// SetQuality sets the video quality for a session.
func SetQuality(sessionID string, quality string) map[string]interface{} {
	sessionsMu.RLock()
	session, ok := activeSessions[sessionID]
	sessionsMu.RUnlock()

	if !ok {
		return map[string]interface{}{
			"success": false,
			"error":   "session not found",
		}
	}

	session.SetQuality(quality)

	return map[string]interface{}{"success": true}
}

// SetMonitor sets the active monitor for a session.
func SetMonitor(sessionID string, monitorID int) map[string]interface{} {
	sessionsMu.RLock()
	session, ok := activeSessions[sessionID]
	sessionsMu.RUnlock()

	if !ok {
		return map[string]interface{}{
			"success": false,
			"error":   "session not found",
		}
	}

	session.SetMonitor(monitorID)

	return map[string]interface{}{"success": true}
}

// GetSessionMonitors returns monitors for a specific session.
func GetSessionMonitors(sessionID string) map[string]interface{} {
	sessionsMu.RLock()
	session, ok := activeSessions[sessionID]
	sessionsMu.RUnlock()

	if !ok {
		return map[string]interface{}{
			"success": false,
			"error":   "session not found",
		}
	}

	return map[string]interface{}{
		"success":  true,
		"monitors": session.GetMonitors(),
	}
}

// StopAllSessions stops all active remote desktop sessions.
func StopAllSessions() {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	for id, session := range activeSessions {
		session.Stop()
		delete(activeSessions, id)
	}
}

// GetActiveSessions returns the number of active sessions.
func GetActiveSessions() int {
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	return len(activeSessions)
}
