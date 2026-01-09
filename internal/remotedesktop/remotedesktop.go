//go:build cgo

// Package remotedesktop provides WebSocket-based screen sharing and remote control.
package remotedesktop

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"
)

var (
	activeSessions = make(map[string]*Session)
	sessionsMu     sync.RWMutex
)

// Session represents an active remote desktop session.
type Session struct {
	sessionID       string
	sendCallback    SendCallback
	logger          *slog.Logger
	capture         *ScreenCapture
	input           *InputController
	encoder         *JPEGEncoder
	selectedMonitor int
	quality         string
	running         bool
	stopCh          chan struct{}
	mu              sync.RWMutex
}

// HasDisplayServer checks if a display server is available.
func HasDisplayServer() bool {
	switch runtime.GOOS {
	case "darwin", "windows":
		return true

	case "linux":
		if os.Getenv("WAYLAND_DISPLAY") != "" {
			return true
		}
		display := os.Getenv("DISPLAY")
		if display != "" {
			cmd := exec.Command("xset", "q")
			if err := cmd.Run(); err == nil {
				return true
			}
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

	screenRecordingOK := true
	accessibilityOK := true
	if runtime.GOOS == "darwin" {
		screenRecordingOK = CheckScreenRecordingPermission()
		accessibilityOK = CheckAccessibilityPermission()
	}

	screenCaptureOK := displayAvailable && screenRecordingOK
	inputControlOK := displayAvailable && accessibilityOK

	return map[string]bool{
		"screen_capture":        screenCaptureOK,
		"input_control":         inputControlOK,
		"clipboard":             displayAvailable,
		"display_server":        displayAvailable,
		"screen_recording_perm": screenRecordingOK,
		"accessibility_perm":    accessibilityOK,
		"all_required":          screenCaptureOK,
		"full_control":          screenCaptureOK && inputControlOK,
		"cgo_enabled":           true,
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
	if logger == nil {
		logger = slog.Default()
	}

	if !HasDisplayServer() {
		return &StartResult{
			Success: false,
			Error:   "No display server (X11/Wayland) available. Remote desktop requires a graphical environment.",
		}
	}

	if runtime.GOOS == "darwin" {
		if !CheckScreenRecordingPermission() {
			logger.Warn("macOS screen recording permission not granted")
			return &StartResult{
				Success: false,
				Error:   "Screen Recording permission required. Please grant permission in System Settings > Privacy & Security > Screen Recording, then restart the agent.",
			}
		}
		logger.Debug("macOS screen recording permission granted")
	}

	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	if existing, ok := activeSessions[sessionID]; ok {
		existing.Stop()
		delete(activeSessions, sessionID)
	}

	session, err := newSession(sessionID, sendCallback, logger)
	if err != nil {
		return &StartResult{
			Success: false,
			Error:   fmt.Sprintf("creating session: %v", err),
		}
	}

	monitors := session.capture.GetMonitors()

	if err := session.Start(); err != nil {
		session.Stop()
		return &StartResult{
			Success: false,
			Error:   err.Error(),
		}
	}

	activeSessions[sessionID] = session

	return &StartResult{
		Success:  true,
		Monitors: monitors,
	}
}

// newSession creates a new session instance.
func newSession(sessionID string, sendCallback SendCallback, logger *slog.Logger) (*Session, error) {
	capture, err := NewScreenCapture()
	if err != nil {
		return nil, fmt.Errorf("creating screen capture: %w", err)
	}

	monitors := capture.GetMonitors()
	selectedMonitor := 1
	for _, m := range monitors {
		if m.Primary {
			selectedMonitor = m.ID
			break
		}
	}

	input := NewInputController(monitors, logger)
	// Configure input controller to use helper if screen capture is using helper (Windows Session 0)
	capture.ConfigureInputController(input)

	settings := QualityPresets["balanced"]
	encoder := NewJPEGEncoder(settings.JPEGQuality)

	return &Session{
		sessionID:       sessionID,
		sendCallback:    sendCallback,
		logger:          logger,
		capture:         capture,
		input:           input,
		encoder:         encoder,
		selectedMonitor: selectedMonitor,
		quality:         "balanced",
		stopCh:          make(chan struct{}),
	}, nil
}

// Start begins the capture and streaming loop.
func (s *Session) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.mu.Unlock()

	go s.captureLoop()

	s.logger.Info("remote desktop session started", "session_id", s.sessionID)
	return nil
}

// captureLoop continuously captures and sends frames via WebSocket.
func (s *Session) captureLoop() {
	s.mu.RLock()
	settings := QualityPresets[s.quality]
	s.mu.RUnlock()

	ticker := time.NewTicker(time.Second / time.Duration(settings.FPS))
	defer ticker.Stop()

	frameCount := 0
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.mu.RLock()
			if !s.running {
				s.mu.RUnlock()
				return
			}
			monitorID := s.selectedMonitor
			quality := s.quality
			s.mu.RUnlock()

			currentSettings := QualityPresets[quality]
			if currentSettings.FPS != settings.FPS {
				settings = currentSettings
				ticker.Reset(time.Second / time.Duration(settings.FPS))
			}

			frame, err := s.capture.CaptureFrame(monitorID)
			if err != nil {
				s.logger.Error("capturing frame", "error", err)
				continue
			}

			if currentSettings.Scale < 1.0 {
				frame = ScaleImage(frame, currentSettings.Scale)
			}

			jpegData, err := s.encoder.Encode(frame)
			if err != nil {
				s.logger.Error("encoding frame", "error", err)
				continue
			}

			msg, _ := json.Marshal(map[string]interface{}{
				"action": "remote_desktop_frame",
				"frame":  base64.StdEncoding.EncodeToString(jpegData),
				"width":  frame.Bounds().Dx(),
				"height": frame.Bounds().Dy(),
			})

			if err := s.sendCallback(msg); err != nil {
				if frameCount < 10 || frameCount%100 == 0 {
					s.logger.Info("frame send error", "error", err, "frame", frameCount)
				}
			}

			frameCount++
			if frameCount <= 3 || frameCount%500 == 0 {
				s.logger.Info("frame sent", "frame", frameCount, "size", len(jpegData),
					"width", frame.Bounds().Dx(), "height", frame.Bounds().Dy())
			}
		}
	}
}

// Stop terminates the session.
func (s *Session) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	s.running = false
	close(s.stopCh)

	if s.capture != nil {
		s.capture.Close()
		s.capture = nil
	}

	if s.encoder != nil {
		s.encoder.Close()
		s.encoder = nil
	}

	s.logger.Info("remote desktop session stopped", "session_id", s.sessionID)
}

// handleInput processes input events.
func (s *Session) handleInput(event InputEvent) {
	s.mu.RLock()
	monitorID := s.selectedMonitor
	s.mu.RUnlock()

	s.logger.Info("handling input event",
		"type", event.Type,
		"action", event.Action,
		"x", event.X,
		"y", event.Y,
		"button", event.Button,
		"key", event.Key,
		"monitor", monitorID,
	)

	switch event.Type {
	case "mouse", "mouse_move":
		if event.Type == "mouse_move" {
			event.Action = "move"
		}
		s.input.HandleMouseEvent(event, monitorID)

	case "mouse_down":
		event.Action = "down"
		s.input.HandleMouseEvent(event, monitorID)

	case "mouse_up":
		event.Action = "up"
		s.input.HandleMouseEvent(event, monitorID)

	case "scroll":
		event.Action = "scroll"
		s.input.HandleMouseEvent(event, monitorID)

	case "keyboard", "key_down":
		if event.Type == "key_down" {
			event.Action = "down"
		}
		s.input.HandleKeyboardEvent(event)

	case "key_up":
		event.Action = "up"
		s.input.HandleKeyboardEvent(event)

	case "quality":
		s.SetQuality(event.Quality)

	case "monitor":
		s.SetMonitor(event.MonitorID)

	default:
		s.logger.Debug("unhandled input event type", "type", event.Type)
	}
}

// SetQuality changes the video quality preset.
func (s *Session) SetQuality(quality string) {
	settings, ok := QualityPresets[quality]
	if !ok {
		s.logger.Warn("invalid quality preset", "quality", quality)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.quality = quality
	if s.encoder != nil {
		s.encoder.SetQuality(settings.JPEGQuality)
	}

	s.logger.Info("quality changed", "quality", quality, "fps", settings.FPS, "jpeg_quality", settings.JPEGQuality)
}

// SetMonitor switches to a different monitor.
func (s *Session) SetMonitor(monitorID int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	monitors := s.capture.GetMonitors()
	valid := false
	for _, m := range monitors {
		if m.ID == monitorID {
			valid = true
			break
		}
	}

	if !valid {
		s.logger.Warn("invalid monitor ID", "monitor_id", monitorID)
		return
	}

	s.selectedMonitor = monitorID
	s.logger.Info("monitor changed", "monitor_id", monitorID)
}

// GetMonitors returns the list of available monitors.
func (s *Session) GetMonitors() []Monitor {
	return s.capture.GetMonitors()
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
