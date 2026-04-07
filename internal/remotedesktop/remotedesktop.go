//go:build cgo

// Package remotedesktop provides WebSocket-based screen sharing and remote control.
package remotedesktop

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	activeSessions = make(map[string]*Session)
	sessionsMu     sync.RWMutex
)

// Session represents an active remote desktop session.
type Session struct {
	sessionID          string
	sendCallback       SendCallback
	sendBinaryCallback SendBinaryCallback
	logger             *slog.Logger
	sessionManager  *SessionManager
	capture         *ScreenCapture
	input           *InputController
	encoder         *JPEGEncoder
	selectedMonitor int
	quality         string
	viewportWidth   int
	viewportHeight  int
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
		logger := slog.Default()

		// Check environment variables first (when run interactively)
		if os.Getenv("WAYLAND_DISPLAY") != "" {
			logger.Info("display server found via WAYLAND_DISPLAY", "value", os.Getenv("WAYLAND_DISPLAY"))
			return true
		}
		if os.Getenv("DISPLAY") != "" {
			logger.Info("display server found via DISPLAY", "value", os.Getenv("DISPLAY"))
			return true
		}

		// When running as a service, try to find an active graphical session
		logger.Info("no DISPLAY env var, searching for active graphical session")
		display, xauth := findActiveLinuxDisplay()
		if display != "" {
			logger.Info("found active display", "display", display, "xauthority", xauth)
			os.Setenv("DISPLAY", display)
			if xauth != "" {
				os.Setenv("XAUTHORITY", xauth)
			}
			return true
		}
		logger.Warn("no display server found")
		return false

	default:
		return false
	}
}

// findActiveLinuxDisplay attempts to find an active X11 display on Linux.
// This is needed when running as a systemd service without access to user environment.
func findActiveLinuxDisplay() (display, xauthority string) {
	// Use loginctl to find active graphical sessions first (most reliable)
	cmd := exec.Command("loginctl", "list-sessions", "--no-legend")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) < 1 {
				continue
			}
			sessionID := fields[0]

			// Get session type
			typeCmd := exec.Command("loginctl", "show-session", sessionID, "-p", "Type", "--value")
			typeOutput, err := typeCmd.Output()
			if err != nil {
				continue
			}
			sessionType := strings.TrimSpace(string(typeOutput))

			// Only graphical sessions (x11 or wayland)
			if sessionType != "x11" && sessionType != "wayland" {
				continue
			}

			// Get user for Xauthority
			userCmd := exec.Command("loginctl", "show-session", sessionID, "-p", "Name", "--value")
			userOutput, err := userCmd.Output()
			if err != nil {
				continue
			}
			username := strings.TrimSpace(string(userOutput))
			uid := getUID(username)

			// For Wayland sessions, XWayland uses a special auth file
			// Try to find the Xauthority in order of preference
			xauthPaths := []string{
				// XWayland on GNOME/Mutter (Wayland)
				"/run/user/" + uid + "/.mutter-Xwaylandauth.*",
				// GDM Xauthority
				"/run/user/" + uid + "/gdm/Xauthority",
				// Standard X11
				"/home/" + username + "/.Xauthority",
			}

			if username == "root" {
				xauthPaths = append(xauthPaths, "/root/.Xauthority")
			}

			var foundXauth string
			for _, pattern := range xauthPaths {
				if strings.Contains(pattern, "*") {
					matches, _ := filepath.Glob(pattern)
					if len(matches) > 0 {
						foundXauth = matches[0]
						break
					}
				} else if _, err := os.Stat(pattern); err == nil {
					foundXauth = pattern
					break
				}
			}

			// For Wayland, use :0 or :1 (XWayland display)
			// Check which X socket exists and is owned by the user
			for _, xDisplay := range []string{":0", ":1"} {
				socketPath := "/tmp/.X11-unix/X" + strings.TrimPrefix(xDisplay, ":")
				if info, err := os.Stat(socketPath); err == nil {
					// Check if socket exists (we'll use Xauthority for auth)
					_ = info
					if foundXauth != "" {
						return xDisplay, foundXauth
					}
				}
			}

			// Get Display from session (for pure X11)
			displayCmd := exec.Command("loginctl", "show-session", sessionID, "-p", "Display", "--value")
			displayOutput, err := displayCmd.Output()
			if err == nil {
				display = strings.TrimSpace(string(displayOutput))
				if display != "" && foundXauth != "" {
					return display, foundXauth
				}
			}
		}
	}

	// Fallback: Check for X11 sockets directly
	for _, xDisplay := range []string{":0", ":1"} {
		socketPath := "/tmp/.X11-unix/X" + strings.TrimPrefix(xDisplay, ":")
		if _, err := os.Stat(socketPath); err == nil {
			xauth := findXauthority()
			return xDisplay, xauth
		}
	}

	return "", ""
}

// findXauthority finds the Xauthority file for the current active session.
func findXauthority() string {
	// Check common locations - order matters (most specific first)
	paths := []string{
		// XWayland on GNOME/Mutter (Wayland sessions)
		"/run/user/*/.mutter-Xwaylandauth.*",
		// GDM managed Xauthority
		"/run/user/*/gdm/Xauthority",
		// Standard user Xauthority
		"/home/*/.Xauthority",
		"/root/.Xauthority",
	}

	for _, pattern := range paths {
		matches, _ := filepath.Glob(pattern)
		for _, path := range matches {
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}
	return ""
}

// getUID returns the UID for a username.
func getUID(username string) string {
	cmd := exec.Command("id", "-u", username)
	output, err := cmd.Output()
	if err != nil {
		return "1000" // Default fallback
	}
	return strings.TrimSpace(string(output))
}

// IsWaylandSession checks if the current session is using Wayland.
// Wayland doesn't support screen capture via XShm, only via PipeWire portal.
func IsWaylandSession() bool {
	if runtime.GOOS != "linux" {
		return false
	}

	// Check environment variable
	if os.Getenv("XDG_SESSION_TYPE") == "wayland" {
		return true
	}
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		return true
	}

	// Check via loginctl for the active session
	cmd := exec.Command("loginctl", "list-sessions", "--no-legend")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		sessionID := fields[0]

		typeCmd := exec.Command("loginctl", "show-session", sessionID, "-p", "Type", "--value")
		typeOutput, err := typeCmd.Output()
		if err != nil {
			continue
		}
		sessionType := strings.TrimSpace(string(typeOutput))
		if sessionType == "wayland" {
			return true
		}
	}

	return false
}

// CheckDependencies returns availability of remote desktop features.
func CheckDependencies() map[string]bool {
	displayAvailable := HasDisplayServer()
	waylandSession := IsWaylandSession()

	screenRecordingOK := true
	accessibilityOK := true
	if runtime.GOOS == "darwin" {
		screenRecordingOK = CheckScreenRecordingPermission()
		accessibilityOK = CheckAccessibilityPermission()
	}

	// On Wayland, screen capture via XShm doesn't work (returns black frames)
	// Native Wayland screen capture requires PipeWire portal (not yet implemented)
	screenCaptureOK := displayAvailable && screenRecordingOK && !waylandSession
	inputControlOK := displayAvailable && accessibilityOK

	return map[string]bool{
		"screen_capture":        screenCaptureOK,
		"input_control":         inputControlOK,
		"clipboard":             displayAvailable,
		"display_server":        displayAvailable,
		"screen_recording_perm": screenRecordingOK,
		"accessibility_perm":    accessibilityOK,
		"wayland_session":       waylandSession,
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
// viewportWidth and viewportHeight specify the client's viewport size for optimal scaling.
// If 0, the native resolution is used.
func StartSession(sessionID string, sendCallback SendCallback, sendBinaryCallback SendBinaryCallback, logger *slog.Logger, viewportWidth, viewportHeight int) *StartResult {
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

	sm := NewSessionManager(logger)
	if err := sm.StartSession(); err != nil {
		return &StartResult{Success: false, Error: fmt.Sprintf("session manager: %v", err)}
	}

	session, err := newSession(sessionID, sendCallback, sendBinaryCallback, logger, viewportWidth, viewportHeight)
	if err != nil {
		sm.StopSession()
		return &StartResult{
			Success: false,
			Error:   fmt.Sprintf("creating session: %v", err),
		}
	}
	session.sessionManager = sm

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
func newSession(sessionID string, sendCallback SendCallback, sendBinaryCallback SendBinaryCallback, logger *slog.Logger, viewportWidth, viewportHeight int) (*Session, error) {
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

	logger.Info("creating session with viewport",
		"viewport_width", viewportWidth,
		"viewport_height", viewportHeight,
	)

	return &Session{
		sessionID:          sessionID,
		sendCallback:       sendCallback,
		sendBinaryCallback: sendBinaryCallback,
		logger:             logger,
		capture:         capture,
		input:           input,
		encoder:         encoder,
		selectedMonitor: selectedMonitor,
		quality:         "balanced",
		viewportWidth:   viewportWidth,
		viewportHeight:  viewportHeight,
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

	// On Windows with helper, use streaming mode for continuous frames
	if s.capture.IsUsingHelper() {
		s.streamingLoop(settings)
		return
	}

	// Direct capture mode (all platforms without helper)
	s.tickerLoop(settings)
}

// streamingLoop reads continuous frames from the helper pipe (Windows streaming mode).
func (s *Session) streamingLoop(settings QualitySettings) {
	err := s.capture.StartStreaming(s.selectedMonitor, settings.JPEGQuality, settings.FPS)
	if err != nil {
		s.logger.Error("failed to start streaming", "error", err)
		// Fall back to regular capture loop
		s.tickerLoop(settings)
		return
	}
	defer s.capture.StopStreaming()
	s.logger.Info("streaming mode started", "fps", settings.FPS, "quality", settings.JPEGQuality)

	frameCount := 0
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		jpegData, w, h, err := s.capture.ReadStreamFrame()
		if err != nil {
			s.logger.Error("stream frame error", "error", err)
			return
		}

		binaryFrame := BuildBinaryFrame(w, h, jpegData)
		if err := s.sendBinaryCallback(binaryFrame); err != nil {
			if frameCount < 10 || frameCount%100 == 0 {
				s.logger.Warn("frame send error", "error", err, "frame", frameCount)
			}
		}
		frameCount++
		if frameCount <= 3 || frameCount%500 == 0 {
			s.logger.Info("streaming frame", "frame", frameCount, "size", len(jpegData), "resolution", fmt.Sprintf("%dx%d", w, h))
		}
	}
}

// tickerLoop captures frames on a timer (used for direct capture or as fallback).
func (s *Session) tickerLoop(settings QualitySettings) {
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
			viewportW := s.viewportWidth
			viewportH := s.viewportHeight
			s.mu.RUnlock()

			currentSettings := QualityPresets[quality]
			if currentSettings.FPS != settings.FPS {
				settings = currentSettings
				ticker.Reset(time.Second / time.Duration(settings.FPS))
			}

			// Try to get pre-encoded JPEG directly (avoids decode+re-encode in helper mode)
			var jpegData []byte
			var frameWidth, frameHeight int

			preEncoded, w, h, err := s.capture.CaptureFrameJPEG(monitorID)
			if err != nil {
				s.logger.Error("capturing frame", "error", err)
				continue
			}

			if preEncoded != nil {
				// Helper mode: JPEG bytes already available, skip encoding
				jpegData = preEncoded
				frameWidth = w
				frameHeight = h
			} else {
				// Direct mode: capture raw frame and encode to JPEG
				frame, err := s.capture.CaptureFrame(monitorID)
				if err != nil {
					s.logger.Error("capturing frame", "error", err)
					continue
				}

				// Calculate scale based on viewport size instead of fixed preset
				scale := s.calculateScale(frame.Bounds().Dx(), frame.Bounds().Dy(), viewportW, viewportH)
				if scale < 1.0 {
					frame = ScaleImage(frame, scale)
				}

				jpegData, err = s.encoder.Encode(frame)
				if err != nil {
					s.logger.Error("encoding frame", "error", err)
					continue
				}
				frameWidth = frame.Bounds().Dx()
				frameHeight = frame.Bounds().Dy()
			}

			binaryFrame := BuildBinaryFrame(frameWidth, frameHeight, jpegData)
			if err := s.sendBinaryCallback(binaryFrame); err != nil {
				if frameCount < 10 || frameCount%100 == 0 {
					s.logger.Info("binary frame send error", "error", err, "frame", frameCount)
				}
			}

			frameCount++
			if frameCount <= 3 || frameCount%500 == 0 {
				s.logger.Info("frame sent", "frame", frameCount, "size", len(jpegData),
					"width", frameWidth, "height", frameHeight,
					"viewport", fmt.Sprintf("%dx%d", viewportW, viewportH))
			}
		}
	}
}

// calculateScale determines the optimal scale factor based on viewport size.
// This ensures we never send more pixels than the client can display.
func (s *Session) calculateScale(srcWidth, srcHeight, viewportWidth, viewportHeight int) float64 {
	// If no viewport specified, use preset scale
	if viewportWidth <= 0 || viewportHeight <= 0 {
		settings := QualityPresets[s.quality]
		return settings.Scale
	}

	// Calculate scale to fit viewport while maintaining aspect ratio
	scaleX := float64(viewportWidth) / float64(srcWidth)
	scaleY := float64(viewportHeight) / float64(srcHeight)
	scale := scaleX
	if scaleY < scaleX {
		scale = scaleY
	}

	// Never upscale - only downscale if needed
	if scale > 1.0 {
		scale = 1.0
	}

	// Minimum scale of 0.25 to prevent tiny images
	if scale < 0.25 {
		scale = 0.25
	}

	return scale
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

	if s.sessionManager != nil {
		s.sessionManager.StopSession()
	}

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

// UpdateStreamingQuality updates quality and signals the streaming loop to apply changes immediately.
// On Windows with helper mode, this stops current streaming so it restarts with new parameters.
// On other platforms, the capture loop picks up the new quality on the next tick.
func (s *Session) UpdateStreamingQuality(quality string) {
	s.SetQuality(quality)

	// For immediate effect on Windows helper mode, stop current streaming so it restarts
	s.mu.RLock()
	capture := s.capture
	s.mu.RUnlock()

	if capture != nil && capture.IsUsingHelper() {
		capture.StopStreaming()
	}
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

// SetViewportSize updates the client viewport size for optimal scaling.
func (s *Session) SetViewportSize(width, height int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.viewportWidth = width
	s.viewportHeight = height
	s.logger.Info("viewport size changed", "width", width, "height", height)
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

// SetViewportSize sets the client viewport size for optimal scaling.
func SetViewportSize(sessionID string, width, height int) map[string]interface{} {
	sessionsMu.RLock()
	session, ok := activeSessions[sessionID]
	sessionsMu.RUnlock()

	if !ok {
		return map[string]interface{}{
			"success": false,
			"error":   "session not found",
		}
	}

	session.SetViewportSize(width, height)

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

// GetSession returns an active session by ID, or nil if not found.
func GetSession(sessionID string) *Session {
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	return activeSessions[sessionID]
}

// GetActiveSessions returns the number of active sessions.
func GetActiveSessions() int {
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	return len(activeSessions)
}
