// SlimRMM Desktop Helper
// This helper runs in the user's interactive session to capture screen
// and inject input when the main agent service requests remote desktop.
//
//go:build windows

package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/kbinani/screenshot"
	"github.com/lxn/win"
	"github.com/slimrmm/slimrmm-agent/internal/winget"
	"golang.org/x/sys/windows"
)

const (
	pipeName       = `\\.\pipe\slimrmm-helper`
	maxMessageSize = 10 * 1024 * 1024 // 10MB max for frame data
)

// Windows INPUT structure for SendInput API
const (
	INPUT_MOUSE    = 0
	INPUT_KEYBOARD = 1
)

// Keyboard input flags (not all defined in lxn/win)
const (
	KEYEVENTF_UNICODE = 0x0004 // Input is Unicode character, not VK code
)

// Windows MOUSEINPUT structure
type MOUSEINPUT struct {
	Dx          int32
	Dy          int32
	MouseData   uint32
	DwFlags     uint32
	Time        uint32
	DwExtraInfo uintptr
}

// Windows KEYBDINPUT structure
type KEYBDINPUT struct {
	WVk         uint16
	WScan       uint16
	DwFlags     uint32
	Time        uint32
	DwExtraInfo uintptr
}

// Windows INPUT structure (union)
type INPUT struct {
	Type uint32
	// Padding on 64-bit systems
	_padding uint32
	// Union of MOUSEINPUT, KEYBDINPUT, HARDWAREINPUT
	Mi MOUSEINPUT
}

// INPUT structure for keyboard
type INPUT_KBD struct {
	Type uint32
	_padding uint32
	Ki KEYBDINPUT
	_pad [8]byte // Ensure same size as INPUT
}

var (
	user32            = windows.NewLazySystemDLL("user32.dll")
	procSendInput     = user32.NewProc("SendInput")
)

// Message types
const (
	MsgTypeCapture             = "capture"
	MsgTypeFrame               = "frame"
	MsgTypeInput               = "input"
	MsgTypeMonitors            = "monitors"
	MsgTypeMonitorList         = "monitor_list"
	MsgTypePing                = "ping"
	MsgTypePong                = "pong"
	MsgTypeError               = "error"
	MsgTypeQuit                = "quit"
	MsgTypeWingetScan          = "winget_scan"
	MsgTypeWingetResult        = "winget_result"
	MsgTypeWingetUpgrade       = "winget_upgrade"
	MsgTypeWingetUpgradeResult = "winget_upgrade_result"
)

// Message is the IPC message format
type Message struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// CaptureRequest requests a screen capture
type CaptureRequest struct {
	MonitorID int     `json:"monitor_id"`
	Quality   int     `json:"quality"` // JPEG quality 1-100
	Scale     float64 `json:"scale"`   // Scale factor 0.1-1.0
}

// FrameResponse contains captured frame data
type FrameResponse struct {
	Width    int    `json:"width"`
	Height   int    `json:"height"`
	Format   string `json:"format"` // "jpeg" or "raw"
	DataSize int    `json:"data_size"`
	// Actual frame data follows the JSON message
}

// InputEvent represents mouse/keyboard input
type InputEvent struct {
	Type   string `json:"type"` // "mousemove", "mousedown", "mouseup", "keydown", "keyup", "scroll"
	X      int    `json:"x,omitempty"`
	Y      int    `json:"y,omitempty"`
	Button int    `json:"button,omitempty"` // 0=left, 1=middle, 2=right
	Key    string `json:"key,omitempty"`    // Character or key name (e.g., "a", "Shift", "Enter")
	Code   string `json:"code,omitempty"`   // Physical key code (e.g., "KeyA", "ShiftLeft", "Enter")
	DeltaX int    `json:"delta_x,omitempty"`
	DeltaY int    `json:"delta_y,omitempty"`
}

// Monitor information
type Monitor struct {
	ID      int  `json:"id"`
	Left    int  `json:"left"`
	Top     int  `json:"top"`
	Width   int  `json:"width"`
	Height  int  `json:"height"`
	Primary bool `json:"primary"`
}

// WingetUpdate represents an available winget update
type WingetUpdate struct {
	Name       string `json:"name"`
	ID         string `json:"id"`
	Version    string `json:"version"`
	Available  string `json:"available"`
	Source     string `json:"source"`
}

// WingetScanResult contains the winget scan results
type WingetScanResult struct {
	Updates   []WingetUpdate `json:"updates"`
	Error     string         `json:"error,omitempty"`
	RawOutput string         `json:"raw_output,omitempty"`
}

// WingetScanRequest contains the winget scan parameters
type WingetScanRequest struct {
	WingetPath string `json:"winget_path,omitempty"`
}

// WingetUpgradeRequest contains the winget upgrade parameters
type WingetUpgradeRequest struct {
	WingetPath string `json:"winget_path,omitempty"`
	PackageID  string `json:"package_id"`
}

// WingetUpgradeResult contains the winget upgrade result
type WingetUpgradeResult struct {
	Success   bool   `json:"success"`
	Output    string `json:"output"`
	Error     string `json:"error,omitempty"`
	ExitCode  int    `json:"exit_code"`
	WingetLog string `json:"winget_log,omitempty"`
}

func main() {
	// Parse flags
	var sessionID string
	var updateMode bool
	var updateSrc string
	var updateDst string
	var updatePID int
	var serviceName string

	flag.StringVar(&sessionID, "session", "", "Session ID for the pipe name")
	flag.BoolVar(&updateMode, "update", false, "Run in update mode to replace agent binary")
	flag.StringVar(&updateSrc, "src", "", "Source path for new binary (update mode)")
	flag.StringVar(&updateDst, "dst", "", "Destination path for binary (update mode)")
	flag.IntVar(&updatePID, "pid", 0, "PID of agent process to wait for (update mode)")
	flag.StringVar(&serviceName, "service", "SlimRMMAgent", "Service name (update mode)")
	flag.Parse()

	// Handle update mode
	if updateMode {
		if err := runUpdateMode(updateSrc, updateDst, updatePID, serviceName); err != nil {
			log.Fatalf("Update failed: %v", err)
		}
		return
	}

	// Determine pipe name
	pName := pipeName
	if sessionID != "" {
		pName = fmt.Sprintf("%s-%s", pipeName, sessionID)
	}

	log.Printf("SlimRMM Helper starting, pipe: %s", pName)

	// Create named pipe
	pipe, err := createPipe(pName)
	if err != nil {
		log.Fatalf("Failed to create pipe: %v", err)
	}
	defer windows.CloseHandle(pipe)

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Wait for client connection
	log.Println("Waiting for client connection...")
	if err := connectPipe(pipe); err != nil {
		log.Fatalf("Failed to connect pipe: %v", err)
	}
	log.Println("Client connected")

	// Main message loop
	for {
		select {
		case <-sigCh:
			log.Println("Shutting down...")
			return
		default:
		}

		msg, err := readMessage(pipe)
		if err != nil {
			log.Printf("Error reading message: %v", err)
			// Try to reconnect
			if err := connectPipe(pipe); err != nil {
				log.Printf("Reconnection failed: %v", err)
				time.Sleep(time.Second)
			}
			continue
		}

		response, frameData := handleMessage(msg)
		if response != nil {
			if err := writeMessage(pipe, response, frameData); err != nil {
				log.Printf("Error writing response: %v", err)
			}
		}

		if msg.Type == MsgTypeQuit {
			log.Println("Quit requested, shutting down...")
			return
		}
	}
}

func createPipe(name string) (windows.Handle, error) {
	pipePath, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}

	pipe, err := windows.CreateNamedPipe(
		pipePath,
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_WAIT,
		1,                  // Max instances
		maxMessageSize,     // Out buffer size
		maxMessageSize,     // In buffer size
		0,                  // Default timeout
		nil,                // Security attributes
	)
	if err != nil {
		return 0, fmt.Errorf("CreateNamedPipe: %w", err)
	}

	return pipe, nil
}

func connectPipe(pipe windows.Handle) error {
	// ConnectNamedPipe blocks until a client connects
	err := windows.ConnectNamedPipe(pipe, nil)
	if err != nil && err != windows.ERROR_PIPE_CONNECTED {
		return err
	}
	return nil
}

func readMessage(pipe windows.Handle) (*Message, error) {
	// In message mode, we must read the entire message at once
	buf := make([]byte, 4096) // Messages from client are small
	totalRead := 0

	for {
		var n uint32
		err := windows.ReadFile(pipe, buf[totalRead:], &n, nil)
		totalRead += int(n)

		if err == nil {
			break
		}

		if err == windows.ERROR_MORE_DATA {
			// Message larger than buffer, grow and continue
			if totalRead >= int(maxMessageSize) {
				return nil, fmt.Errorf("message too large: %d", totalRead)
			}
			newBuf := make([]byte, len(buf)*2)
			copy(newBuf, buf[:totalRead])
			buf = newBuf
			continue
		}

		return nil, err
	}

	if totalRead < 4 {
		return nil, fmt.Errorf("message too short: %d bytes", totalRead)
	}

	// Parse length prefix and validate
	msgLen := binary.LittleEndian.Uint32(buf[:4])
	if int(msgLen) != totalRead-4 {
		return nil, fmt.Errorf("length mismatch: header says %d, got %d", msgLen, totalRead-4)
	}

	var msg Message
	if err := json.Unmarshal(buf[4:totalRead], &msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

func writeMessage(pipe windows.Handle, msg *Message, extraData []byte) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// Build complete message: length (4 bytes) + JSON + extra data
	totalLen := len(data) + len(extraData)
	fullMsg := make([]byte, 4+totalLen)
	binary.LittleEndian.PutUint32(fullMsg[:4], uint32(totalLen))
	copy(fullMsg[4:], data)
	if len(extraData) > 0 {
		copy(fullMsg[4+len(data):], extraData)
	}

	// Write everything in a single call (required for message mode pipes)
	var bytesWritten uint32
	return windows.WriteFile(pipe, fullMsg, &bytesWritten, nil)
}

func handleMessage(msg *Message) (*Message, []byte) {
	switch msg.Type {
	case MsgTypePing:
		return &Message{Type: MsgTypePong}, nil

	case MsgTypeMonitors:
		monitors := getMonitors()
		payload, _ := json.Marshal(monitors)
		return &Message{Type: MsgTypeMonitorList, Payload: payload}, nil

	case MsgTypeCapture:
		var req CaptureRequest
		if err := json.Unmarshal(msg.Payload, &req); err != nil {
			errPayload, _ := json.Marshal(map[string]string{"error": err.Error()})
			return &Message{Type: MsgTypeError, Payload: errPayload}, nil
		}
		return captureScreen(req)

	case MsgTypeInput:
		var input InputEvent
		if err := json.Unmarshal(msg.Payload, &input); err != nil {
			errPayload, _ := json.Marshal(map[string]string{"error": err.Error()})
			return &Message{Type: MsgTypeError, Payload: errPayload}, nil
		}
		handleInput(input)
		return nil, nil // No response for input events

	case MsgTypeWingetScan:
		var req WingetScanRequest
		if msg.Payload != nil {
			json.Unmarshal(msg.Payload, &req)
		}
		return scanWingetUpdates(req.WingetPath)

	case MsgTypeWingetUpgrade:
		var req WingetUpgradeRequest
		if err := json.Unmarshal(msg.Payload, &req); err != nil {
			errPayload, _ := json.Marshal(map[string]string{"error": err.Error()})
			return &Message{Type: MsgTypeError, Payload: errPayload}, nil
		}
		return upgradeWingetPackage(req.WingetPath, req.PackageID)

	case MsgTypeQuit:
		return nil, nil

	default:
		errPayload, _ := json.Marshal(map[string]string{"error": "unknown message type"})
		return &Message{Type: MsgTypeError, Payload: errPayload}, nil
	}
}

func getMonitors() []Monitor {
	n := screenshot.NumActiveDisplays()
	monitors := make([]Monitor, 0, n)

	for i := 0; i < n; i++ {
		bounds := screenshot.GetDisplayBounds(i)
		monitors = append(monitors, Monitor{
			ID:      i + 1,
			Left:    bounds.Min.X,
			Top:     bounds.Min.Y,
			Width:   bounds.Dx(),
			Height:  bounds.Dy(),
			Primary: i == 0,
		})
	}

	return monitors
}

func captureScreen(req CaptureRequest) (*Message, []byte) {
	// Validate monitor ID
	n := screenshot.NumActiveDisplays()
	idx := req.MonitorID - 1
	if idx < 0 || idx >= n {
		errPayload, _ := json.Marshal(map[string]string{"error": "invalid monitor ID"})
		return &Message{Type: MsgTypeError, Payload: errPayload}, nil
	}

	// Capture screen
	bounds := screenshot.GetDisplayBounds(idx)
	img, err := screenshot.CaptureRect(bounds)
	if err != nil {
		errPayload, _ := json.Marshal(map[string]string{"error": err.Error()})
		return &Message{Type: MsgTypeError, Payload: errPayload}, nil
	}

	// Scale if needed
	if req.Scale > 0 && req.Scale < 1.0 {
		img = scaleImage(img, req.Scale)
	}

	// Encode as JPEG
	quality := req.Quality
	if quality <= 0 || quality > 100 {
		quality = 70
	}

	var buf []byte
	writer := &sliceWriter{buf: &buf}
	if err := jpeg.Encode(writer, img, &jpeg.Options{Quality: quality}); err != nil {
		errPayload, _ := json.Marshal(map[string]string{"error": err.Error()})
		return &Message{Type: MsgTypeError, Payload: errPayload}, nil
	}

	resp := FrameResponse{
		Width:    img.Bounds().Dx(),
		Height:   img.Bounds().Dy(),
		Format:   "jpeg",
		DataSize: len(buf),
	}

	payload, _ := json.Marshal(resp)
	return &Message{Type: MsgTypeFrame, Payload: payload}, buf
}

// sliceWriter implements io.Writer for a byte slice
type sliceWriter struct {
	buf *[]byte
}

func (w *sliceWriter) Write(p []byte) (n int, err error) {
	*w.buf = append(*w.buf, p...)
	return len(p), nil
}

func scaleImage(img *image.RGBA, scale float64) *image.RGBA {
	bounds := img.Bounds()
	newWidth := int(float64(bounds.Dx()) * scale)
	newHeight := int(float64(bounds.Dy()) * scale)

	if newWidth < 1 {
		newWidth = 1
	}
	if newHeight < 1 {
		newHeight = 1
	}

	scaled := image.NewRGBA(image.Rect(0, 0, newWidth, newHeight))

	// Nearest-neighbor scaling
	xRatio := float64(bounds.Dx()) / float64(newWidth)
	yRatio := float64(bounds.Dy()) / float64(newHeight)

	for y := 0; y < newHeight; y++ {
		srcY := int(float64(y) * yRatio)
		for x := 0; x < newWidth; x++ {
			srcX := int(float64(x) * xRatio)
			scaled.Set(x, y, img.At(srcX+bounds.Min.X, srcY+bounds.Min.Y))
		}
	}

	return scaled
}

func handleInput(event InputEvent) {
	switch event.Type {
	case "mousemove":
		// Move mouse to absolute position
		win.SetCursorPos(int32(event.X), int32(event.Y))

	case "mousedown":
		injectMouseClick(event.Button, true)

	case "mouseup":
		injectMouseClick(event.Button, false)

	case "scroll":
		injectScroll(event.DeltaX, event.DeltaY)

	case "keydown":
		injectKey(event.Key, event.Code, true)

	case "keyup":
		injectKey(event.Key, event.Code, false)
	}
}

func injectMouseClick(button int, down bool) {
	var flags uint32
	switch button {
	case 0: // Left
		if down {
			flags = win.MOUSEEVENTF_LEFTDOWN
		} else {
			flags = win.MOUSEEVENTF_LEFTUP
		}
	case 1: // Middle
		if down {
			flags = win.MOUSEEVENTF_MIDDLEDOWN
		} else {
			flags = win.MOUSEEVENTF_MIDDLEUP
		}
	case 2: // Right
		if down {
			flags = win.MOUSEEVENTF_RIGHTDOWN
		} else {
			flags = win.MOUSEEVENTF_RIGHTUP
		}
	default:
		return
	}

	input := INPUT{
		Type: INPUT_MOUSE,
		Mi: MOUSEINPUT{
			DwFlags: flags,
		},
	}
	procSendInput.Call(1, uintptr(unsafe.Pointer(&input)), unsafe.Sizeof(input))
}

func injectScroll(deltaX, deltaY int) {
	if deltaY != 0 {
		input := INPUT{
			Type: INPUT_MOUSE,
			Mi: MOUSEINPUT{
				DwFlags:   win.MOUSEEVENTF_WHEEL,
				MouseData: uint32(deltaY * 120), // WHEEL_DELTA = 120
			},
		}
		procSendInput.Call(1, uintptr(unsafe.Pointer(&input)), unsafe.Sizeof(input))
	}

	if deltaX != 0 {
		input := INPUT{
			Type: INPUT_MOUSE,
			Mi: MOUSEINPUT{
				DwFlags:   win.MOUSEEVENTF_HWHEEL,
				MouseData: uint32(deltaX * 120),
			},
		}
		procSendInput.Call(1, uintptr(unsafe.Pointer(&input)), unsafe.Sizeof(input))
	}
}

func injectKey(key string, code string, down bool) {
	// First try code (physical key) for modifiers to distinguish left/right
	// Then fall back to key (character/name) for everything else
	vk := keyCodeToVK(code)
	if vk == 0 {
		vk = keyNameToVK(key)
	}

	// Special keys use VK codes
	if vk != 0 {
		var flags uint32
		if !down {
			flags = win.KEYEVENTF_KEYUP
		}

		input := INPUT_KBD{
			Type: INPUT_KEYBOARD,
			Ki: KEYBDINPUT{
				WVk:     uint16(vk),
				DwFlags: flags,
			},
		}
		procSendInput.Call(1, uintptr(unsafe.Pointer(&input)), unsafe.Sizeof(input))
		return
	}

	// For regular characters (including Unicode like ö, ä, ü, @, €), use KEYEVENTF_UNICODE
	// This works regardless of keyboard layout
	runes := []rune(key)
	if len(runes) == 1 {
		var flags uint32 = KEYEVENTF_UNICODE
		if !down {
			flags |= win.KEYEVENTF_KEYUP
		}

		input := INPUT_KBD{
			Type: INPUT_KEYBOARD,
			Ki: KEYBDINPUT{
				WVk:     0, // Must be 0 for KEYEVENTF_UNICODE
				WScan:   uint16(runes[0]), // Unicode code point
				DwFlags: flags,
			},
		}
		procSendInput.Call(1, uintptr(unsafe.Pointer(&input)), unsafe.Sizeof(input))
	}
}

// keyCodeToVK converts a JavaScript key code (physical key) to Windows VK code.
// This is used for modifier keys to distinguish left/right variants.
func keyCodeToVK(code string) uint32 {
	codeMap := map[string]uint32{
		// Modifier keys (left/right specific)
		"ShiftLeft":    win.VK_LSHIFT,
		"ShiftRight":   win.VK_RSHIFT,
		"ControlLeft":  win.VK_LCONTROL,
		"ControlRight": win.VK_RCONTROL,
		"AltLeft":      win.VK_LMENU,
		"AltRight":     win.VK_RMENU, // AltGr on EU keyboards
		"MetaLeft":     win.VK_LWIN,  // Command on Mac
		"MetaRight":    win.VK_RWIN,
		// Space (often used with code)
		"Space":        win.VK_SPACE,
	}

	if vk, ok := codeMap[code]; ok {
		return vk
	}
	return 0
}

// keyNameToVK converts a JavaScript key name to Windows virtual key code.
// Returns 0 for regular characters that should be handled via KEYEVENTF_UNICODE.
// Only returns a VK code for special keys (modifiers, function keys, navigation, etc.)
func keyNameToVK(key string) uint32 {
	// Special keys mapping - these need VK codes to work properly
	keyMap := map[string]uint32{
		// Navigation
		"Escape":      win.VK_ESCAPE,
		"Enter":       win.VK_RETURN,
		"Tab":         win.VK_TAB,
		"Backspace":   win.VK_BACK,
		"Delete":      win.VK_DELETE,
		"Insert":      win.VK_INSERT,
		"Home":        win.VK_HOME,
		"End":         win.VK_END,
		"PageUp":      win.VK_PRIOR,
		"PageDown":    win.VK_NEXT,
		"ArrowLeft":   win.VK_LEFT,
		"ArrowRight":  win.VK_RIGHT,
		"ArrowUp":     win.VK_UP,
		"ArrowDown":   win.VK_DOWN,
		// Modifiers (generic)
		"Control":      win.VK_CONTROL,
		"Shift":        win.VK_SHIFT,
		"Alt":          win.VK_MENU,
		"AltGraph":     win.VK_RMENU,  // Right Alt (AltGr) for special chars on EU keyboards
		"Meta":         win.VK_LWIN,   // Command key on Mac -> Windows key
		// Modifiers (left/right specific - some browsers report these)
		"ControlLeft":  win.VK_LCONTROL,
		"ControlRight": win.VK_RCONTROL,
		"ShiftLeft":    win.VK_LSHIFT,
		"ShiftRight":   win.VK_RSHIFT,
		"AltLeft":      win.VK_LMENU,
		"AltRight":     win.VK_RMENU,
		"MetaLeft":     win.VK_LWIN,
		"MetaRight":    win.VK_RWIN,
		// Lock keys
		"CapsLock":    win.VK_CAPITAL,
		"NumLock":     win.VK_NUMLOCK,
		"ScrollLock":  win.VK_SCROLL,
		// System keys
		"PrintScreen": win.VK_SNAPSHOT,
		"Pause":       win.VK_PAUSE,
		"ContextMenu": win.VK_APPS,
		// Function keys
		"F1":          win.VK_F1,
		"F2":          win.VK_F2,
		"F3":          win.VK_F3,
		"F4":          win.VK_F4,
		"F5":          win.VK_F5,
		"F6":          win.VK_F6,
		"F7":          win.VK_F7,
		"F8":          win.VK_F8,
		"F9":          win.VK_F9,
		"F10":         win.VK_F10,
		"F11":         win.VK_F11,
		"F12":         win.VK_F12,
	}

	if vk, ok := keyMap[key]; ok {
		return vk
	}

	// All regular characters (a-z, 0-9, ö, ä, ü, ß, @, €, etc.)
	// return 0 to be handled via KEYEVENTF_UNICODE
	// This ensures correct behavior regardless of keyboard layout
	return 0
}

// scanWingetUpdates runs winget upgrade in the user context and returns available updates.
func scanWingetUpdates(providedPath string) (*Message, []byte) {
	log.Println("Scanning for winget updates in user context")

	result := WingetScanResult{
		Updates: make([]WingetUpdate, 0),
	}

	// Use provided path or try to find winget
	wingetPath := providedPath
	if wingetPath == "" {
		var err error
		wingetPath, err = exec.LookPath("winget")
		if err != nil {
			result.Error = "winget not found in PATH"
			payload, _ := json.Marshal(result)
			return &Message{Type: MsgTypeWingetResult, Payload: payload}, nil
		}
	}

	log.Printf("Using winget at: %s", wingetPath)

	// Run winget upgrade
	cmd := exec.Command(wingetPath, "upgrade", "--accept-source-agreements", "--disable-interactivity", "--include-unknown")
	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	log.Printf("winget command output length: %d", len(outputStr))
	log.Printf("winget command output:\n%s", outputStr)

	if err != nil {
		log.Printf("winget command failed: %v", err)
		// Don't return error, try to parse output anyway
	}

	// Parse output - split on both \n and \r to handle Windows line endings
	// and progress indicator resets (winget uses \r for spinner animation)
	lines := strings.FieldsFunc(outputStr, func(r rune) bool {
		return r == '\n' || r == '\r'
	})
	headerFound := false
	separatorFound := false

	log.Printf("Parsing %d lines", len(lines))

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Skip progress indicators (spinner animation characters)
		if strings.Contains(trimmed, "█") || strings.Contains(trimmed, "▒") ||
			trimmed == "-" || trimmed == "\\" || trimmed == "|" || trimmed == "/" {
			continue
		}

		// Handle separator
		if strings.HasPrefix(trimmed, "---") || strings.HasPrefix(trimmed, "───") {
			separatorFound = true
			log.Printf("Line %d: SEPARATOR", i)
			continue
		}

		// Detect header (case-insensitive for localization support)
		lowerLine := strings.ToLower(trimmed)
		if strings.Contains(lowerLine, "name") && strings.Contains(lowerLine, "id") && strings.Contains(lowerLine, "version") {
			headerFound = true
			log.Printf("Line %d: HEADER - %s", i, trimmed)
			continue
		}

		// Skip summary lines (English and German)
		lowerTrimmed := strings.ToLower(trimmed)
		if strings.Contains(lowerTrimmed, "upgrades available") || strings.Contains(lowerTrimmed, "upgrade available") ||
			strings.Contains(lowerTrimmed, "no installed package") || strings.Contains(lowerTrimmed, "keine installierten") ||
			strings.Contains(lowerTrimmed, "aktualisierungen verfügbar") || strings.Contains(lowerTrimmed, "aktualisierung verfügbar") ||
			strings.Contains(lowerTrimmed, "aktualisierungen verf") { // Handle encoding issues
			log.Printf("Line %d: SUMMARY - %s", i, trimmed)
			continue
		}

		// Parse data lines
		if headerFound && separatorFound {
			log.Printf("Line %d: DATA - %s", i, trimmed)
			if update := parseWingetUpdateLine(trimmed); update != nil {
				result.Updates = append(result.Updates, *update)
				log.Printf("  -> Parsed: %s (%s) %s -> %s", update.Name, update.ID, update.Version, update.Available)
			} else {
				log.Printf("  -> Failed to parse")
			}
		} else {
			log.Printf("Line %d: SKIP (header=%v sep=%v) - %s", i, headerFound, separatorFound, trimmed)
		}
	}

	log.Printf("Found %d winget updates in user context", len(result.Updates))

	// Include raw output for debugging (truncate if too long)
	if len(outputStr) > 2000 {
		result.RawOutput = outputStr[:2000] + "...(truncated)"
	} else {
		result.RawOutput = outputStr
	}

	payload, _ := json.Marshal(result)
	return &Message{Type: MsgTypeWingetResult, Payload: payload}, nil
}

// parseWingetUpdateLine parses a winget upgrade output line.
func parseWingetUpdateLine(line string) *WingetUpdate {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return nil
	}

	// Format: Name [Name...] Id Version Available [Source]
	// The challenge: version strings can contain spaces like "6.6.6 (19875)"
	// Solution: Find the package ID by its format (Publisher.Package)

	lastIdx := len(fields) - 1
	source := "winget"

	// Check if last field is source
	if fields[lastIdx] == "winget" || fields[lastIdx] == "msstore" {
		source = fields[lastIdx]
		lastIdx--
	}

	if lastIdx < 3 {
		return nil
	}

	// Find the package ID by scanning for a field that matches winget ID format
	idIdx := -1
	for i := 1; i <= lastIdx-2; i++ {
		if isWingetPackageID(fields[i]) {
			idIdx = i
			break
		}
	}

	if idIdx < 0 {
		return nil
	}

	id := fields[idIdx]

	// Name is everything before the ID
	name := strings.Join(fields[:idIdx], " ")
	if name == "" {
		return nil
	}

	// Version fields are after the ID
	// There should be at least 2 version-like fields (current and available)
	versionFields := fields[idIdx+1 : lastIdx+1]
	if len(versionFields) < 2 {
		return nil
	}

	// Find version strings (contain digits)
	var versions []string
	for _, f := range versionFields {
		if containsDigit(f) {
			versions = append(versions, f)
		}
	}

	if len(versions) < 2 {
		return nil
	}

	// Last two version-like fields are current and available
	version := versions[len(versions)-2]
	available := versions[len(versions)-1]

	return &WingetUpdate{
		Name:      name,
		ID:        id,
		Version:   version,
		Available: available,
		Source:    source,
	}
}

// isWingetPackageID checks if a string looks like a winget package ID.
// Winget package IDs follow the format "Publisher.Package" (e.g., "Microsoft.VisualStudioCode").
func isWingetPackageID(s string) bool {
	// Must contain at least one dot
	if !strings.Contains(s, ".") {
		return false
	}

	// Must not start or end with a dot
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}

	// Must not start with a digit (version numbers start with digits)
	if len(s) > 0 && s[0] >= '0' && s[0] <= '9' {
		return false
	}

	// Must not be wrapped in parentheses like "(19875)"
	if strings.HasPrefix(s, "(") || strings.HasSuffix(s, ")") {
		return false
	}

	// Should only contain valid characters (letters, digits, dots, underscores, hyphens)
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}

	return true
}

// containsDigit checks if a string contains at least one digit.
func containsDigit(s string) bool {
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}

// runUpdateMode performs deferred binary replacement after the agent exits.
// This is used when updating from command line where the running binary is locked.
func runUpdateMode(srcPath, dstPath string, pid int, serviceName string) error {
	log.Printf("Update mode: src=%s dst=%s pid=%d service=%s", srcPath, dstPath, pid, serviceName)

	if srcPath == "" || dstPath == "" {
		return fmt.Errorf("source and destination paths are required")
	}

	// Wait for the parent process to exit if PID is provided
	if pid > 0 {
		log.Printf("Waiting for process %d to exit...", pid)
		if err := waitForProcessExit(pid, 30*time.Second); err != nil {
			log.Printf("Warning: %v, continuing anyway", err)
		}
		// Give extra time for file handles to be released
		time.Sleep(500 * time.Millisecond)
	}

	// Try to stop the service (in case it's running)
	log.Println("Stopping service...")
	stopService(serviceName)
	time.Sleep(500 * time.Millisecond)

	// Replace the binary
	log.Println("Replacing binary...")
	if err := replaceBinary(srcPath, dstPath); err != nil {
		return fmt.Errorf("replacing binary: %w", err)
	}

	// Start the service
	log.Println("Starting service...")
	if err := startService(serviceName); err != nil {
		return fmt.Errorf("starting service: %w", err)
	}

	log.Println("Update completed successfully")

	// Clean up the source file
	os.Remove(srcPath)

	return nil
}

// waitForProcessExit waits for a process to exit.
func waitForProcessExit(pid int, timeout time.Duration) error {
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		// Process might already be gone
		return nil
	}
	defer windows.CloseHandle(handle)

	// Wait for process to exit
	// WAIT_TIMEOUT is 0x00000102 = 258
	const waitTimeout = 0x00000102
	event, err := windows.WaitForSingleObject(handle, uint32(timeout.Milliseconds()))
	if err != nil {
		return fmt.Errorf("waiting for process: %w", err)
	}

	if event == waitTimeout {
		return fmt.Errorf("timeout waiting for process %d to exit", pid)
	}

	return nil
}

// replaceBinary replaces the destination binary with the source.
func replaceBinary(srcPath, dstPath string) error {
	// First, try to rename the old binary out of the way
	oldPath := dstPath + ".old"
	os.Remove(oldPath) // Remove any previous .old file

	if err := os.Rename(dstPath, oldPath); err != nil {
		log.Printf("Rename failed: %v, trying direct removal", err)
		if rmErr := os.Remove(dstPath); rmErr != nil {
			return fmt.Errorf("cannot remove old binary: %w", rmErr)
		}
	}

	// Try to rename the new binary into place (atomic)
	if err := os.Rename(srcPath, dstPath); err != nil {
		log.Printf("Rename of new binary failed: %v, falling back to copy", err)
		// Fall back to copy if cross-device
		if err := copyFile(srcPath, dstPath); err != nil {
			// Try to restore the old binary
			os.Rename(oldPath, dstPath)
			return fmt.Errorf("copy failed: %w", err)
		}
	}

	// Set executable permissions (no-op on Windows but good practice)
	os.Chmod(dstPath, 0755)

	// Clean up old binary
	os.Remove(oldPath)

	return nil
}

// copyFile copies a file from src to dst.
func copyFile(srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	if _, err := copyBuffer(dst, src); err != nil {
		return err
	}

	return nil
}

// copyBuffer copies from src to dst using a buffer.
func copyBuffer(dst *os.File, src *os.File) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		nr, readErr := src.Read(buf)
		if nr > 0 {
			nw, writeErr := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if writeErr != nil {
				return written, writeErr
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return written, nil
			}
			return written, readErr
		}
	}
}

// stopService stops the Windows service using PowerShell with force and timeout.
func stopService(name string) error {
	psScript := fmt.Sprintf(`
		$ErrorActionPreference = 'SilentlyContinue'
		$svc = Get-Service -Name '%s' -ErrorAction SilentlyContinue
		if ($svc -and $svc.Status -ne 'Stopped') {
			Stop-Service -Name '%s' -Force -NoWait -ErrorAction SilentlyContinue
			try {
				$svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
			} catch {
				# Force kill if timeout
				$proc = Get-CimInstance Win32_Service -Filter "Name='%s'" | Select-Object -ExpandProperty ProcessId
				if ($proc -and $proc -ne 0) {
					Stop-Process -Id $proc -Force -ErrorAction SilentlyContinue
					Start-Sleep -Seconds 2
				}
			}
		}
	`, name, name, name)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("PowerShell stop failed: %v, output: %s", err, string(output))
	}
	return nil
}

// startService starts the Windows service using PowerShell with timeout.
func startService(name string) error {
	psScript := fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		try {
			$svc = Get-Service -Name '%s' -ErrorAction Stop
			if ($svc.Status -eq 'Running') {
				Write-Output 'ALREADY_RUNNING'
				exit 0
			}
			Start-Service -Name '%s' -ErrorAction Stop
			$svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
			Write-Output 'SUCCESS'
		} catch {
			Write-Error $_.Exception.Message
			exit 1
		}
	`, name, name)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("PowerShell start failed: %v, output: %s", err, string(output))
	}
	log.Printf("Service start result: %s", strings.TrimSpace(string(output)))
	return nil
}

// getRecentWingetLog reads the most recent winget log file for debugging.
// Winget logs are stored in: %LOCALAPPDATA%\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\DiagOutputDir
func getRecentWingetLog() string {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return ""
	}

	diagDir := filepath.Join(localAppData, "Packages", "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe", "LocalState", "DiagOutputDir")

	// Check if directory exists
	if _, err := os.Stat(diagDir); os.IsNotExist(err) {
		log.Printf("Winget DiagOutputDir does not exist: %s", diagDir)
		return ""
	}

	// Find all log files
	entries, err := os.ReadDir(diagDir)
	if err != nil {
		log.Printf("Failed to read winget DiagOutputDir: %v", err)
		return ""
	}

	// Filter and sort by modification time (most recent first)
	type logFile struct {
		name    string
		modTime time.Time
	}
	var logFiles []logFile

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// Only consider .log files
		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".log") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		logFiles = append(logFiles, logFile{
			name:    entry.Name(),
			modTime: info.ModTime(),
		})
	}

	if len(logFiles) == 0 {
		log.Printf("No winget log files found in: %s", diagDir)
		return ""
	}

	// Sort by modification time, most recent first
	sort.Slice(logFiles, func(i, j int) bool {
		return logFiles[i].modTime.After(logFiles[j].modTime)
	})

	// Read the most recent log file
	mostRecent := logFiles[0]
	logPath := filepath.Join(diagDir, mostRecent.name)
	log.Printf("Reading most recent winget log: %s (modified: %s)", logPath, mostRecent.modTime.Format(time.RFC3339))

	content, err := os.ReadFile(logPath)
	if err != nil {
		log.Printf("Failed to read winget log file: %v", err)
		return ""
	}

	// Limit log size to 50KB to avoid huge responses
	const maxLogSize = 50 * 1024
	if len(content) > maxLogSize {
		// Take the last 50KB (most relevant for recent errors)
		content = content[len(content)-maxLogSize:]
		return "... (truncated) ...\n" + string(content)
	}

	return string(content)
}

// upgradeWingetPackage runs winget upgrade for a specific package in user context.
func upgradeWingetPackage(providedPath, packageID string) (*Message, []byte) {
	log.Printf("Upgrading winget package in user context: %s", packageID)

	result := WingetUpgradeResult{}

	// Use provided path or try to find winget
	wingetPath := providedPath
	if wingetPath == "" {
		var err error
		wingetPath, err = exec.LookPath("winget")
		if err != nil {
			result.Error = "winget not found in PATH"
			result.ExitCode = -1
			payload, _ := json.Marshal(result)
			return &Message{Type: MsgTypeWingetUpgradeResult, Payload: payload}, nil
		}
	}

	log.Printf("Using winget at: %s", wingetPath)

	// Create context with 15 minute timeout (some packages like Zoom need more time)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Run winget upgrade with timeout
	// --force closes running applications to allow update
	cmd := exec.CommandContext(ctx, wingetPath, "upgrade",
		"--id", packageID,
		"--accept-source-agreements",
		"--accept-package-agreements",
		"--disable-interactivity",
		"--silent",
		"--force",
	)

	log.Printf("Starting winget upgrade command for package: %s", packageID)

	output, err := cmd.CombinedOutput()
	result.Output = string(output)

	log.Printf("Winget upgrade command finished, output length: %d bytes", len(output))

	if err != nil {
		// Check for context timeout
		if ctx.Err() == context.DeadlineExceeded {
			result.ExitCode = -2
			result.Error = "upgrade timed out after 15 minutes"
			log.Printf("Winget upgrade timed out for package: %s", packageID)
			// Get winget logs for timeout failures
			result.WingetLog = getRecentWingetLog()
			payload, _ := json.Marshal(result)
			return &Message{Type: MsgTypeWingetUpgradeResult, Payload: payload}, nil
		}

		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
			log.Printf("Winget exit code: %d (0x%X)", result.ExitCode, uint32(result.ExitCode))

			// Check for "already up to date" exit code
			if winget.IsNoUpdateAvailable(result.ExitCode) {
				result.Success = true
				result.Error = "already up to date"
			} else if winget.IsPackageNotFound(result.ExitCode) {
				// Package not found - might be system-level package
				result.Success = false
				result.Error = "package not found in user context"
			} else {
				result.Error = fmt.Sprintf("upgrade failed with exit code %d (0x%X)", result.ExitCode, uint32(result.ExitCode))
			}
		} else {
			result.ExitCode = -1
			result.Error = err.Error()
		}
	} else {
		result.Success = true
		result.ExitCode = 0
	}

	// If upgrade failed (and not just "already up to date"), try to get winget logs
	if !result.Success {
		log.Printf("Attempting to retrieve winget log for failed upgrade")
		result.WingetLog = getRecentWingetLog()
		if result.WingetLog != "" {
			log.Printf("Retrieved winget log (%d bytes)", len(result.WingetLog))
		}
	}

	log.Printf("Winget upgrade completed: success=%v exitCode=%d error=%s", result.Success, result.ExitCode, result.Error)

	payload, _ := json.Marshal(result)
	return &Message{Type: MsgTypeWingetUpgradeResult, Payload: payload}, nil
}
