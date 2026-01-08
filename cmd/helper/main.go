// SlimRMM Desktop Helper
// This helper runs in the user's interactive session to capture screen
// and inject input when the main agent service requests remote desktop.
//
//go:build windows

package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"image"
	"image/jpeg"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/kbinani/screenshot"
	"github.com/lxn/win"
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
	MsgTypeCapture    = "capture"
	MsgTypeFrame      = "frame"
	MsgTypeInput      = "input"
	MsgTypeMonitors   = "monitors"
	MsgTypeMonitorList = "monitor_list"
	MsgTypePing       = "ping"
	MsgTypePong       = "pong"
	MsgTypeError      = "error"
	MsgTypeQuit       = "quit"
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
	Key    string `json:"key,omitempty"`
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

func main() {
	// Parse flags
	var sessionID string
	flag.StringVar(&sessionID, "session", "", "Session ID for the pipe name")
	flag.Parse()

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
		injectKey(event.Key, true)

	case "keyup":
		injectKey(event.Key, false)
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

func injectKey(key string, down bool) {
	// Convert key name to virtual key code
	vk := keyNameToVK(key)
	if vk == 0 {
		return
	}

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
}

// keyNameToVK converts a JavaScript key name to Windows virtual key code
func keyNameToVK(key string) uint32 {
	// Common keys mapping
	keyMap := map[string]uint32{
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
		"Control":     win.VK_CONTROL,
		"Shift":       win.VK_SHIFT,
		"Alt":         win.VK_MENU,
		"Meta":        win.VK_LWIN,
		"CapsLock":    win.VK_CAPITAL,
		"NumLock":     win.VK_NUMLOCK,
		"ScrollLock":  win.VK_SCROLL,
		"PrintScreen": win.VK_SNAPSHOT,
		"Pause":       win.VK_PAUSE,
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
		" ":           win.VK_SPACE,
	}

	if vk, ok := keyMap[key]; ok {
		return vk
	}

	// Single character - use its ASCII value
	if len(key) == 1 {
		return uint32(key[0])
	}

	return 0
}
