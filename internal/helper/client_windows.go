// Package helper provides Windows helper process management for remote desktop.
// The helper runs in the user's interactive session to access the desktop.
//go:build windows

package helper

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	pipeName       = `\\.\pipe\slimrmm-helper`
	maxMessageSize = 10 * 1024 * 1024 // 10MB
	connectTimeout = 10 * time.Second
)

// Message types - must match helper/main.go
const (
	MsgTypeCapture     = "capture"
	MsgTypeFrame       = "frame"
	MsgTypeInput       = "input"
	MsgTypeMonitors    = "monitors"
	MsgTypeMonitorList = "monitor_list"
	MsgTypePing        = "ping"
	MsgTypePong        = "pong"
	MsgTypeError       = "error"
	MsgTypeQuit        = "quit"
)

// Message is the IPC message format
type Message struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// CaptureRequest requests a screen capture
type CaptureRequest struct {
	MonitorID int     `json:"monitor_id"`
	Quality   int     `json:"quality"`
	Scale     float64 `json:"scale"`
}

// FrameResponse contains captured frame metadata
type FrameResponse struct {
	Width    int    `json:"width"`
	Height   int    `json:"height"`
	Format   string `json:"format"`
	DataSize int    `json:"data_size"`
}

// InputEvent represents mouse/keyboard input
type InputEvent struct {
	Type   string `json:"type"`
	X      int    `json:"x,omitempty"`
	Y      int    `json:"y,omitempty"`
	Button int    `json:"button,omitempty"`
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

// Client manages communication with the helper process
type Client struct {
	pipe       windows.Handle
	helperCmd  *exec.Cmd
	sessionID  string
	mu         sync.Mutex
	connected  bool
}

// Windows API for session management
var (
	kernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	wtsapi32                    = windows.NewLazySystemDLL("wtsapi32.dll")
	userenv                     = windows.NewLazySystemDLL("userenv.dll")
	advapi32                    = windows.NewLazySystemDLL("advapi32.dll")

	procWTSGetActiveConsoleSessionId = kernel32.NewProc("WTSGetActiveConsoleSessionId")
	procWTSQueryUserToken            = wtsapi32.NewProc("WTSQueryUserToken")
	procCreateEnvironmentBlock       = userenv.NewProc("CreateEnvironmentBlock")
	procDestroyEnvironmentBlock      = userenv.NewProc("DestroyEnvironmentBlock")
	procCreateProcessAsUserW         = advapi32.NewProc("CreateProcessAsUserW")
	procDuplicateTokenEx             = advapi32.NewProc("DuplicateTokenEx")
	procWaitNamedPipeW               = kernel32.NewProc("WaitNamedPipeW")
)

// Windows constants
const (
	MAXIMUM_ALLOWED              = 0x02000000
	TOKEN_DUPLICATE              = 0x0002
	TOKEN_QUERY                  = 0x0008
	TOKEN_ASSIGN_PRIMARY         = 0x0001
	SecurityImpersonation        = 2
	TokenPrimary                 = 1
	CREATE_UNICODE_ENVIRONMENT   = 0x00000400
	CREATE_NEW_CONSOLE           = 0x00000010
	CREATE_NO_WINDOW             = 0x08000000
	DETACHED_PROCESS             = 0x00000008
	NORMAL_PRIORITY_CLASS        = 0x00000020
)

// NewClient creates a new helper client
func NewClient() *Client {
	return &Client{}
}

// Start starts the helper process in the active user session
func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	// Get active console session
	sessionID, _, _ := procWTSGetActiveConsoleSessionId.Call()
	if sessionID == 0xFFFFFFFF {
		return fmt.Errorf("no active console session")
	}
	c.sessionID = fmt.Sprintf("%d", sessionID)

	log.Printf("Active console session: %s", c.sessionID)

	// Find helper executable
	helperPath, err := findHelperExe()
	if err != nil {
		return fmt.Errorf("finding helper: %w", err)
	}

	// Start helper in user session
	if err := c.startHelperInSession(helperPath, uint32(sessionID)); err != nil {
		return fmt.Errorf("starting helper: %w", err)
	}

	// Connect to helper pipe
	if err := c.connectToPipe(); err != nil {
		c.stopHelper()
		return fmt.Errorf("connecting to pipe: %w", err)
	}

	c.connected = true
	log.Printf("Helper started and connected")
	return nil
}

// findHelperExe locates the helper executable
func findHelperExe() (string, error) {
	// Check same directory as agent
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}

	dir := filepath.Dir(exePath)
	helperPath := filepath.Join(dir, "slimrmm-helper.exe")
	if _, err := os.Stat(helperPath); err == nil {
		return helperPath, nil
	}

	// Check common installation paths
	paths := []string{
		`C:\Program Files\SlimRMM\slimrmm-helper.exe`,
		`C:\Program Files (x86)\SlimRMM\slimrmm-helper.exe`,
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	return "", fmt.Errorf("helper executable not found")
}

// startHelperInSession starts the helper in the specified session using CreateProcessAsUser
func (c *Client) startHelperInSession(helperPath string, sessionID uint32) error {
	// Get user token for the session
	var userToken windows.Token
	ret, _, err := procWTSQueryUserToken.Call(
		uintptr(sessionID),
		uintptr(unsafe.Pointer(&userToken)),
	)
	if ret == 0 {
		// If WTSQueryUserToken fails, try to run directly (may work if already in user session)
		log.Printf("WTSQueryUserToken failed: %v, trying direct start", err)
		return c.startHelperDirect(helperPath)
	}
	defer windows.CloseHandle(windows.Handle(userToken))

	// Duplicate token for CreateProcessAsUser
	var dupToken windows.Token
	ret, _, err = procDuplicateTokenEx.Call(
		uintptr(userToken),
		MAXIMUM_ALLOWED,
		0, // Security attributes
		SecurityImpersonation,
		TokenPrimary,
		uintptr(unsafe.Pointer(&dupToken)),
	)
	if ret == 0 {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer windows.CloseHandle(windows.Handle(dupToken))

	// Create environment block for user
	var envBlock uintptr
	ret, _, err = procCreateEnvironmentBlock.Call(
		uintptr(unsafe.Pointer(&envBlock)),
		uintptr(dupToken),
		0, // Don't inherit
	)
	if ret == 0 {
		return fmt.Errorf("CreateEnvironmentBlock: %w", err)
	}
	defer procDestroyEnvironmentBlock.Call(envBlock)

	// Prepare command line
	cmdLine := fmt.Sprintf(`"%s" -session %s`, helperPath, c.sessionID)
	cmdLinePtr, err := windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		return err
	}

	// Startup info
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Desktop, _ = windows.UTF16PtrFromString("winsta0\\default")

	// Process info
	var pi windows.ProcessInformation

	// Create process in user session
	ret, _, err = procCreateProcessAsUserW.Call(
		uintptr(dupToken),
		0, // Application name (use command line)
		uintptr(unsafe.Pointer(cmdLinePtr)),
		0, // Process security attributes
		0, // Thread security attributes
		0, // Inherit handles
		CREATE_UNICODE_ENVIRONMENT|CREATE_NO_WINDOW|NORMAL_PRIORITY_CLASS,
		envBlock,
		0, // Current directory
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return fmt.Errorf("CreateProcessAsUserW: %w", err)
	}

	// Close handles we don't need
	windows.CloseHandle(windows.Handle(pi.Thread))

	log.Printf("Helper process started with PID %d", pi.ProcessId)

	// Give helper time to start
	time.Sleep(500 * time.Millisecond)
	return nil
}

// startHelperDirect starts helper as child process (fallback)
func (c *Client) startHelperDirect(helperPath string) error {
	c.helperCmd = exec.Command(helperPath, "-session", c.sessionID)
	c.helperCmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: CREATE_NO_WINDOW,
	}

	if err := c.helperCmd.Start(); err != nil {
		return err
	}

	log.Printf("Helper started directly with PID %d", c.helperCmd.Process.Pid)
	time.Sleep(500 * time.Millisecond)
	return nil
}

// connectToPipe connects to the helper's named pipe
func (c *Client) connectToPipe() error {
	pName := fmt.Sprintf("%s-%s", pipeName, c.sessionID)
	pNamePtr, err := windows.UTF16PtrFromString(pName)
	if err != nil {
		return err
	}

	deadline := time.Now().Add(connectTimeout)
	for time.Now().Before(deadline) {
		pipe, err := windows.CreateFile(
			pNamePtr,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0,    // No sharing
			nil,  // Security attributes
			windows.OPEN_EXISTING,
			0,    // Flags
			0,    // Template file
		)
		if err == nil {
			c.pipe = pipe

			// Set pipe to message mode
			var mode uint32 = windows.PIPE_READMODE_MESSAGE
			windows.SetNamedPipeHandleState(pipe, &mode, nil, nil)

			return nil
		}

		if err == windows.ERROR_PIPE_BUSY {
			// Wait for pipe to become available
			procWaitNamedPipeW.Call(uintptr(unsafe.Pointer(pNamePtr)), 1000)
			continue
		}

		// Pipe not ready yet, wait and retry
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("timeout connecting to helper pipe")
}

// Stop stops the helper process
func (c *Client) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil
	}

	// Send quit message
	c.sendMessage(&Message{Type: MsgTypeQuit})

	// Close pipe
	if c.pipe != 0 {
		windows.CloseHandle(c.pipe)
		c.pipe = 0
	}

	c.connected = false
	c.stopHelper()
	return nil
}

func (c *Client) stopHelper() {
	if c.helperCmd != nil && c.helperCmd.Process != nil {
		c.helperCmd.Process.Kill()
		c.helperCmd = nil
	}
}

// IsConnected returns whether the helper is connected
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

// Ping sends a ping to the helper
func (c *Client) Ping() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return fmt.Errorf("not connected")
	}

	if err := c.sendMessage(&Message{Type: MsgTypePing}); err != nil {
		return err
	}

	msg, _, err := c.readMessage()
	if err != nil {
		return err
	}

	if msg.Type != MsgTypePong {
		return fmt.Errorf("unexpected response: %s", msg.Type)
	}

	return nil
}

// GetMonitors returns the list of available monitors
func (c *Client) GetMonitors() ([]Monitor, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	if err := c.sendMessage(&Message{Type: MsgTypeMonitors}); err != nil {
		return nil, err
	}

	msg, _, err := c.readMessage()
	if err != nil {
		return nil, err
	}

	if msg.Type == MsgTypeError {
		return nil, fmt.Errorf("helper error: %s", string(msg.Payload))
	}

	if msg.Type != MsgTypeMonitorList {
		return nil, fmt.Errorf("unexpected response: %s", msg.Type)
	}

	var monitors []Monitor
	if err := json.Unmarshal(msg.Payload, &monitors); err != nil {
		return nil, err
	}

	return monitors, nil
}

// CaptureScreen captures a frame from the specified monitor
func (c *Client) CaptureScreen(monitorID, quality int, scale float64) ([]byte, *FrameResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, nil, fmt.Errorf("not connected")
	}

	req := CaptureRequest{
		MonitorID: monitorID,
		Quality:   quality,
		Scale:     scale,
	}

	payload, _ := json.Marshal(req)
	if err := c.sendMessage(&Message{Type: MsgTypeCapture, Payload: payload}); err != nil {
		return nil, nil, err
	}

	msg, frameData, err := c.readMessage()
	if err != nil {
		return nil, nil, err
	}

	if msg.Type == MsgTypeError {
		return nil, nil, fmt.Errorf("helper error: %s", string(msg.Payload))
	}

	if msg.Type != MsgTypeFrame {
		return nil, nil, fmt.Errorf("unexpected response: %s", msg.Type)
	}

	var resp FrameResponse
	if err := json.Unmarshal(msg.Payload, &resp); err != nil {
		return nil, nil, err
	}

	return frameData, &resp, nil
}

// SendInput sends an input event to the helper
func (c *Client) SendInput(event InputEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return fmt.Errorf("not connected")
	}

	payload, _ := json.Marshal(event)
	return c.sendMessage(&Message{Type: MsgTypeInput, Payload: payload})
}

// sendMessage sends a message to the helper
func (c *Client) sendMessage(msg *Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// Build complete message: length (4 bytes) + JSON
	fullMsg := make([]byte, 4+len(data))
	binary.LittleEndian.PutUint32(fullMsg[:4], uint32(len(data)))
	copy(fullMsg[4:], data)

	// Write everything in a single call (required for message mode pipes)
	var written uint32
	return windows.WriteFile(c.pipe, fullMsg, &written, nil)
}

// readMessage reads a message and optional extra data from the helper
func (c *Client) readMessage() (*Message, []byte, error) {
	// In message mode, we must read the entire message at once
	// Start with a reasonable buffer, grow if needed
	buf := make([]byte, 64*1024) // 64KB initial
	totalRead := 0

	for {
		var n uint32
		err := windows.ReadFile(c.pipe, buf[totalRead:], &n, nil)
		totalRead += int(n)

		if err == nil {
			// Complete message read
			break
		}

		if err == windows.ERROR_MORE_DATA {
			// Message larger than buffer, grow and continue
			if totalRead >= maxMessageSize {
				return nil, nil, fmt.Errorf("message too large: %d", totalRead)
			}
			newBuf := make([]byte, len(buf)*2)
			copy(newBuf, buf[:totalRead])
			buf = newBuf
			continue
		}

		return nil, nil, err
	}

	if totalRead < 4 {
		return nil, nil, fmt.Errorf("message too short: %d bytes", totalRead)
	}

	// Parse length prefix
	dataLen := binary.LittleEndian.Uint32(buf[:4])
	if int(dataLen) != totalRead-4 {
		return nil, nil, fmt.Errorf("length mismatch: header says %d, got %d", dataLen, totalRead-4)
	}

	data := buf[4:totalRead]

	// Find end of JSON (first closing brace at depth 0)
	jsonEnd := findJSONEnd(data)
	if jsonEnd < 0 {
		return nil, nil, fmt.Errorf("invalid message format")
	}

	var msg Message
	if err := json.Unmarshal(data[:jsonEnd+1], &msg); err != nil {
		return nil, nil, err
	}

	// Extra data follows the JSON
	var extraData []byte
	if jsonEnd+1 < len(data) {
		extraData = data[jsonEnd+1:]
	}

	return &msg, extraData, nil
}

// findJSONEnd finds the end of a JSON object in the data
func findJSONEnd(data []byte) int {
	depth := 0
	inString := false
	escaped := false

	for i, b := range data {
		if escaped {
			escaped = false
			continue
		}

		if b == '\\' && inString {
			escaped = true
			continue
		}

		if b == '"' {
			inString = !inString
			continue
		}

		if inString {
			continue
		}

		switch b {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}

	return -1
}

// Reconnect attempts to reconnect to the helper
func (c *Client) Reconnect() error {
	c.Stop()
	return c.Start()
}

// ensure io import is used
var _ = io.EOF
