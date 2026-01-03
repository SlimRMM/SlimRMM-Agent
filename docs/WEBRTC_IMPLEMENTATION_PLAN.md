# WebRTC Remote Desktop Implementation Plan for Go Agent

## Overview

This document outlines the complete implementation plan for porting the WebRTC-based remote desktop functionality from the Python agent to the Go agent. The goal is 100% feature parity with the existing Python implementation.

## Current Python Implementation Analysis

### Dependencies Used
| Python Library | Purpose | Go Equivalent |
|----------------|---------|---------------|
| aiortc | WebRTC implementation | github.com/pion/webrtc/v4 |
| mss | Screen capture | github.com/kbinani/screenshot |
| pynput | Mouse/keyboard control | github.com/go-vgo/robotgo |
| pyperclip | Clipboard sync | golang.design/x/clipboard |
| numpy | Image processing | image/draw (stdlib) |
| av (PyAV) | Video encoding | github.com/pion/mediadevices or manual VP8/VP9 |

### Feature Matrix
| Feature | Python Status | Go Implementation |
|---------|---------------|-------------------|
| Screen capture | ✅ mss | kbinani/screenshot |
| Multi-monitor support | ✅ | kbinani/screenshot |
| Quality presets (low/balanced/high) | ✅ | Manual scaling |
| WebRTC offer/answer | ✅ aiortc | pion/webrtc |
| ICE candidate exchange | ✅ | pion/webrtc |
| Data channel for input | ✅ | pion/webrtc |
| Mouse control (move/click/scroll) | ✅ pynput | go-vgo/robotgo |
| Keyboard control | ✅ pynput | go-vgo/robotgo |
| Clipboard sync | ✅ pyperclip | golang.design/x/clipboard |
| Display server detection (X11/Wayland) | ✅ | Environment checks |

---

## Architecture

### Module Structure

```
internal/
├── remotedesktop/
│   ├── remotedesktop.go      # Main session manager and public API
│   ├── capture.go            # Screen capture implementation
│   ├── capture_darwin.go     # macOS-specific capture
│   ├── capture_linux.go      # Linux-specific capture
│   ├── capture_windows.go    # Windows-specific capture
│   ├── input.go              # Input handling (mouse/keyboard)
│   ├── input_darwin.go       # macOS-specific input
│   ├── input_linux.go        # Linux-specific input
│   ├── input_windows.go      # Windows-specific input
│   ├── webrtc.go             # WebRTC peer connection management
│   ├── track.go              # Video track implementation
│   └── clipboard.go          # Clipboard synchronization
```

### Key Interfaces

```go
// Session represents an active remote desktop session
type Session interface {
    Start() (*StartResult, error)
    Stop() error
    HandleAnswer(answer SessionDescription) error
    HandleICECandidate(candidate ICECandidate) error
    SetQuality(quality string)
    SetMonitor(monitorID int)
    GetMonitors() []Monitor
}

// ScreenCapture handles screen capture operations
type ScreenCapture interface {
    GetMonitors() []Monitor
    CaptureFrame(monitorID int) (*image.RGBA, error)
    Close()
}

// InputController handles mouse and keyboard input
type InputController interface {
    MoveMouse(x, y int)
    MouseDown(button MouseButton)
    MouseUp(button MouseButton)
    MouseClick(button MouseButton)
    MouseScroll(dx, dy int)
    KeyDown(key string)
    KeyUp(key string)
    TypeString(s string)
}

// ClipboardManager handles clipboard synchronization
type ClipboardManager interface {
    GetText() (string, error)
    SetText(text string) error
}
```

---

## Implementation Details

### 1. Screen Capture (`capture.go`)

Using `github.com/kbinani/screenshot`:

```go
package remotedesktop

import (
    "image"
    "github.com/kbinani/screenshot"
)

type Monitor struct {
    ID      int    `json:"id"`
    Left    int    `json:"left"`
    Top     int    `json:"top"`
    Width   int    `json:"width"`
    Height  int    `json:"height"`
    Name    string `json:"name"`
    Primary bool   `json:"primary"`
}

type screenCapture struct {
    monitors []Monitor
}

func NewScreenCapture() (*screenCapture, error) {
    sc := &screenCapture{}
    sc.updateMonitors()
    return sc, nil
}

func (sc *screenCapture) updateMonitors() {
    n := screenshot.NumActiveDisplays()
    sc.monitors = make([]Monitor, 0, n)

    for i := 0; i < n; i++ {
        bounds := screenshot.GetDisplayBounds(i)
        sc.monitors = append(sc.monitors, Monitor{
            ID:      i + 1, // 1-based like Python
            Left:    bounds.Min.X,
            Top:     bounds.Min.Y,
            Width:   bounds.Dx(),
            Height:  bounds.Dy(),
            Name:    fmt.Sprintf("Monitor %d", i+1),
            Primary: i == 0,
        })
    }
}

func (sc *screenCapture) GetMonitors() []Monitor {
    sc.updateMonitors()
    return sc.monitors
}

func (sc *screenCapture) CaptureFrame(monitorID int) (*image.RGBA, error) {
    idx := monitorID - 1 // Convert to 0-based
    if idx < 0 || idx >= screenshot.NumActiveDisplays() {
        return nil, fmt.Errorf("invalid monitor ID: %d", monitorID)
    }

    bounds := screenshot.GetDisplayBounds(idx)
    img, err := screenshot.CaptureRect(bounds)
    if err != nil {
        return nil, fmt.Errorf("capturing screen: %w", err)
    }

    return img, nil
}
```

### 2. Quality Presets

Match Python exactly:

```go
var QualityPresets = map[string]QualitySettings{
    "low":      {Scale: 0.5, FPS: 15},
    "balanced": {Scale: 0.75, FPS: 30},
    "high":     {Scale: 1.0, FPS: 60},
}

type QualitySettings struct {
    Scale float64
    FPS   int
}

func scaleImage(img *image.RGBA, scale float64) *image.RGBA {
    if scale >= 1.0 {
        return img
    }

    newWidth := int(float64(img.Bounds().Dx()) * scale)
    newHeight := int(float64(img.Bounds().Dy()) * scale)

    scaled := image.NewRGBA(image.Rect(0, 0, newWidth, newHeight))
    draw.NearestNeighbor.Scale(scaled, scaled.Bounds(), img, img.Bounds(), draw.Over, nil)

    return scaled
}
```

### 3. WebRTC Implementation (`webrtc.go`)

Using `github.com/pion/webrtc/v4`:

```go
package remotedesktop

import (
    "encoding/json"
    "github.com/pion/webrtc/v4"
)

type SessionDescription struct {
    Type string `json:"type"`
    SDP  string `json:"sdp"`
}

type ICECandidate struct {
    Candidate     string `json:"candidate"`
    SDPMid        string `json:"sdpMid"`
    SDPMLineIndex uint16 `json:"sdpMLineIndex"`
}

func getWebRTCConfig() webrtc.Configuration {
    return webrtc.Configuration{
        ICEServers: []webrtc.ICEServer{
            {URLs: []string{"stun:stun.l.google.com:19302"}},
            {URLs: []string{"stun:stun1.l.google.com:19302"}},
            {URLs: []string{"stun:stun2.l.google.com:19302"}},
        },
    }
}

type webrtcSession struct {
    sessionID    string
    pc           *webrtc.PeerConnection
    videoTrack   *videoTrack
    dataChannel  *webrtc.DataChannel
    sendCallback func(msg []byte) error

    capture      *screenCapture
    input        *inputController

    selectedMon  int
    quality      string
    running      bool
    mu           sync.Mutex
}

func (s *webrtcSession) Start() (*StartResult, error) {
    var err error

    // Create peer connection
    s.pc, err = webrtc.NewPeerConnection(getWebRTCConfig())
    if err != nil {
        return nil, fmt.Errorf("creating peer connection: %w", err)
    }

    // Handle ICE candidates
    s.pc.OnICECandidate(func(c *webrtc.ICECandidate) {
        if c == nil {
            return
        }

        candidate := c.ToJSON()
        msg, _ := json.Marshal(map[string]interface{}{
            "action":     "ice_candidate",
            "session_id": s.sessionID,
            "candidate": map[string]interface{}{
                "candidate":     candidate.Candidate,
                "sdpMid":        candidate.SDPMid,
                "sdpMLineIndex": candidate.SDPMLineIndex,
            },
        })
        s.sendCallback(msg)
    })

    // Handle connection state changes
    s.pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
        if state == webrtc.PeerConnectionStateFailed {
            s.Stop()
        }
    })

    // Create video track
    s.videoTrack, err = newVideoTrack(s.capture, s.selectedMon, s.quality)
    if err != nil {
        return nil, fmt.Errorf("creating video track: %w", err)
    }

    // Add track to peer connection
    rtpSender, err := s.pc.AddTrack(s.videoTrack)
    if err != nil {
        return nil, fmt.Errorf("adding track: %w", err)
    }

    // Read incoming RTCP packets (required for pion)
    go func() {
        rtcpBuf := make([]byte, 1500)
        for {
            if _, _, err := rtpSender.Read(rtcpBuf); err != nil {
                return
            }
        }
    }()

    // Create data channel for input
    s.dataChannel, err = s.pc.CreateDataChannel("input", nil)
    if err != nil {
        return nil, fmt.Errorf("creating data channel: %w", err)
    }

    s.dataChannel.OnMessage(func(msg webrtc.DataChannelMessage) {
        s.handleInput(msg.Data)
    })

    // Create offer
    offer, err := s.pc.CreateOffer(nil)
    if err != nil {
        return nil, fmt.Errorf("creating offer: %w", err)
    }

    err = s.pc.SetLocalDescription(offer)
    if err != nil {
        return nil, fmt.Errorf("setting local description: %w", err)
    }

    s.running = true

    return &StartResult{
        Success: true,
        Offer: SessionDescription{
            Type: offer.Type.String(),
            SDP:  offer.SDP,
        },
        Monitors: s.capture.GetMonitors(),
    }, nil
}

func (s *webrtcSession) HandleAnswer(answer SessionDescription) error {
    return s.pc.SetRemoteDescription(webrtc.SessionDescription{
        Type: webrtc.NewSDPType(answer.Type),
        SDP:  answer.SDP,
    })
}

func (s *webrtcSession) HandleICECandidate(candidate ICECandidate) error {
    if candidate.Candidate == "" {
        return nil // End of candidates
    }

    return s.pc.AddICECandidate(webrtc.ICECandidateInit{
        Candidate:     candidate.Candidate,
        SDPMid:        &candidate.SDPMid,
        SDPMLineIndex: &candidate.SDPMLineIndex,
    })
}
```

### 4. Video Track (`track.go`)

Custom video track for screen capture:

```go
package remotedesktop

import (
    "image"
    "time"

    "github.com/pion/webrtc/v4"
    "github.com/pion/webrtc/v4/pkg/media"
)

type videoTrack struct {
    capture   *screenCapture
    monitorID int
    quality   string
    fps       int

    codec     webrtc.RTPCodecCapability
    id        string
    streamID  string

    running   bool
    stopCh    chan struct{}
    mu        sync.RWMutex
}

func newVideoTrack(capture *screenCapture, monitorID int, quality string) (*videoTrack, error) {
    settings := QualityPresets[quality]

    return &videoTrack{
        capture:   capture,
        monitorID: monitorID,
        quality:   quality,
        fps:       settings.FPS,
        codec: webrtc.RTPCodecCapability{
            MimeType:  webrtc.MimeTypeVP8,
            ClockRate: 90000,
        },
        id:       "video",
        streamID: "screen",
        stopCh:   make(chan struct{}),
        running:  true,
    }, nil
}

func (t *videoTrack) Bind(binding webrtc.TrackLocalContext) (webrtc.RTPCodecParameters, error) {
    go t.captureLoop(binding)
    return webrtc.RTPCodecParameters{RTPCodecCapability: t.codec}, nil
}

func (t *videoTrack) captureLoop(binding webrtc.TrackLocalContext) {
    ticker := time.NewTicker(time.Second / time.Duration(t.fps))
    defer ticker.Stop()

    encoder := newVP8Encoder()
    defer encoder.Close()

    for {
        select {
        case <-t.stopCh:
            return
        case <-ticker.C:
            t.mu.RLock()
            if !t.running {
                t.mu.RUnlock()
                return
            }
            monID := t.monitorID
            quality := t.quality
            t.mu.RUnlock()

            // Capture frame
            img, err := t.capture.CaptureFrame(monID)
            if err != nil {
                continue
            }

            // Scale if needed
            settings := QualityPresets[quality]
            if settings.Scale < 1.0 {
                img = scaleImage(img, settings.Scale)
            }

            // Encode to VP8
            data, err := encoder.Encode(img)
            if err != nil {
                continue
            }

            // Write to track
            if err := binding.WriteRTP(&media.Sample{
                Data:     data,
                Duration: time.Second / time.Duration(t.fps),
            }); err != nil {
                return
            }
        }
    }
}

func (t *videoTrack) SetQuality(quality string) {
    t.mu.Lock()
    defer t.mu.Unlock()

    if settings, ok := QualityPresets[quality]; ok {
        t.quality = quality
        t.fps = settings.FPS
    }
}

func (t *videoTrack) SetMonitor(monitorID int) {
    t.mu.Lock()
    defer t.mu.Unlock()
    t.monitorID = monitorID
}

func (t *videoTrack) Stop() {
    t.mu.Lock()
    t.running = false
    t.mu.Unlock()
    close(t.stopCh)
}
```

### 5. Input Control (`input.go`)

Using `github.com/go-vgo/robotgo`:

```go
package remotedesktop

import (
    "github.com/go-vgo/robotgo"
)

// Special key mappings (matching Python)
var specialKeyMap = map[string]string{
    "Enter":      "enter",
    "Escape":     "esc",
    "Backspace":  "backspace",
    "Tab":        "tab",
    "Space":      "space",
    "ArrowUp":    "up",
    "ArrowDown":  "down",
    "ArrowLeft":  "left",
    "ArrowRight": "right",
    "Control":    "ctrl",
    "Alt":        "alt",
    "Shift":      "shift",
    "Meta":       "cmd",
    "Delete":     "delete",
    "Home":       "home",
    "End":        "end",
    "PageUp":     "pageup",
    "PageDown":   "pagedown",
    "F1": "f1", "F2": "f2", "F3": "f3", "F4": "f4",
    "F5": "f5", "F6": "f6", "F7": "f7", "F8": "f8",
    "F9": "f9", "F10": "f10", "F11": "f11", "F12": "f12",
}

type inputController struct {
    monitors []Monitor
}

func newInputController(monitors []Monitor) *inputController {
    return &inputController{monitors: monitors}
}

func (c *inputController) UpdateMonitors(monitors []Monitor) {
    c.monitors = monitors
}

// HandleMouseEvent processes mouse events from the frontend
// x, y are normalized coordinates (0-1) relative to the selected monitor
func (c *inputController) HandleMouseEvent(action string, x, y float64, monitorID int, button string, delta float64) {
    // Get monitor offset
    var offsetX, offsetY int
    for _, m := range c.monitors {
        if m.ID == monitorID {
            offsetX = m.Left
            offsetY = m.Top
            x = x * float64(m.Width)
            y = y * float64(m.Height)
            break
        }
    }

    absX := offsetX + int(x)
    absY := offsetY + int(y)

    btnName := "left"
    if button == "right" || button == "2" {
        btnName = "right"
    } else if button == "middle" || button == "1" {
        btnName = "center"
    }

    switch action {
    case "move":
        robotgo.Move(absX, absY)
    case "click":
        robotgo.Move(absX, absY)
        robotgo.Click(btnName, false)
    case "dblclick":
        robotgo.Move(absX, absY)
        robotgo.Click(btnName, true)
    case "down":
        robotgo.Move(absX, absY)
        robotgo.Toggle(btnName, "down")
    case "up":
        robotgo.Toggle(btnName, "up")
    case "scroll":
        robotgo.Scroll(0, int(delta))
    }
}

// HandleKeyboardEvent processes keyboard events
func (c *inputController) HandleKeyboardEvent(action, key string) {
    actualKey := key
    if mapped, ok := specialKeyMap[key]; ok {
        actualKey = mapped
    }

    switch action {
    case "down":
        robotgo.KeyDown(actualKey)
    case "up":
        robotgo.KeyUp(actualKey)
    case "type":
        robotgo.TypeStr(key)
    }
}
```

### 6. Clipboard (`clipboard.go`)

```go
package remotedesktop

import (
    "golang.design/x/clipboard"
)

type clipboardManager struct {
    initialized bool
}

func newClipboardManager() (*clipboardManager, error) {
    if err := clipboard.Init(); err != nil {
        return nil, err
    }
    return &clipboardManager{initialized: true}, nil
}

func (c *clipboardManager) GetText() (string, error) {
    data := clipboard.Read(clipboard.FmtText)
    return string(data), nil
}

func (c *clipboardManager) SetText(text string) error {
    clipboard.Write(clipboard.FmtText, []byte(text))
    return nil
}
```

### 7. Session Manager (`remotedesktop.go`)

```go
package remotedesktop

import (
    "encoding/json"
    "fmt"
    "os"
    "runtime"
    "sync"
)

var (
    activeSessions = make(map[string]*webrtcSession)
    sessionsMu     sync.RWMutex
)

type StartResult struct {
    Success  bool               `json:"success"`
    Error    string             `json:"error,omitempty"`
    Offer    SessionDescription `json:"offer,omitempty"`
    Monitors []Monitor          `json:"monitors,omitempty"`
}

// HasDisplayServer checks if a display server is available
func HasDisplayServer() bool {
    switch runtime.GOOS {
    case "darwin", "windows":
        return true
    case "linux":
        // Check for Wayland
        if os.Getenv("WAYLAND_DISPLAY") != "" {
            return true
        }
        // Check for X11
        if os.Getenv("DISPLAY") != "" {
            return true
        }
        return false
    default:
        return false
    }
}

// CheckDependencies returns availability of remote desktop features
func CheckDependencies() map[string]bool {
    displayAvailable := HasDisplayServer()

    return map[string]bool{
        "screen_capture":  true, // kbinani/screenshot is always available
        "webrtc":          true, // pion/webrtc is always available
        "input_control":   true, // robotgo available on all platforms
        "clipboard":       true, // golang.design/x/clipboard available
        "display_server":  displayAvailable,
        "all_required":    displayAvailable,
        "full_control":    true,
    }
}

// GetMonitors returns list of available monitors
func GetMonitors() map[string]interface{} {
    if !HasDisplayServer() {
        return map[string]interface{}{
            "success": false,
            "error":   "No display server available",
            "monitors": []Monitor{},
        }
    }

    capture, err := NewScreenCapture()
    if err != nil {
        return map[string]interface{}{
            "success": false,
            "error":   err.Error(),
            "monitors": []Monitor{},
        }
    }

    return map[string]interface{}{
        "success":  true,
        "monitors": capture.GetMonitors(),
    }
}

// StartSession starts a new remote desktop session
func StartSession(sessionID string, sendCallback func([]byte) error) *StartResult {
    if !HasDisplayServer() {
        return &StartResult{
            Success: false,
            Error:   "No display server (X11/Wayland) available",
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
    capture, err := NewScreenCapture()
    if err != nil {
        return &StartResult{
            Success: false,
            Error:   fmt.Sprintf("screen capture: %v", err),
        }
    }

    session := &webrtcSession{
        sessionID:    sessionID,
        sendCallback: sendCallback,
        capture:      capture,
        input:        newInputController(capture.GetMonitors()),
        selectedMon:  1,
        quality:      "balanced",
    }

    result, err := session.Start()
    if err != nil {
        return &StartResult{
            Success: false,
            Error:   err.Error(),
        }
    }

    activeSessions[sessionID] = session
    return result
}

// StopSession stops a remote desktop session
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

// HandleAnswer handles WebRTC answer from frontend
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

// HandleICECandidate handles ICE candidate from frontend
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
```

### 8. Handler Integration (`handler/remotedesktop.go`)

```go
package handler

import (
    "context"
    "encoding/json"

    "github.com/slimrmm/slimrmm-agent/internal/remotedesktop"
)

func (h *Handler) registerRemoteDesktopHandlers() {
    h.handlers["start_remote_desktop"] = h.handleStartRemoteDesktop
    h.handlers["stop_remote_desktop"] = h.handleStopRemoteDesktop
    h.handlers["webrtc_answer"] = h.handleWebRTCAnswer
    h.handlers["ice_candidate"] = h.handleICECandidate
    h.handlers["get_monitors"] = h.handleGetMonitors
    h.handlers["remote_control"] = h.handleRemoteControl
}

func (h *Handler) handleStartRemoteDesktop(ctx context.Context, data json.RawMessage) (interface{}, error) {
    var req struct {
        SessionID string `json:"session_id"`
    }
    json.Unmarshal(data, &req)

    if req.SessionID == "" {
        req.SessionID = h.cfg.GetUUID() // Use agent UUID as session ID
    }

    sendCallback := func(msg []byte) error {
        h.SendRaw(json.RawMessage(msg))
        return nil
    }

    result := remotedesktop.StartSession(req.SessionID, sendCallback)

    // Send offer to frontend via WebSocket
    if result.Success {
        h.SendRaw(map[string]interface{}{
            "action":     "webrtc_offer",
            "session_id": req.SessionID,
            "offer":      result.Offer,
            "monitors":   result.Monitors,
        })
    }

    return result, nil
}

func (h *Handler) handleStopRemoteDesktop(ctx context.Context, data json.RawMessage) (interface{}, error) {
    var req struct {
        SessionID string `json:"session_id"`
    }
    json.Unmarshal(data, &req)

    if req.SessionID == "" {
        req.SessionID = h.cfg.GetUUID()
    }

    return remotedesktop.StopSession(req.SessionID), nil
}

func (h *Handler) handleWebRTCAnswer(ctx context.Context, data json.RawMessage) (interface{}, error) {
    var req struct {
        SessionID string                       `json:"session_id"`
        Answer    remotedesktop.SessionDescription `json:"answer"`
    }
    if err := json.Unmarshal(data, &req); err != nil {
        return nil, err
    }

    if req.SessionID == "" {
        req.SessionID = h.cfg.GetUUID()
    }

    return remotedesktop.HandleAnswer(req.SessionID, req.Answer), nil
}

func (h *Handler) handleICECandidate(ctx context.Context, data json.RawMessage) (interface{}, error) {
    var req struct {
        SessionID string                     `json:"session_id"`
        Candidate remotedesktop.ICECandidate `json:"candidate"`
    }
    if err := json.Unmarshal(data, &req); err != nil {
        return nil, err
    }

    if req.SessionID == "" {
        req.SessionID = h.cfg.GetUUID()
    }

    return remotedesktop.HandleICECandidate(req.SessionID, req.Candidate), nil
}

func (h *Handler) handleGetMonitors(ctx context.Context, data json.RawMessage) (interface{}, error) {
    result := remotedesktop.GetMonitors()

    // Also send via WebSocket for frontend compatibility
    h.SendRaw(map[string]interface{}{
        "action":   "monitors",
        "monitors": result["monitors"],
    })

    return result, nil
}

func (h *Handler) handleRemoteControl(ctx context.Context, data json.RawMessage) (interface{}, error) {
    var req struct {
        Type   string  `json:"type"`
        X      float64 `json:"x"`
        Y      float64 `json:"y"`
        Button string  `json:"button"`
        Delta  float64 `json:"delta"`
        DX     float64 `json:"dx"`
        DY     float64 `json:"dy"`
        Key    string  `json:"key"`
        Code   string  `json:"code"`
    }
    if err := json.Unmarshal(data, &req); err != nil {
        return nil, err
    }

    // Forward to active session's input controller
    // Implementation depends on how input is routed

    return map[string]string{"status": "ok"}, nil
}
```

---

## Video Encoding Strategy

### Option A: Use pion/mediadevices (Recommended)
Uses hardware encoding when available:

```go
import "github.com/pion/mediadevices"
import "github.com/pion/mediadevices/pkg/codec/vpx"

// Configure VP8 encoder
vpxParams, _ := vpx.NewVP8Params()
vpxParams.BitRate = 1_000_000 // 1 Mbps

codecSelector := mediadevices.NewCodecSelector(
    mediadevices.WithVideoEncoders(&vpxParams),
)
```

### Option B: Manual VP8 with libvpx
Direct CGO bindings to libvpx for maximum control:

```go
// #cgo pkg-config: vpx
// #include <vpx/vpx_encoder.h>
// #include <vpx/vp8cx.h>
import "C"
```

### Option C: Use x264 for H.264
Better compression but requires hardware support on receiver:

```go
import "github.com/pion/mediadevices/pkg/codec/x264"
```

**Recommendation**: Start with pion/mediadevices + VP8 for broadest compatibility.

---

## Build Tags and Platform Support

### go.mod additions

```go
require (
    github.com/pion/webrtc/v4 v4.0.0
    github.com/kbinani/screenshot v0.0.0-20230812160703-b9a4c069f3db
    github.com/go-vgo/robotgo v0.100.10
    golang.design/x/clipboard v0.7.0
    github.com/pion/mediadevices v0.6.0
)
```

### Platform-specific build considerations

**Linux**: Requires X11 development libraries
```bash
# Debian/Ubuntu
apt-get install libx11-dev libxtst-dev libxcursor-dev

# RHEL/CentOS
yum install libX11-devel libXtst-devel libXcursor-devel
```

**macOS**: Requires accessibility permissions for input control

**Windows**: Works out of the box with robotgo

---

## Testing Plan

1. **Unit Tests**
   - Screen capture on all platforms
   - Image scaling algorithms
   - Key mapping accuracy
   - Session lifecycle

2. **Integration Tests**
   - WebRTC offer/answer exchange
   - ICE candidate handling
   - Video streaming latency
   - Input event round-trip

3. **Manual Testing**
   - Multi-monitor switching
   - Quality preset changes
   - Keyboard special keys
   - Mouse drag operations
   - Clipboard sync

---

## Implementation Order

1. **Phase 1: Core Infrastructure**
   - [ ] Create `internal/remotedesktop` package structure
   - [ ] Implement `capture.go` with kbinani/screenshot
   - [ ] Implement basic `webrtc.go` with pion/webrtc
   - [ ] Add handler registrations

2. **Phase 2: Video Streaming**
   - [ ] Implement `track.go` video track
   - [ ] Add VP8 encoding
   - [ ] Implement quality presets
   - [ ] Add frame rate control

3. **Phase 3: Input Control**
   - [ ] Implement `input.go` with robotgo
   - [ ] Add keyboard mapping
   - [ ] Add mouse event handling
   - [ ] Test on all platforms

4. **Phase 4: Polish**
   - [ ] Add clipboard sync
   - [ ] Implement multi-monitor support
   - [ ] Add proper error handling
   - [ ] Performance optimization

5. **Phase 5: Testing**
   - [ ] Write unit tests
   - [ ] Manual testing on Windows
   - [ ] Manual testing on macOS
   - [ ] Manual testing on Linux

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| robotgo CGO compilation issues | Provide pre-built binaries, document build requirements |
| VP8 encoding performance | Use hardware acceleration when available, fallback to software |
| macOS accessibility permissions | Document in installation guide, detect and prompt user |
| Linux without X11/Wayland | Graceful degradation, clear error messages |
| WebRTC NAT traversal | Use STUN servers, document TURN setup for restrictive networks |

---

## Estimated Implementation Effort

| Component | Complexity | Estimated Time |
|-----------|------------|----------------|
| Screen capture | Low | 2-3 hours |
| WebRTC setup | Medium | 4-6 hours |
| Video encoding | High | 6-8 hours |
| Input control | Medium | 4-5 hours |
| Handler integration | Low | 2-3 hours |
| Testing & debugging | High | 8-12 hours |
| **Total** | | **26-37 hours** |
