// Package remotedesktop provides WebSocket-based screen sharing and remote control.
package remotedesktop

// Monitor represents display information.
type Monitor struct {
	ID      int    `json:"id"`
	Left    int    `json:"left"`
	Top     int    `json:"top"`
	Width   int    `json:"width"`
	Height  int    `json:"height"`
	Name    string `json:"name"`
	Primary bool   `json:"primary"`
}

// StartResult contains the result of starting a remote desktop session.
type StartResult struct {
	Success  bool      `json:"success"`
	Error    string    `json:"error,omitempty"`
	Monitors []Monitor `json:"monitors,omitempty"`
}

// QualitySettings defines video quality parameters.
type QualitySettings struct {
	Scale       float64
	FPS         int
	JPEGQuality int
}

// QualityPresets maps quality names to settings.
// Improved presets: "low" now uses 0.75x scale instead of 0.5x for better readability
var QualityPresets = map[string]QualitySettings{
	"low":      {Scale: 0.75, FPS: 15, JPEGQuality: 60},
	"balanced": {Scale: 0.85, FPS: 30, JPEGQuality: 80},
	"high":     {Scale: 1.0, FPS: 60, JPEGQuality: 90},
}

// MouseButton represents mouse button types.
type MouseButton int

const (
	MouseButtonLeft MouseButton = iota
	MouseButtonMiddle
	MouseButtonRight
)

// InputEvent represents an input event from the frontend.
type InputEvent struct {
	Type      string  `json:"type"`
	Action    string  `json:"action"`
	X         float64 `json:"x"`
	Y         float64 `json:"y"`
	Button    string  `json:"button"`
	Delta     float64 `json:"delta"`
	DeltaX    float64 `json:"dx"`
	DeltaY    float64 `json:"dy"`
	Key       string  `json:"key"`
	Code      string  `json:"code"`
	MonitorID int     `json:"monitor_id"`
	Quality   string  `json:"quality"`
	Text      string  `json:"text"`
}

// SendCallback is the function type for sending messages to the frontend.
type SendCallback func(msg []byte) error

// specialKeyMap maps JavaScript key names to robotgo key names.
var specialKeyMap = map[string]string{
	"Enter":      "enter",
	"Escape":     "escape",
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
	"Insert":     "insert",
	"CapsLock":   "capslock",
	"NumLock":    "numlock",
	"F1":         "f1",
	"F2":         "f2",
	"F3":         "f3",
	"F4":         "f4",
	"F5":         "f5",
	"F6":         "f6",
	"F7":         "f7",
	"F8":         "f8",
	"F9":         "f9",
	"F10":        "f10",
	"F11":        "f11",
	"F12":        "f12",
}

// MapKey maps a JavaScript key name to a robotgo key name.
func MapKey(key string) string {
	if mapped, ok := specialKeyMap[key]; ok {
		return mapped
	}
	return key
}
