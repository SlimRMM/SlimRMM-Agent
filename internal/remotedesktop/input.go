//go:build cgo

package remotedesktop

import (
	"log/slog"
	"sync"

	"github.com/go-vgo/robotgo"
)

// InputController handles mouse and keyboard input.
type InputController struct {
	monitors []Monitor
	logger   *slog.Logger
	mu       sync.RWMutex
}

// NewInputController creates a new input controller.
func NewInputController(monitors []Monitor, logger *slog.Logger) *InputController {
	if logger == nil {
		logger = slog.Default()
	}

	return &InputController{
		monitors: monitors,
		logger:   logger,
	}
}

// UpdateMonitors updates the monitor list.
func (ic *InputController) UpdateMonitors(monitors []Monitor) {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	ic.monitors = monitors
}

// HandleMouseEvent processes mouse events from the frontend.
// x, y are normalized coordinates (0-1) relative to the monitor dimensions.
func (ic *InputController) HandleMouseEvent(event InputEvent, monitorID int) {
	ic.mu.RLock()
	var monitor *Monitor
	for _, m := range ic.monitors {
		if m.ID == monitorID {
			mon := m
			monitor = &mon
			break
		}
	}
	ic.mu.RUnlock()

	if monitor == nil {
		ic.logger.Warn("monitor not found", "monitor_id", monitorID)
		return
	}

	// Convert normalized coordinates (0-1) to absolute screen coordinates
	absX := monitor.Left + int(event.X*float64(monitor.Width))
	absY := monitor.Top + int(event.Y*float64(monitor.Height))

	// Determine button
	button := "left"
	switch event.Button {
	case "right", "2":
		button = "right"
	case "middle", "1":
		button = "center"
	}

	ic.logger.Debug("mouse event",
		"action", event.Action,
		"x", absX,
		"y", absY,
		"button", button,
	)

	switch event.Action {
	case "move":
		robotgo.Move(absX, absY)

	case "click":
		robotgo.Move(absX, absY)
		robotgo.Click(button, false)

	case "dblclick":
		robotgo.Move(absX, absY)
		robotgo.Click(button, true)

	case "down":
		robotgo.Move(absX, absY)
		robotgo.Toggle(button, "down")

	case "up":
		robotgo.Toggle(button, "up")

	case "scroll":
		// deltaY: positive = scroll up, negative = scroll down
		dy := int(event.DeltaY)
		if dy == 0 {
			dy = int(event.Delta)
		}
		// robotgo.Scroll: positive = scroll down, so we negate
		robotgo.Scroll(0, -dy/120) // Normalize wheel delta
	}
}

// HandleKeyboardEvent processes keyboard events from the frontend.
func (ic *InputController) HandleKeyboardEvent(event InputEvent) {
	key := MapKey(event.Key)

	ic.logger.Debug("keyboard event",
		"action", event.Action,
		"key", event.Key,
		"mapped_key", key,
	)

	switch event.Action {
	case "down":
		// Handle single character keys differently
		if len(event.Key) == 1 {
			robotgo.KeyDown(event.Key)
		} else {
			robotgo.KeyDown(key)
		}

	case "up":
		if len(event.Key) == 1 {
			robotgo.KeyUp(event.Key)
		} else {
			robotgo.KeyUp(key)
		}

	case "type":
		robotgo.TypeStr(event.Key)
	}
}

// MoveMouse moves the mouse to absolute coordinates.
func (ic *InputController) MoveMouse(x, y int) {
	robotgo.Move(x, y)
}

// MouseClick performs a mouse click at the current position.
func (ic *InputController) MouseClick(button MouseButton) {
	btnName := "left"
	switch button {
	case MouseButtonMiddle:
		btnName = "center"
	case MouseButtonRight:
		btnName = "right"
	}
	robotgo.Click(btnName, false)
}

// MouseDoubleClick performs a double click at the current position.
func (ic *InputController) MouseDoubleClick(button MouseButton) {
	btnName := "left"
	switch button {
	case MouseButtonMiddle:
		btnName = "center"
	case MouseButtonRight:
		btnName = "right"
	}
	robotgo.Click(btnName, true)
}

// MouseDown presses a mouse button.
func (ic *InputController) MouseDown(button MouseButton) {
	btnName := "left"
	switch button {
	case MouseButtonMiddle:
		btnName = "center"
	case MouseButtonRight:
		btnName = "right"
	}
	robotgo.Toggle(btnName, "down")
}

// MouseUp releases a mouse button.
func (ic *InputController) MouseUp(button MouseButton) {
	btnName := "left"
	switch button {
	case MouseButtonMiddle:
		btnName = "center"
	case MouseButtonRight:
		btnName = "right"
	}
	robotgo.Toggle(btnName, "up")
}

// MouseScroll performs a scroll operation.
func (ic *InputController) MouseScroll(dx, dy int) {
	robotgo.Scroll(dx, dy)
}

// KeyDown presses a key.
func (ic *InputController) KeyDown(key string) {
	robotgo.KeyDown(MapKey(key))
}

// KeyUp releases a key.
func (ic *InputController) KeyUp(key string) {
	robotgo.KeyUp(MapKey(key))
}

// TypeString types a string.
func (ic *InputController) TypeString(s string) {
	robotgo.TypeStr(s)
}

// GetMousePosition returns the current mouse position.
func (ic *InputController) GetMousePosition() (x, y int) {
	return robotgo.Location()
}
