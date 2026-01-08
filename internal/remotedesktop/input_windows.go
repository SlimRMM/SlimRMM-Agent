//go:build cgo && windows

package remotedesktop

import (
	"log/slog"
	"sync"

	"github.com/go-vgo/robotgo"
	"github.com/slimrmm/slimrmm-agent/internal/helper"
)

// InputController handles mouse and keyboard input on Windows.
// It routes input through the helper process when running as a service.
type InputController struct {
	monitors     []Monitor
	logger       *slog.Logger
	mu           sync.RWMutex
	helperClient *helper.Client
	useHelper    bool
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

// SetHelper configures the input controller to use the helper process.
func (ic *InputController) SetHelper(client *helper.Client, useHelper bool) {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	ic.helperClient = client
	ic.useHelper = useHelper
}

// UpdateMonitors updates the monitor list.
func (ic *InputController) UpdateMonitors(monitors []Monitor) {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	ic.monitors = monitors
}

// HandleMouseEvent processes mouse events from the frontend.
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
	useHelper := ic.useHelper
	helperClient := ic.helperClient
	ic.mu.RUnlock()

	if monitor == nil {
		ic.logger.Warn("monitor not found", "monitor_id", monitorID)
		return
	}

	// Convert normalized coordinates (0-1) to absolute screen coordinates
	absX := monitor.Left + int(event.X*float64(monitor.Width))
	absY := monitor.Top + int(event.Y*float64(monitor.Height))

	// Determine button (0=left, 1=middle, 2=right)
	button := 0
	switch event.Button {
	case "right", "2":
		button = 2
	case "middle", "1":
		button = 1
	}

	ic.logger.Debug("mouse event",
		"action", event.Action,
		"x", absX,
		"y", absY,
		"button", button,
		"useHelper", useHelper,
	)

	if useHelper && helperClient != nil {
		ic.handleMouseViaHelper(event.Action, absX, absY, button, event, helperClient)
	} else {
		ic.handleMouseDirectly(event.Action, absX, absY, button, event)
	}
}

// handleMouseViaHelper routes mouse events through the helper process
func (ic *InputController) handleMouseViaHelper(action string, absX, absY, button int, event InputEvent, client *helper.Client) {
	switch action {
	case "move":
		client.SendInput(helper.InputEvent{Type: "mousemove", X: absX, Y: absY})

	case "click":
		client.SendInput(helper.InputEvent{Type: "mousemove", X: absX, Y: absY})
		client.SendInput(helper.InputEvent{Type: "mousedown", Button: button})
		client.SendInput(helper.InputEvent{Type: "mouseup", Button: button})

	case "dblclick":
		client.SendInput(helper.InputEvent{Type: "mousemove", X: absX, Y: absY})
		client.SendInput(helper.InputEvent{Type: "mousedown", Button: button})
		client.SendInput(helper.InputEvent{Type: "mouseup", Button: button})
		client.SendInput(helper.InputEvent{Type: "mousedown", Button: button})
		client.SendInput(helper.InputEvent{Type: "mouseup", Button: button})

	case "down":
		client.SendInput(helper.InputEvent{Type: "mousemove", X: absX, Y: absY})
		client.SendInput(helper.InputEvent{Type: "mousedown", Button: button})

	case "up":
		client.SendInput(helper.InputEvent{Type: "mouseup", Button: button})

	case "scroll":
		dy := int(event.DeltaY)
		if dy == 0 {
			dy = int(event.Delta)
		}
		client.SendInput(helper.InputEvent{Type: "scroll", DeltaY: -dy / 120})
	}
}

// handleMouseDirectly handles mouse events using robotgo
func (ic *InputController) handleMouseDirectly(action string, absX, absY, button int, event InputEvent) {
	btnName := "left"
	switch button {
	case 1:
		btnName = "center"
	case 2:
		btnName = "right"
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
		dy := int(event.DeltaY)
		if dy == 0 {
			dy = int(event.Delta)
		}
		robotgo.Scroll(0, -dy/120)
	}
}

// HandleKeyboardEvent processes keyboard events from the frontend.
func (ic *InputController) HandleKeyboardEvent(event InputEvent) {
	ic.mu.RLock()
	useHelper := ic.useHelper
	helperClient := ic.helperClient
	ic.mu.RUnlock()

	ic.logger.Debug("keyboard event",
		"action", event.Action,
		"key", event.Key,
		"useHelper", useHelper,
	)

	if useHelper && helperClient != nil {
		ic.handleKeyboardViaHelper(event, helperClient)
	} else {
		ic.handleKeyboardDirectly(event)
	}
}

// handleKeyboardViaHelper routes keyboard events through the helper
func (ic *InputController) handleKeyboardViaHelper(event InputEvent, client *helper.Client) {
	switch event.Action {
	case "down":
		client.SendInput(helper.InputEvent{Type: "keydown", Key: event.Key})

	case "up":
		client.SendInput(helper.InputEvent{Type: "keyup", Key: event.Key})

	case "type":
		// Type each character
		for _, c := range event.Key {
			key := string(c)
			client.SendInput(helper.InputEvent{Type: "keydown", Key: key})
			client.SendInput(helper.InputEvent{Type: "keyup", Key: key})
		}
	}
}

// handleKeyboardDirectly handles keyboard events using robotgo
func (ic *InputController) handleKeyboardDirectly(event InputEvent) {
	key := MapKey(event.Key)

	switch event.Action {
	case "down":
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
	ic.mu.RLock()
	useHelper := ic.useHelper
	helperClient := ic.helperClient
	ic.mu.RUnlock()

	if useHelper && helperClient != nil {
		helperClient.SendInput(helper.InputEvent{Type: "mousemove", X: x, Y: y})
	} else {
		robotgo.Move(x, y)
	}
}

// MouseClick performs a mouse click at the current position.
func (ic *InputController) MouseClick(button MouseButton) {
	ic.mu.RLock()
	useHelper := ic.useHelper
	helperClient := ic.helperClient
	ic.mu.RUnlock()

	btn := 0
	btnName := "left"
	switch button {
	case MouseButtonMiddle:
		btn = 1
		btnName = "center"
	case MouseButtonRight:
		btn = 2
		btnName = "right"
	}

	if useHelper && helperClient != nil {
		helperClient.SendInput(helper.InputEvent{Type: "mousedown", Button: btn})
		helperClient.SendInput(helper.InputEvent{Type: "mouseup", Button: btn})
	} else {
		robotgo.Click(btnName, false)
	}
}

// MouseDoubleClick performs a double click at the current position.
func (ic *InputController) MouseDoubleClick(button MouseButton) {
	ic.mu.RLock()
	useHelper := ic.useHelper
	helperClient := ic.helperClient
	ic.mu.RUnlock()

	btn := 0
	btnName := "left"
	switch button {
	case MouseButtonMiddle:
		btn = 1
		btnName = "center"
	case MouseButtonRight:
		btn = 2
		btnName = "right"
	}

	if useHelper && helperClient != nil {
		helperClient.SendInput(helper.InputEvent{Type: "mousedown", Button: btn})
		helperClient.SendInput(helper.InputEvent{Type: "mouseup", Button: btn})
		helperClient.SendInput(helper.InputEvent{Type: "mousedown", Button: btn})
		helperClient.SendInput(helper.InputEvent{Type: "mouseup", Button: btn})
	} else {
		robotgo.Click(btnName, true)
	}
}

// MouseDown presses a mouse button.
func (ic *InputController) MouseDown(button MouseButton) {
	ic.mu.RLock()
	useHelper := ic.useHelper
	helperClient := ic.helperClient
	ic.mu.RUnlock()

	btn := 0
	btnName := "left"
	switch button {
	case MouseButtonMiddle:
		btn = 1
		btnName = "center"
	case MouseButtonRight:
		btn = 2
		btnName = "right"
	}

	if useHelper && helperClient != nil {
		helperClient.SendInput(helper.InputEvent{Type: "mousedown", Button: btn})
	} else {
		robotgo.Toggle(btnName, "down")
	}
}

// MouseUp releases a mouse button.
func (ic *InputController) MouseUp(button MouseButton) {
	ic.mu.RLock()
	useHelper := ic.useHelper
	helperClient := ic.helperClient
	ic.mu.RUnlock()

	btn := 0
	btnName := "left"
	switch button {
	case MouseButtonMiddle:
		btn = 1
		btnName = "center"
	case MouseButtonRight:
		btn = 2
		btnName = "right"
	}

	if useHelper && helperClient != nil {
		helperClient.SendInput(helper.InputEvent{Type: "mouseup", Button: btn})
	} else {
		robotgo.Toggle(btnName, "up")
	}
}

// MouseScroll performs a scroll operation.
func (ic *InputController) MouseScroll(dx, dy int) {
	ic.mu.RLock()
	useHelper := ic.useHelper
	helperClient := ic.helperClient
	ic.mu.RUnlock()

	if useHelper && helperClient != nil {
		if dy != 0 {
			helperClient.SendInput(helper.InputEvent{Type: "scroll", DeltaY: dy})
		}
		if dx != 0 {
			helperClient.SendInput(helper.InputEvent{Type: "scroll", DeltaX: dx})
		}
	} else {
		robotgo.Scroll(dx, dy)
	}
}

// KeyDown presses a key.
func (ic *InputController) KeyDown(key string) {
	ic.mu.RLock()
	useHelper := ic.useHelper
	helperClient := ic.helperClient
	ic.mu.RUnlock()

	if useHelper && helperClient != nil {
		helperClient.SendInput(helper.InputEvent{Type: "keydown", Key: key})
	} else {
		robotgo.KeyDown(MapKey(key))
	}
}

// KeyUp releases a key.
func (ic *InputController) KeyUp(key string) {
	ic.mu.RLock()
	useHelper := ic.useHelper
	helperClient := ic.helperClient
	ic.mu.RUnlock()

	if useHelper && helperClient != nil {
		helperClient.SendInput(helper.InputEvent{Type: "keyup", Key: key})
	} else {
		robotgo.KeyUp(MapKey(key))
	}
}

// TypeString types a string.
func (ic *InputController) TypeString(s string) {
	ic.mu.RLock()
	useHelper := ic.useHelper
	helperClient := ic.helperClient
	ic.mu.RUnlock()

	if useHelper && helperClient != nil {
		for _, c := range s {
			key := string(c)
			helperClient.SendInput(helper.InputEvent{Type: "keydown", Key: key})
			helperClient.SendInput(helper.InputEvent{Type: "keyup", Key: key})
		}
	} else {
		robotgo.TypeStr(s)
	}
}

// GetMousePosition returns the current mouse position.
func (ic *InputController) GetMousePosition() (x, y int) {
	return robotgo.Location()
}
