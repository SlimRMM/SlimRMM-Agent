package remotedesktop

import (
	"testing"
)

func TestMonitorStruct(t *testing.T) {
	monitor := Monitor{
		ID:      1,
		Left:    0,
		Top:     0,
		Width:   1920,
		Height:  1080,
		Name:    "Primary Display",
		Primary: true,
	}

	if monitor.ID != 1 {
		t.Errorf("ID = %d, want 1", monitor.ID)
	}
	if monitor.Left != 0 {
		t.Errorf("Left = %d, want 0", monitor.Left)
	}
	if monitor.Top != 0 {
		t.Errorf("Top = %d, want 0", monitor.Top)
	}
	if monitor.Width != 1920 {
		t.Errorf("Width = %d, want 1920", monitor.Width)
	}
	if monitor.Height != 1080 {
		t.Errorf("Height = %d, want 1080", monitor.Height)
	}
	if monitor.Name != "Primary Display" {
		t.Errorf("Name = %s, want 'Primary Display'", monitor.Name)
	}
	if !monitor.Primary {
		t.Error("Primary should be true")
	}
}

func TestStartResultStruct(t *testing.T) {
	monitors := []Monitor{
		{ID: 1, Width: 1920, Height: 1080, Primary: true},
		{ID: 2, Width: 1920, Height: 1080, Primary: false},
	}

	result := StartResult{
		Success:  true,
		Error:    "",
		Monitors: monitors,
	}

	if !result.Success {
		t.Error("Success should be true")
	}
	if result.Error != "" {
		t.Error("Error should be empty")
	}
	if len(result.Monitors) != 2 {
		t.Errorf("len(Monitors) = %d, want 2", len(result.Monitors))
	}
}

func TestStartResultWithError(t *testing.T) {
	result := StartResult{
		Success:  false,
		Error:    "No display server available",
		Monitors: nil,
	}

	if result.Success {
		t.Error("Success should be false")
	}
	if result.Error != "No display server available" {
		t.Errorf("Error = %s, want 'No display server available'", result.Error)
	}
	if result.Monitors != nil {
		t.Error("Monitors should be nil")
	}
}

func TestQualitySettings(t *testing.T) {
	settings := QualitySettings{
		Scale:       0.85,
		FPS:         30,
		JPEGQuality: 80,
	}

	if settings.Scale != 0.85 {
		t.Errorf("Scale = %f, want 0.85", settings.Scale)
	}
	if settings.FPS != 30 {
		t.Errorf("FPS = %d, want 30", settings.FPS)
	}
	if settings.JPEGQuality != 80 {
		t.Errorf("JPEGQuality = %d, want 80", settings.JPEGQuality)
	}
}

func TestQualityPresets(t *testing.T) {
	presets := []struct {
		name        string
		scale       float64
		fps         int
		jpegQuality int
	}{
		{"low", 0.75, 15, 70},
		{"balanced", 0.85, 30, 80},
		{"high", 1.0, 60, 90},
	}

	for _, p := range presets {
		t.Run(p.name, func(t *testing.T) {
			preset, ok := QualityPresets[p.name]
			if !ok {
				t.Fatalf("preset %s not found", p.name)
			}
			if preset.Scale != p.scale {
				t.Errorf("Scale = %f, want %f", preset.Scale, p.scale)
			}
			if preset.FPS != p.fps {
				t.Errorf("FPS = %d, want %d", preset.FPS, p.fps)
			}
			if preset.JPEGQuality != p.jpegQuality {
				t.Errorf("JPEGQuality = %d, want %d", preset.JPEGQuality, p.jpegQuality)
			}
		})
	}
}

func TestMouseButtonConstants(t *testing.T) {
	if MouseButtonLeft != 0 {
		t.Errorf("MouseButtonLeft = %d, want 0", MouseButtonLeft)
	}
	if MouseButtonMiddle != 1 {
		t.Errorf("MouseButtonMiddle = %d, want 1", MouseButtonMiddle)
	}
	if MouseButtonRight != 2 {
		t.Errorf("MouseButtonRight = %d, want 2", MouseButtonRight)
	}
}

func TestInputEventStruct(t *testing.T) {
	event := InputEvent{
		Type:      "mouse",
		Action:    "move",
		X:         100.5,
		Y:         200.5,
		Button:    "left",
		Delta:     -10.0,
		DeltaX:    5.0,
		DeltaY:    -3.0,
		Key:       "a",
		Code:      "KeyA",
		MonitorID: 1,
		Quality:   "balanced",
		Text:      "hello",
	}

	if event.Type != "mouse" {
		t.Errorf("Type = %s, want mouse", event.Type)
	}
	if event.Action != "move" {
		t.Errorf("Action = %s, want move", event.Action)
	}
	if event.X != 100.5 {
		t.Errorf("X = %f, want 100.5", event.X)
	}
	if event.Y != 200.5 {
		t.Errorf("Y = %f, want 200.5", event.Y)
	}
	if event.Button != "left" {
		t.Errorf("Button = %s, want left", event.Button)
	}
	if event.Delta != -10.0 {
		t.Errorf("Delta = %f, want -10.0", event.Delta)
	}
	if event.DeltaX != 5.0 {
		t.Errorf("DeltaX = %f, want 5.0", event.DeltaX)
	}
	if event.DeltaY != -3.0 {
		t.Errorf("DeltaY = %f, want -3.0", event.DeltaY)
	}
	if event.Key != "a" {
		t.Errorf("Key = %s, want a", event.Key)
	}
	if event.Code != "KeyA" {
		t.Errorf("Code = %s, want KeyA", event.Code)
	}
	if event.MonitorID != 1 {
		t.Errorf("MonitorID = %d, want 1", event.MonitorID)
	}
	if event.Quality != "balanced" {
		t.Errorf("Quality = %s, want balanced", event.Quality)
	}
	if event.Text != "hello" {
		t.Errorf("Text = %s, want hello", event.Text)
	}
}

func TestSendCallbackType(t *testing.T) {
	var called bool
	var capturedMsg []byte

	cb := SendCallback(func(msg []byte) error {
		called = true
		capturedMsg = msg
		return nil
	})

	testMsg := []byte("test message")
	err := cb(testMsg)

	if err != nil {
		t.Errorf("callback returned error: %v", err)
	}
	if !called {
		t.Error("callback was not called")
	}
	if string(capturedMsg) != "test message" {
		t.Errorf("capturedMsg = %s, want 'test message'", string(capturedMsg))
	}
}

func TestSpecialKeyMap(t *testing.T) {
	keys := map[string]string{
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

	for jsKey, expectedRobotgo := range keys {
		t.Run(jsKey, func(t *testing.T) {
			actual, ok := specialKeyMap[jsKey]
			if !ok {
				t.Fatalf("key %s not found in specialKeyMap", jsKey)
			}
			if actual != expectedRobotgo {
				t.Errorf("specialKeyMap[%s] = %s, want %s", jsKey, actual, expectedRobotgo)
			}
		})
	}
}

func TestMapKey(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Enter", "enter"},
		{"Escape", "escape"},
		{"ArrowUp", "up"},
		{"Control", "ctrl"},
		{"Meta", "cmd"},
		{"F1", "f1"},
		{"F12", "f12"},
		// Non-special keys should pass through unchanged
		{"a", "a"},
		{"A", "A"},
		{"1", "1"},
		{"!", "!"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := MapKey(tt.input)
			if result != tt.expected {
				t.Errorf("MapKey(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestQualityPresetsHaveAllSettings(t *testing.T) {
	// Verify all presets have valid values
	for name, preset := range QualityPresets {
		if preset.Scale <= 0 || preset.Scale > 1.0 {
			t.Errorf("preset %s has invalid Scale: %f", name, preset.Scale)
		}
		if preset.FPS <= 0 || preset.FPS > 120 {
			t.Errorf("preset %s has invalid FPS: %d", name, preset.FPS)
		}
		if preset.JPEGQuality <= 0 || preset.JPEGQuality > 100 {
			t.Errorf("preset %s has invalid JPEGQuality: %d", name, preset.JPEGQuality)
		}
	}

	// Verify low < balanced < high for quality
	low := QualityPresets["low"]
	balanced := QualityPresets["balanced"]
	high := QualityPresets["high"]

	if low.FPS >= balanced.FPS {
		t.Error("low FPS should be less than balanced FPS")
	}
	if balanced.FPS >= high.FPS {
		t.Error("balanced FPS should be less than high FPS")
	}
	if low.JPEGQuality >= balanced.JPEGQuality {
		t.Error("low JPEGQuality should be less than balanced JPEGQuality")
	}
	if balanced.JPEGQuality >= high.JPEGQuality {
		t.Error("balanced JPEGQuality should be less than high JPEGQuality")
	}
}

func TestMonitorWithNegativeCoordinates(t *testing.T) {
	// Monitors can have negative coordinates (multi-monitor setups)
	monitor := Monitor{
		ID:      2,
		Left:    -1920,
		Top:     0,
		Width:   1920,
		Height:  1080,
		Name:    "Secondary Display",
		Primary: false,
	}

	if monitor.Left != -1920 {
		t.Errorf("Left = %d, want -1920", monitor.Left)
	}
	if monitor.Primary {
		t.Error("Primary should be false")
	}
}

func TestInputEventDefaultValues(t *testing.T) {
	event := InputEvent{}

	if event.Type != "" {
		t.Error("default Type should be empty")
	}
	if event.X != 0 {
		t.Error("default X should be 0")
	}
	if event.Y != 0 {
		t.Error("default Y should be 0")
	}
	if event.MonitorID != 0 {
		t.Error("default MonitorID should be 0")
	}
}
