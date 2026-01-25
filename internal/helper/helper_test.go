package helper

import (
	"testing"
)

func TestNewClient(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Error("NewClient should return a non-nil client")
	}
}

func TestClientStart(t *testing.T) {
	client := NewClient()
	err := client.Start()
	// On non-Windows, Start should return an error
	if err == nil {
		t.Log("Start succeeded (running on Windows)")
	} else {
		if err.Error() != "helper not supported on this platform" {
			t.Errorf("Start error = %v, want 'helper not supported on this platform'", err)
		}
	}
}

func TestClientStop(t *testing.T) {
	client := NewClient()
	err := client.Stop()
	// Stop is a no-op on non-Windows, should return nil
	if err != nil {
		t.Errorf("Stop returned error: %v", err)
	}
}

func TestClientIsConnected(t *testing.T) {
	client := NewClient()
	// On non-Windows, IsConnected should always return false
	if client.IsConnected() {
		t.Log("IsConnected returned true (running on Windows)")
	}
}

func TestClientPing(t *testing.T) {
	client := NewClient()
	err := client.Ping()
	// On non-Windows, Ping should return an error
	if err == nil {
		t.Log("Ping succeeded (running on Windows)")
	} else {
		if err.Error() != "helper not supported on this platform" {
			t.Errorf("Ping error = %v, want 'helper not supported on this platform'", err)
		}
	}
}

func TestClientGetMonitors(t *testing.T) {
	client := NewClient()
	monitors, err := client.GetMonitors()
	// On non-Windows, should return error
	if err == nil {
		t.Logf("GetMonitors succeeded with %d monitors (running on Windows)", len(monitors))
	} else {
		if err.Error() != "helper not supported on this platform" {
			t.Errorf("GetMonitors error = %v, want 'helper not supported on this platform'", err)
		}
		if monitors != nil {
			t.Error("GetMonitors should return nil monitors on error")
		}
	}
}

func TestClientCaptureScreen(t *testing.T) {
	client := NewClient()
	data, frame, err := client.CaptureScreen(0, 80, 1.0)
	// On non-Windows, should return error
	if err == nil {
		t.Logf("CaptureScreen succeeded with %d bytes (running on Windows)", len(data))
	} else {
		if err.Error() != "helper not supported on this platform" {
			t.Errorf("CaptureScreen error = %v, want 'helper not supported on this platform'", err)
		}
		if data != nil || frame != nil {
			t.Error("CaptureScreen should return nil on error")
		}
	}
}

func TestClientSendInput(t *testing.T) {
	client := NewClient()
	event := InputEvent{
		Type:   "mouse",
		X:      100,
		Y:      200,
		Button: 0,
	}
	err := client.SendInput(event)
	// On non-Windows, should return error
	if err == nil {
		t.Log("SendInput succeeded (running on Windows)")
	} else {
		if err.Error() != "helper not supported on this platform" {
			t.Errorf("SendInput error = %v, want 'helper not supported on this platform'", err)
		}
	}
}

func TestClientReconnect(t *testing.T) {
	client := NewClient()
	err := client.Reconnect()
	// On non-Windows, should return error
	if err == nil {
		t.Log("Reconnect succeeded (running on Windows)")
	} else {
		if err.Error() != "helper not supported on this platform" {
			t.Errorf("Reconnect error = %v, want 'helper not supported on this platform'", err)
		}
	}
}

func TestClientScanWingetUpdates(t *testing.T) {
	client := NewClient()
	result, err := client.ScanWingetUpdates("")
	// On non-Windows, should return error
	if err == nil {
		t.Logf("ScanWingetUpdates succeeded with %d updates", len(result.Updates))
	} else {
		if err.Error() != "helper not supported on this platform" {
			t.Errorf("ScanWingetUpdates error = %v, want 'helper not supported on this platform'", err)
		}
		if result != nil {
			t.Error("ScanWingetUpdates should return nil result on error")
		}
	}
}

func TestClientUpgradeWingetPackage(t *testing.T) {
	client := NewClient()
	result, err := client.UpgradeWingetPackage("", "test.package")
	// On non-Windows, should return error
	if err == nil {
		t.Logf("UpgradeWingetPackage succeeded: %v", result.Success)
	} else {
		if err.Error() != "helper not supported on this platform" {
			t.Errorf("UpgradeWingetPackage error = %v, want 'helper not supported on this platform'", err)
		}
		if result != nil {
			t.Error("UpgradeWingetPackage should return nil result on error")
		}
	}
}

func TestClientInstallWingetPackage(t *testing.T) {
	client := NewClient()
	result, err := client.InstallWingetPackage("", "test.package", "1.0.0", "machine", true)
	// On non-Windows, should return error
	if err == nil {
		t.Logf("InstallWingetPackage succeeded: %v", result.Success)
	} else {
		if err.Error() != "helper not supported on this platform" {
			t.Errorf("InstallWingetPackage error = %v, want 'helper not supported on this platform'", err)
		}
		if result != nil {
			t.Error("InstallWingetPackage should return nil result on error")
		}
	}
}

func TestMonitorStruct(t *testing.T) {
	monitor := Monitor{
		ID:      1,
		Left:    0,
		Top:     0,
		Width:   1920,
		Height:  1080,
		Primary: true,
	}

	if monitor.ID != 1 {
		t.Errorf("ID = %d, want 1", monitor.ID)
	}
	if monitor.Width != 1920 {
		t.Errorf("Width = %d, want 1920", monitor.Width)
	}
	if monitor.Height != 1080 {
		t.Errorf("Height = %d, want 1080", monitor.Height)
	}
	if !monitor.Primary {
		t.Error("Primary should be true")
	}
}

func TestFrameResponseStruct(t *testing.T) {
	frame := FrameResponse{
		Width:    1920,
		Height:   1080,
		Format:   "jpeg",
		DataSize: 12345,
	}

	if frame.Width != 1920 {
		t.Errorf("Width = %d, want 1920", frame.Width)
	}
	if frame.Height != 1080 {
		t.Errorf("Height = %d, want 1080", frame.Height)
	}
	if frame.Format != "jpeg" {
		t.Errorf("Format = %s, want jpeg", frame.Format)
	}
	if frame.DataSize != 12345 {
		t.Errorf("DataSize = %d, want 12345", frame.DataSize)
	}
}

func TestInputEventStruct(t *testing.T) {
	event := InputEvent{
		Type:   "mouse_move",
		X:      100,
		Y:      200,
		Button: 1,
		Key:    "a",
		DeltaX: 10,
		DeltaY: -5,
	}

	if event.Type != "mouse_move" {
		t.Errorf("Type = %s, want mouse_move", event.Type)
	}
	if event.X != 100 {
		t.Errorf("X = %d, want 100", event.X)
	}
	if event.Y != 200 {
		t.Errorf("Y = %d, want 200", event.Y)
	}
	if event.Button != 1 {
		t.Errorf("Button = %d, want 1", event.Button)
	}
	if event.Key != "a" {
		t.Errorf("Key = %s, want a", event.Key)
	}
}

func TestWingetUpdateStruct(t *testing.T) {
	update := WingetUpdate{
		Name:      "Test App",
		ID:        "test.app",
		Version:   "1.0.0",
		Available: "2.0.0",
		Source:    "winget",
	}

	if update.Name != "Test App" {
		t.Errorf("Name = %s, want Test App", update.Name)
	}
	if update.ID != "test.app" {
		t.Errorf("ID = %s, want test.app", update.ID)
	}
	if update.Version != "1.0.0" {
		t.Errorf("Version = %s, want 1.0.0", update.Version)
	}
	if update.Available != "2.0.0" {
		t.Errorf("Available = %s, want 2.0.0", update.Available)
	}
}

func TestWingetScanResultStruct(t *testing.T) {
	result := WingetScanResult{
		Updates: []WingetUpdate{
			{Name: "App1", ID: "app.1", Version: "1.0", Available: "2.0"},
		},
		Error:     "",
		RawOutput: "some output",
	}

	if len(result.Updates) != 1 {
		t.Errorf("len(Updates) = %d, want 1", len(result.Updates))
	}
	if result.Error != "" {
		t.Error("Error should be empty")
	}
	if result.RawOutput != "some output" {
		t.Errorf("RawOutput = %s, want 'some output'", result.RawOutput)
	}
}

func TestWingetUpgradeResultStruct(t *testing.T) {
	result := WingetUpgradeResult{
		Success:   true,
		Output:    "Upgrade completed",
		Error:     "",
		ExitCode:  0,
		WingetLog: "log contents",
	}

	if !result.Success {
		t.Error("Success should be true")
	}
	if result.Output != "Upgrade completed" {
		t.Errorf("Output = %s, want 'Upgrade completed'", result.Output)
	}
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}
}

func TestWingetInstallResultStruct(t *testing.T) {
	result := WingetInstallResult{
		Success:   true,
		Output:    "Install completed",
		Error:     "",
		ExitCode:  0,
		WingetLog: "log contents",
	}

	if !result.Success {
		t.Error("Success should be true")
	}
	if result.Output != "Install completed" {
		t.Errorf("Output = %s, want 'Install completed'", result.Output)
	}
}

func TestGetManager(t *testing.T) {
	mgr := GetManager()
	if mgr == nil {
		t.Error("GetManager should return non-nil manager")
	}

	// Verify singleton
	mgr2 := GetManager()
	if mgr != mgr2 {
		t.Error("GetManager should return same instance")
	}
}

func TestManagerAcquire(t *testing.T) {
	mgr := GetManager()
	client, err := mgr.Acquire()
	// On non-Windows, should return error
	if err == nil {
		t.Log("Acquire succeeded (running on Windows)")
		mgr.Release()
	} else {
		if err.Error() != "helper not supported on this platform" {
			t.Errorf("Acquire error = %v, want 'helper not supported on this platform'", err)
		}
		if client != nil {
			t.Error("Acquire should return nil client on error")
		}
	}
}

func TestManagerRelease(t *testing.T) {
	mgr := GetManager()
	// Release is a no-op on non-Windows
	mgr.Release()
}

func TestManagerForceStop(t *testing.T) {
	mgr := GetManager()
	// ForceStop is a no-op on non-Windows
	mgr.ForceStop()
}

func TestManagerIsRunning(t *testing.T) {
	mgr := GetManager()
	// On non-Windows, IsRunning should always return false
	if mgr.IsRunning() {
		t.Log("IsRunning returned true (running on Windows)")
	}
}

func TestManagerRefCount(t *testing.T) {
	mgr := GetManager()
	// On non-Windows, RefCount should always return 0
	count := mgr.RefCount()
	if count != 0 {
		t.Logf("RefCount = %d (running on Windows or has active references)", count)
	}
}

func TestManagerReconnect(t *testing.T) {
	mgr := GetManager()
	client, err := mgr.Reconnect()
	// On non-Windows, should return error
	if err == nil {
		t.Logf("Reconnect succeeded (running on Windows), client: %v", client != nil)
	} else {
		if err.Error() != "helper not supported on this platform" {
			t.Errorf("Reconnect error = %v, want 'helper not supported on this platform'", err)
		}
	}
}

func TestManagerGetClient(t *testing.T) {
	mgr := GetManager()
	// On non-Windows, GetClient should return nil
	client := mgr.GetClient()
	if client != nil {
		t.Log("GetClient returned non-nil (running on Windows)")
	}
}
