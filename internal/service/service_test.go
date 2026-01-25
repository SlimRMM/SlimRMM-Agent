package service

import (
	"runtime"
	"testing"
)

func TestServiceStatusConstants(t *testing.T) {
	if StatusRunning != "running" {
		t.Errorf("StatusRunning = %s, want running", StatusRunning)
	}
	if StatusStopped != "stopped" {
		t.Errorf("StatusStopped = %s, want stopped", StatusStopped)
	}
	if StatusUnknown != "unknown" {
		t.Errorf("StatusUnknown = %s, want unknown", StatusUnknown)
	}
}

func TestServiceInfo(t *testing.T) {
	info := ServiceInfo{
		Name:        "test-service",
		DisplayName: "Test Service",
		Description: "A test service",
		Status:      StatusRunning,
		Enabled:     true,
		StartType:   "auto",
	}

	if info.Name != "test-service" {
		t.Errorf("Name = %s, want test-service", info.Name)
	}
	if info.DisplayName != "Test Service" {
		t.Errorf("DisplayName = %s, want Test Service", info.DisplayName)
	}
	if info.Description != "A test service" {
		t.Errorf("Description = %s, want A test service", info.Description)
	}
	if info.Status != StatusRunning {
		t.Errorf("Status = %s, want running", info.Status)
	}
	if !info.Enabled {
		t.Error("Enabled should be true")
	}
	if info.StartType != "auto" {
		t.Errorf("StartType = %s, want auto", info.StartType)
	}
}

func TestServiceInfoDefaults(t *testing.T) {
	info := ServiceInfo{}

	if info.Name != "" {
		t.Error("default Name should be empty")
	}
	if info.Status != "" {
		t.Error("default Status should be empty")
	}
	if info.Enabled {
		t.Error("default Enabled should be false")
	}
}

func TestNew(t *testing.T) {
	mgr := New()

	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		if mgr == nil {
			t.Error("New should return a manager on supported platforms")
		}
	default:
		if mgr != nil {
			t.Error("New should return nil on unsupported platforms")
		}
	}
}

func TestServiceConfig(t *testing.T) {
	config := ServiceConfig{
		Name:        "test-svc",
		DisplayName: "Test Service",
		Description: "Test description",
		ExecPath:    "/usr/bin/test",
		Args:        []string{"--config", "/etc/test.conf"},
		WorkingDir:  "/var/lib/test",
		User:        "testuser",
		Group:       "testgroup",
		Environment: map[string]string{
			"VAR1": "value1",
			"VAR2": "value2",
		},
	}

	if config.Name != "test-svc" {
		t.Errorf("Name = %s, want test-svc", config.Name)
	}
	if config.ExecPath != "/usr/bin/test" {
		t.Errorf("ExecPath = %s, want /usr/bin/test", config.ExecPath)
	}
	if len(config.Args) != 2 {
		t.Errorf("len(Args) = %d, want 2", len(config.Args))
	}
	if config.WorkingDir != "/var/lib/test" {
		t.Errorf("WorkingDir = %s, want /var/lib/test", config.WorkingDir)
	}
	if config.User != "testuser" {
		t.Errorf("User = %s, want testuser", config.User)
	}
	if len(config.Environment) != 2 {
		t.Errorf("len(Environment) = %d, want 2", len(config.Environment))
	}
}

func TestDefaultConfig(t *testing.T) {
	execPath := "/usr/bin/slimrmm-agent"
	config := DefaultConfig(execPath)

	if config == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if config.Name != "slimrmm-agent" {
		t.Errorf("Name = %s, want slimrmm-agent", config.Name)
	}
	if config.DisplayName != "SlimRMM Agent" {
		t.Errorf("DisplayName = %s, want SlimRMM Agent", config.DisplayName)
	}
	if config.ExecPath != execPath {
		t.Errorf("ExecPath = %s, want %s", config.ExecPath, execPath)
	}
	if config.WorkingDir != "/var/lib/slimrmm" {
		t.Errorf("WorkingDir = %s, want /var/lib/slimrmm", config.WorkingDir)
	}
	if config.User != "root" {
		t.Errorf("User = %s, want root", config.User)
	}
	if config.Group != "root" {
		t.Errorf("Group = %s, want root", config.Group)
	}
}

func TestErrors(t *testing.T) {
	if ErrServiceNotFound == nil {
		t.Error("ErrServiceNotFound should not be nil")
	}
	if ErrServiceNotFound.Error() == "" {
		t.Error("ErrServiceNotFound should have a message")
	}
	if ErrServiceExists == nil {
		t.Error("ErrServiceExists should not be nil")
	}
	if ErrServiceExists.Error() == "" {
		t.Error("ErrServiceExists should have a message")
	}
}

func TestServiceConfigEnvironment(t *testing.T) {
	config := ServiceConfig{
		Environment: map[string]string{
			"LOG_LEVEL": "debug",
			"DATA_DIR":  "/var/lib/data",
		},
	}

	if config.Environment["LOG_LEVEL"] != "debug" {
		t.Error("Environment LOG_LEVEL not set correctly")
	}
	if config.Environment["DATA_DIR"] != "/var/lib/data" {
		t.Error("Environment DATA_DIR not set correctly")
	}
}

func TestServiceInfoWithAllStatuses(t *testing.T) {
	statuses := []ServiceStatus{StatusRunning, StatusStopped, StatusUnknown}

	for _, status := range statuses {
		info := ServiceInfo{Status: status}
		if info.Status != status {
			t.Errorf("Status assignment failed for %s", status)
		}
	}
}

func TestServiceInfoStartTypes(t *testing.T) {
	startTypes := []string{"auto", "manual", "disabled"}

	for _, st := range startTypes {
		info := ServiceInfo{StartType: st}
		if info.StartType != st {
			t.Errorf("StartType assignment failed for %s", st)
		}
	}
}

func TestServiceConfigWithArgs(t *testing.T) {
	args := []string{"--config", "/etc/config.yaml", "--verbose", "--log-level", "debug"}
	config := ServiceConfig{
		Name:     "test",
		ExecPath: "/usr/bin/test",
		Args:     args,
	}

	if len(config.Args) != 5 {
		t.Errorf("len(Args) = %d, want 5", len(config.Args))
	}
	if config.Args[0] != "--config" {
		t.Error("first arg should be --config")
	}
}

func TestManagerInterface(t *testing.T) {
	// Verify the interface is properly defined
	mgr := New()
	if mgr == nil && (runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
		t.Error("Manager should be implemented for supported platforms")
	}

	// Type assertion should work
	var _ Manager = mgr
}

func TestAgentInfoStruct(t *testing.T) {
	info := AgentInfo{
		Version:        "2.0.0",
		GitCommit:      "abc123",
		BuildDate:      "2024-01-15",
		Server:         "https://rmm.example.com",
		UUID:           "12345678-1234-1234-1234-123456789012",
		InstallDate:    "2024-01-01T00:00:00Z",
		LastConnection: "2024-01-15T10:00:00Z",
		LastHeartbeat:  "2024-01-15T10:05:00Z",
		MTLSEnabled:    true,
		FullDiskAccess: true,
		ScreenSharing:  false,
	}

	if info.Version != "2.0.0" {
		t.Errorf("Version = %s, want 2.0.0", info.Version)
	}
	if info.GitCommit != "abc123" {
		t.Errorf("GitCommit = %s, want abc123", info.GitCommit)
	}
	if info.Server != "https://rmm.example.com" {
		t.Errorf("Server = %s, want https://rmm.example.com", info.Server)
	}
	if !info.MTLSEnabled {
		t.Error("MTLSEnabled should be true")
	}
	if !info.FullDiskAccess {
		t.Error("FullDiskAccess should be true")
	}
	if info.ScreenSharing {
		t.Error("ScreenSharing should be false")
	}
}

func TestAgentInfoDefaults(t *testing.T) {
	info := AgentInfo{}

	if info.Version != "" {
		t.Error("default Version should be empty")
	}
	if info.UUID != "" {
		t.Error("default UUID should be empty")
	}
	if info.MTLSEnabled {
		t.Error("default MTLSEnabled should be false")
	}
	if info.FullDiskAccess {
		t.Error("default FullDiskAccess should be false")
	}
}

func TestValueOrNA(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "N/A"},
		{"value", "value"},
		{"https://example.com", "https://example.com"},
		{" ", " "}, // Space is not empty
	}

	for _, tt := range tests {
		result := valueOrNA(tt.input)
		if result != tt.expected {
			t.Errorf("valueOrNA(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestPermissionStatus(t *testing.T) {
	if permissionStatus(true) != "Granted" {
		t.Error("permissionStatus(true) should be 'Granted'")
	}
	if permissionStatus(false) != "Not Granted" {
		t.Error("permissionStatus(false) should be 'Not Granted'")
	}
}

func TestCheckFullDiskAccess(t *testing.T) {
	// This function is platform-specific, so just verify it doesn't panic
	result := checkFullDiskAccess()

	// On non-macOS platforms, it should return false
	if runtime.GOOS != "darwin" && result {
		t.Error("checkFullDiskAccess should return false on non-macOS")
	}
	// On macOS, we can't predict the result, just verify it returns a bool
}

func TestCheckScreenSharingEnabled(t *testing.T) {
	// This function is platform-specific, so just verify it doesn't panic
	result := checkScreenSharingEnabled()

	// On non-macOS platforms, it should return false
	if runtime.GOOS != "darwin" && result {
		t.Error("checkScreenSharingEnabled should return false on non-macOS")
	}
}

func TestServiceConfigEmpty(t *testing.T) {
	config := ServiceConfig{}

	if config.Name != "" {
		t.Error("default Name should be empty")
	}
	if config.ExecPath != "" {
		t.Error("default ExecPath should be empty")
	}
	if config.Args != nil {
		t.Error("default Args should be nil")
	}
	if config.Environment != nil {
		t.Error("default Environment should be nil")
	}
}

func TestDefaultConfigPaths(t *testing.T) {
	tests := []struct {
		execPath string
	}{
		{"/usr/bin/slimrmm-agent"},
		{"/opt/slimrmm/bin/agent"},
		{"C:\\Program Files\\SlimRMM\\agent.exe"},
	}

	for _, tt := range tests {
		config := DefaultConfig(tt.execPath)
		if config.ExecPath != tt.execPath {
			t.Errorf("ExecPath = %s, want %s", config.ExecPath, tt.execPath)
		}
		// Other defaults should remain the same
		if config.Name != "slimrmm-agent" {
			t.Error("Name should always be slimrmm-agent")
		}
	}
}

func TestServiceStatusString(t *testing.T) {
	tests := []struct {
		status   ServiceStatus
		expected string
	}{
		{StatusRunning, "running"},
		{StatusStopped, "stopped"},
		{StatusUnknown, "unknown"},
	}

	for _, tt := range tests {
		if string(tt.status) != tt.expected {
			t.Errorf("string(%v) = %s, want %s", tt.status, string(tt.status), tt.expected)
		}
	}
}

func TestErrorMessages(t *testing.T) {
	// Verify error messages are meaningful
	if ErrServiceNotFound.Error() != "service not found" {
		t.Errorf("ErrServiceNotFound = %q, want 'service not found'", ErrServiceNotFound.Error())
	}
	if ErrServiceExists.Error() != "service already exists" {
		t.Errorf("ErrServiceExists = %q, want 'service already exists'", ErrServiceExists.Error())
	}
}

func TestServiceConfigWithEmptyEnvironment(t *testing.T) {
	config := ServiceConfig{
		Name:        "test",
		ExecPath:    "/bin/test",
		Environment: map[string]string{},
	}

	if config.Environment == nil {
		t.Error("Environment should not be nil")
	}
	if len(config.Environment) != 0 {
		t.Error("Environment should be empty")
	}
}

func TestNewManagerByOS(t *testing.T) {
	mgr := New()

	switch runtime.GOOS {
	case "linux":
		if _, ok := mgr.(*SystemdManager); !ok {
			t.Error("Linux should use SystemdManager")
		}
	case "darwin":
		if _, ok := mgr.(*LaunchdManager); !ok {
			t.Error("macOS should use LaunchdManager")
		}
	case "windows":
		// Windows manager type varies by implementation
		if mgr == nil {
			t.Error("Windows should have a manager implementation")
		}
	default:
		if mgr != nil {
			t.Errorf("Unsupported OS %s should return nil manager", runtime.GOOS)
		}
	}
}
