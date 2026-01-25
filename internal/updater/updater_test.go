package updater

import (
	"log/slog"
	"os"
	"runtime"
	"testing"
)

func TestConstants(t *testing.T) {
	if GitHubAPIURL == "" {
		t.Error("GitHubAPIURL should not be empty")
	}
	if UpdateCheckInterval <= 0 {
		t.Error("UpdateCheckInterval should be positive")
	}
	if MaxDownloadSize <= 0 {
		t.Error("MaxDownloadSize should be positive")
	}
	if HealthCheckTimeout <= 0 {
		t.Error("HealthCheckTimeout should be positive")
	}
	if HealthCheckRetries <= 0 {
		t.Error("HealthCheckRetries should be positive")
	}
}

func TestGitHubRelease(t *testing.T) {
	release := GitHubRelease{
		TagName: "v1.0.0",
		Assets: []Asset{
			{
				Name:               "slimrmm-agent_1.0.0_linux_amd64.tar.gz",
				BrowserDownloadURL: "https://example.com/download",
				Size:               1024,
			},
		},
	}

	if release.TagName != "v1.0.0" {
		t.Error("TagName not set correctly")
	}
	if len(release.Assets) != 1 {
		t.Error("Assets not set correctly")
	}
	if release.Assets[0].Name != "slimrmm-agent_1.0.0_linux_amd64.tar.gz" {
		t.Error("Asset Name not set correctly")
	}
}

func TestAsset(t *testing.T) {
	asset := Asset{
		Name:               "test-asset.tar.gz",
		BrowserDownloadURL: "https://example.com/test",
		Size:               2048,
	}

	if asset.Name != "test-asset.tar.gz" {
		t.Error("Name not set correctly")
	}
	if asset.BrowserDownloadURL != "https://example.com/test" {
		t.Error("BrowserDownloadURL not set correctly")
	}
	if asset.Size != 2048 {
		t.Error("Size not set correctly")
	}
}

func TestUpdateInfo(t *testing.T) {
	info := UpdateInfo{
		Version:     "1.0.0",
		DownloadURL: "https://example.com/download",
		AssetName:   "asset.tar.gz",
		Size:        1024,
	}

	if info.Version != "1.0.0" {
		t.Error("Version not set correctly")
	}
	if info.DownloadURL != "https://example.com/download" {
		t.Error("DownloadURL not set correctly")
	}
}

func TestUpdateResult(t *testing.T) {
	result := UpdateResult{
		Success:       true,
		OldVersion:    "1.0.0",
		NewVersion:    "1.1.0",
		RolledBack:    false,
		Error:         "",
		RestartNeeded: true,
	}

	if !result.Success {
		t.Error("Success not set correctly")
	}
	if result.OldVersion != "1.0.0" {
		t.Error("OldVersion not set correctly")
	}
	if result.NewVersion != "1.1.0" {
		t.Error("NewVersion not set correctly")
	}
	if !result.RestartNeeded {
		t.Error("RestartNeeded not set correctly")
	}
}

func TestNew(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	u := New(logger)

	if u == nil {
		t.Fatal("New returned nil")
	}
	if u.logger == nil {
		t.Error("logger should be set")
	}
	if u.serviceName == "" {
		t.Error("serviceName should be set")
	}
	if u.dataDir == "" {
		t.Error("dataDir should be set")
	}
}

func TestGetServiceName(t *testing.T) {
	name := getServiceName()
	if name == "" {
		t.Error("getServiceName should return a non-empty string")
	}

	switch runtime.GOOS {
	case "darwin":
		if name != "io.slimrmm.agent" {
			t.Errorf("macOS service name = %s, want io.slimrmm.agent", name)
		}
	case "windows":
		if name != "SlimRMMAgent" {
			t.Errorf("Windows service name = %s, want SlimRMMAgent", name)
		}
	default:
		if name != "slimrmm-agent" {
			t.Errorf("Linux service name = %s, want slimrmm-agent", name)
		}
	}
}

func TestIsValidServiceName(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"slimrmm-agent", true},
		{"io.slimrmm.agent", true},
		{"SlimRMMAgent", true},
		{"service_name", true},
		{"", false},
		{"name with spaces", false},
		{"name;injection", false},
		{"name`cmd`", false},
		{"$(command)", false},
		// Too long
		{string(make([]byte, 129)), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidServiceName(tt.name); got != tt.valid {
				t.Errorf("isValidServiceName(%q) = %v, want %v", tt.name, got, tt.valid)
			}
		})
	}
}

func TestSetMaintenanceCallback(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	u := New(logger)

	var callbackCalled bool
	var callbackEnabled bool
	var callbackReason string

	u.SetMaintenanceCallback(func(enabled bool, reason string) {
		callbackCalled = true
		callbackEnabled = enabled
		callbackReason = reason
	})

	u.notifyMaintenance(true, "test reason")

	if !callbackCalled {
		t.Error("callback should have been called")
	}
	if !callbackEnabled {
		t.Error("enabled should be true")
	}
	if callbackReason != "test reason" {
		t.Errorf("reason = %q, want 'test reason'", callbackReason)
	}
}

func TestNotifyMaintenanceNoCallback(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	u := New(logger)

	// Should not panic when no callback is set
	u.notifyMaintenance(true, "test")
}

func TestGetAssetPattern(t *testing.T) {
	pattern := getAssetPattern()
	if pattern == "" {
		t.Error("getAssetPattern should return a non-empty string")
	}

	// Pattern should contain the current OS and arch
	os := runtime.GOOS
	arch := runtime.GOARCH
	if os != "" && arch != "" {
		// Just verify it returns something
		_ = pattern
	}
}

func TestMatchesAssetPattern(t *testing.T) {
	tests := []struct {
		assetName string
		matches   bool
	}{
		// Correct format for current platform
		{"slimrmm-agent_1.0.0_" + runtime.GOOS + "_" + runtime.GOARCH + getExtension(), true},
		{"slimrmm-agent_2.3.4_" + runtime.GOOS + "_" + runtime.GOARCH + getExtension(), true},
		// Wrong prefix
		{"other-agent_1.0.0_" + runtime.GOOS + "_" + runtime.GOARCH + getExtension(), false},
		// Wrong platform
		{"slimrmm-agent_1.0.0_wrongos_wrongarch.tar.gz", false},
		// Empty
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.assetName, func(t *testing.T) {
			if got := matchesAssetPattern(tt.assetName, ""); got != tt.matches {
				t.Errorf("matchesAssetPattern(%q) = %v, want %v", tt.assetName, got, tt.matches)
			}
		})
	}
}

func getExtension() string {
	if runtime.GOOS == "windows" {
		return ".zip"
	}
	return ".tar.gz"
}

func TestIsNewerVersion(t *testing.T) {
	tests := []struct {
		latest  string
		current string
		newer   bool
	}{
		{"1.0.0", "1.0.0", false},
		{"1.0.1", "1.0.0", true},
		{"1.1.0", "1.0.0", true},
		{"2.0.0", "1.0.0", true},
		{"1.0.0", "1.0.1", false},
		{"1.0.0", "2.0.0", false},
		{"1.0.0", "unknown", true},
		{"1.0.0", "dev", true},
		{"1.0.0.1", "1.0.0", true},
		{"1.0.0", "1.0.0.1", false},
		{"1.0.0-beta", "1.0.0-alpha", false}, // Both become 1.0.0
		{"2.0.0-rc1", "1.0.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.latest+"_vs_"+tt.current, func(t *testing.T) {
			if got := isNewerVersion(tt.latest, tt.current); got != tt.newer {
				t.Errorf("isNewerVersion(%q, %q) = %v, want %v", tt.latest, tt.current, got, tt.newer)
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		version string
		parts   []int
	}{
		{"1.0.0", []int{1, 0, 0}},
		{"1.2.3", []int{1, 2, 3}},
		{"10.20.30", []int{10, 20, 30}},
		{"1.0.0-beta", []int{1, 0, 0}},
		{"2.0.0-rc1", []int{2, 0, 0}},
		{"1", []int{1}},
		{"1.2", []int{1, 2}},
		{"1.2.3.4", []int{1, 2, 3, 4}},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := parseVersion(tt.version)
			if len(got) != len(tt.parts) {
				t.Errorf("parseVersion(%q) returned %d parts, want %d", tt.version, len(got), len(tt.parts))
				return
			}
			for i, v := range got {
				if v != tt.parts[i] {
					t.Errorf("parseVersion(%q)[%d] = %d, want %d", tt.version, i, v, tt.parts[i])
				}
			}
		})
	}
}

func TestServiceNameRegex(t *testing.T) {
	// Test the regex directly
	validNames := []string{
		"service",
		"my-service",
		"my_service",
		"my.service",
		"Service123",
		"io.example.service",
	}

	invalidNames := []string{
		"",
		"service name",
		"service;name",
		"service`cmd`",
		"service$var",
		"service|pipe",
	}

	for _, name := range validNames {
		if !serviceNameRegex.MatchString(name) {
			t.Errorf("serviceNameRegex should match %q", name)
		}
	}

	for _, name := range invalidNames {
		if name != "" && serviceNameRegex.MatchString(name) {
			t.Errorf("serviceNameRegex should not match %q", name)
		}
	}
}

func TestUpdateResultWithError(t *testing.T) {
	result := UpdateResult{
		Success:    false,
		OldVersion: "1.0.0",
		NewVersion: "1.1.0",
		RolledBack: true,
		Error:      "download failed: timeout",
	}

	if result.Success {
		t.Error("Success should be false")
	}
	if !result.RolledBack {
		t.Error("RolledBack should be true")
	}
	if result.Error == "" {
		t.Error("Error should be set")
	}
}

func TestMaintenanceCallbackType(t *testing.T) {
	// Verify the callback type signature
	var callback MaintenanceCallback = func(enabled bool, reason string) {
		_ = enabled
		_ = reason
	}
	if callback == nil {
		t.Error("callback should not be nil")
	}
}
