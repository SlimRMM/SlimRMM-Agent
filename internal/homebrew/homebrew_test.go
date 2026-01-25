package homebrew

import (
	"encoding/json"
	"testing"
	"time"
)

func TestIsValidCaskName(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"firefox", true},
		{"visual-studio-code", true},
		{"a", true},
		{"z", true},
		{"1password", true},
		{"google-chrome", true},
		{"java8", true},
		{"", false},
		{"-firefox", false},
		{"firefox-", false},
		{"Fire-Fox", false},
		{"firefox_app", false},
		{"firefox.app", false},
		{"fire fox", false},
		{string(make([]byte, 129)), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidCaskName(tt.name); got != tt.valid {
				t.Errorf("IsValidCaskName(%q) = %v, want %v", tt.name, got, tt.valid)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	if HomebrewAPIBase == "" {
		t.Error("HomebrewAPIBase should not be empty")
	}
	if HomebrewAPIBase != "https://formulae.brew.sh/api" {
		t.Errorf("HomebrewAPIBase = %s, want https://formulae.brew.sh/api", HomebrewAPIBase)
	}
	if RequestTimeout != 30*time.Second {
		t.Errorf("RequestTimeout = %v, want 30s", RequestTimeout)
	}
}

func TestCaskInfo(t *testing.T) {
	info := CaskInfo{
		Token:    "firefox",
		Name:     []string{"Mozilla Firefox"},
		Desc:     "Web browser",
		Homepage: "https://www.mozilla.org/firefox/",
		URL:      "https://download.mozilla.org/...",
		Version:  "120.0",
		SHA256:   "abc123...",
	}

	if info.Token != "firefox" {
		t.Errorf("Token = %s, want firefox", info.Token)
	}
	if info.Version != "120.0" {
		t.Errorf("Version = %s, want 120.0", info.Version)
	}
}

func TestCaskArtifact(t *testing.T) {
	artifact := CaskArtifact{
		App: []string{"Firefox.app"},
	}

	if len(artifact.App) != 1 {
		t.Error("App should have one entry")
	}
	if artifact.App[0] != "Firefox.app" {
		t.Errorf("App[0] = %s, want Firefox.app", artifact.App[0])
	}
}

func TestCaskArtifactPkg(t *testing.T) {
	artifact := CaskArtifact{
		Pkg: []string{"installer.pkg"},
	}

	if len(artifact.Pkg) != 1 {
		t.Error("Pkg should have one entry")
	}
	if artifact.Pkg[0] != "installer.pkg" {
		t.Errorf("Pkg[0] = %s, want installer.pkg", artifact.Pkg[0])
	}
}

func TestGetArtifactTypeApp(t *testing.T) {
	info := CaskInfo{
		Artifacts: []json.RawMessage{
			json.RawMessage(`{"app": ["Firefox.app"]}`),
		},
	}

	if info.GetArtifactType() != "app" {
		t.Errorf("GetArtifactType = %s, want app", info.GetArtifactType())
	}
}

func TestGetArtifactTypePkg(t *testing.T) {
	info := CaskInfo{
		Artifacts: []json.RawMessage{
			json.RawMessage(`{"pkg": ["Installer.pkg"]}`),
		},
	}

	if info.GetArtifactType() != "pkg" {
		t.Errorf("GetArtifactType = %s, want pkg", info.GetArtifactType())
	}
}

func TestGetArtifactTypeUnknown(t *testing.T) {
	info := CaskInfo{
		Artifacts: []json.RawMessage{},
	}

	if info.GetArtifactType() != "unknown" {
		t.Errorf("GetArtifactType = %s, want unknown", info.GetArtifactType())
	}
}

func TestGetArtifactTypeInvalidJSON(t *testing.T) {
	info := CaskInfo{
		Artifacts: []json.RawMessage{
			json.RawMessage(`invalid json`),
		},
	}

	// Should return unknown for invalid JSON
	if info.GetArtifactType() != "unknown" {
		t.Errorf("GetArtifactType = %s, want unknown for invalid JSON", info.GetArtifactType())
	}
}

func TestGetAppName(t *testing.T) {
	info := CaskInfo{
		Artifacts: []json.RawMessage{
			json.RawMessage(`{"app": ["Firefox.app"]}`),
		},
	}

	if info.GetAppName() != "Firefox.app" {
		t.Errorf("GetAppName = %s, want Firefox.app", info.GetAppName())
	}
}

func TestGetAppNameEmpty(t *testing.T) {
	info := CaskInfo{
		Artifacts: []json.RawMessage{},
	}

	if info.GetAppName() != "" {
		t.Errorf("GetAppName = %s, want empty string", info.GetAppName())
	}
}

func TestGetAppNameNoPkg(t *testing.T) {
	info := CaskInfo{
		Artifacts: []json.RawMessage{
			json.RawMessage(`{"pkg": ["Installer.pkg"]}`),
		},
	}

	// No app, should return empty
	if info.GetAppName() != "" {
		t.Errorf("GetAppName = %s, want empty string for pkg artifact", info.GetAppName())
	}
}

func TestCaskInfoWithDependsOn(t *testing.T) {
	info := CaskInfo{
		Token:   "java8",
		Version: "8.0.362",
		DependsOn: map[string]any{
			"macos": map[string]any{
				">=": "10.15",
			},
		},
	}

	if info.DependsOn == nil {
		t.Error("DependsOn should be set")
	}
	if _, ok := info.DependsOn["macos"]; !ok {
		t.Error("DependsOn should have macos key")
	}
}

func TestCaskNamePatternRegex(t *testing.T) {
	// Test the compiled regex directly
	validNames := []string{"firefox", "google-chrome", "a", "1password"}
	invalidNames := []string{"", "-test", "test-", "TEST"}

	for _, name := range validNames {
		if !caskNamePattern.MatchString(name) {
			t.Errorf("caskNamePattern should match %q", name)
		}
	}

	for _, name := range invalidNames {
		if name != "" && caskNamePattern.MatchString(name) {
			t.Errorf("caskNamePattern should not match %q", name)
		}
	}
}

func TestCaskInfoMultipleArtifacts(t *testing.T) {
	info := CaskInfo{
		Artifacts: []json.RawMessage{
			json.RawMessage(`{"zap": {"trash": ["~/Library/Caches/com.mozilla.firefox"]}}`),
			json.RawMessage(`{"app": ["Firefox.app"]}`),
		},
	}

	// Should find the app artifact
	if info.GetArtifactType() != "app" {
		t.Errorf("GetArtifactType = %s, want app", info.GetArtifactType())
	}
}

func TestCaskInfoJSONSerialization(t *testing.T) {
	info := CaskInfo{
		Token:    "visual-studio-code",
		Name:     []string{"Microsoft Visual Studio Code", "VS Code"},
		Desc:     "Open-source code editor",
		Homepage: "https://code.visualstudio.com/",
		URL:      "https://update.code.visualstudio.com/latest/darwin/stable",
		Version:  "1.85.0",
		SHA256:   "abcdef123456...",
		Artifacts: []json.RawMessage{
			json.RawMessage(`{"app": ["Visual Studio Code.app"]}`),
		},
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed CaskInfo
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.Token != "visual-studio-code" {
		t.Errorf("Token = %s, want visual-studio-code", parsed.Token)
	}
	if len(parsed.Name) != 2 {
		t.Errorf("len(Name) = %d, want 2", len(parsed.Name))
	}
	if parsed.Version != "1.85.0" {
		t.Errorf("Version = %s, want 1.85.0", parsed.Version)
	}
}

func TestCaskInfoDefaults(t *testing.T) {
	info := CaskInfo{}

	if info.Token != "" {
		t.Error("default Token should be empty")
	}
	if info.Name != nil {
		t.Error("default Name should be nil")
	}
	if info.Artifacts != nil {
		t.Error("default Artifacts should be nil")
	}
	if info.DependsOn != nil {
		t.Error("default DependsOn should be nil")
	}
}

func TestCaskArtifactBothTypes(t *testing.T) {
	// In theory an artifact could have both, test the struct
	artifact := CaskArtifact{
		App: []string{"App1.app", "App2.app"},
		Pkg: []string{"Installer.pkg"},
	}

	if len(artifact.App) != 2 {
		t.Errorf("len(App) = %d, want 2", len(artifact.App))
	}
	if len(artifact.Pkg) != 1 {
		t.Errorf("len(Pkg) = %d, want 1", len(artifact.Pkg))
	}
}

func TestCaskArtifactEmpty(t *testing.T) {
	artifact := CaskArtifact{}

	if artifact.App != nil {
		t.Error("default App should be nil")
	}
	if artifact.Pkg != nil {
		t.Error("default Pkg should be nil")
	}
}

func TestCaskInfoWithAllFields(t *testing.T) {
	info := CaskInfo{
		Token:    "docker",
		Name:     []string{"Docker Desktop", "Docker"},
		Desc:     "App to build and share containerized applications and microservices",
		Homepage: "https://www.docker.com/products/docker-desktop",
		URL:      "https://desktop.docker.com/mac/main/arm64/Docker.dmg",
		Version:  "4.26.0,131620",
		SHA256:   "1234567890abcdef...",
		Artifacts: []json.RawMessage{
			json.RawMessage(`{"app": ["Docker.app"]}`),
			json.RawMessage(`{"zap": {"trash": ["~/Library/Group Containers/group.com.docker"]}}`),
		},
		DependsOn: map[string]any{
			"macos": map[string]any{
				">=": "12.0",
			},
		},
	}

	// Test basic field access
	if info.Token != "docker" {
		t.Errorf("Token = %s, want docker", info.Token)
	}
	if info.Desc == "" {
		t.Error("Desc should not be empty")
	}
	if info.Homepage != "https://www.docker.com/products/docker-desktop" {
		t.Errorf("Homepage mismatch")
	}

	// Test artifact methods
	if info.GetArtifactType() != "app" {
		t.Errorf("GetArtifactType = %s, want app", info.GetArtifactType())
	}
	if info.GetAppName() != "Docker.app" {
		t.Errorf("GetAppName = %s, want Docker.app", info.GetAppName())
	}

	// Test DependsOn
	macos, ok := info.DependsOn["macos"]
	if !ok {
		t.Error("DependsOn should have macos key")
	}
	macosMap, ok := macos.(map[string]any)
	if !ok {
		t.Error("macos should be a map")
	}
	if macosMap[">="] != "12.0" {
		t.Errorf("macos >= = %v, want 12.0", macosMap[">="])
	}
}

func TestIsValidCaskNameEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		// Single characters
		{"a", true},
		{"z", true},
		{"0", true},
		{"9", true},

		// Two character names
		{"ab", true},
		{"a1", true},
		{"1a", true},

		// Long valid names
		{"this-is-a-very-long-cask-name-that-is-still-valid", true},

		// Names at max length (128 chars)
		{string(make([]byte, 128)), false}, // 128 null bytes - invalid chars

		// Names over max length
		{string(make([]byte, 129)), false},

		// Invalid patterns
		{"A", false},       // uppercase
		{"Firefox", false}, // mixed case
		{"test_app", false}, // underscore
		{"test.app", false}, // dot
		{"-test", false},    // starts with hyphen
		{"test-", false},    // ends with hyphen
	}

	for _, tt := range tests {
		name := tt.name
		if len(name) > 20 {
			name = name[:20] + "..."
		}
		t.Run(name, func(t *testing.T) {
			result := IsValidCaskName(tt.name)
			if result != tt.expected {
				t.Errorf("IsValidCaskName(%q) = %v, want %v", tt.name, result, tt.expected)
			}
		})
	}
}

func TestCaskArtifactJSONUnmarshal(t *testing.T) {
	tests := []struct {
		name        string
		jsonData    string
		expectApp   bool
		expectPkg   bool
		appName     string
		pkgName     string
	}{
		{
			name:      "app artifact",
			jsonData:  `{"app": ["Firefox.app"]}`,
			expectApp: true,
			appName:   "Firefox.app",
		},
		{
			name:      "pkg artifact",
			jsonData:  `{"pkg": ["Installer.pkg"]}`,
			expectPkg: true,
			pkgName:   "Installer.pkg",
		},
		{
			name:     "empty artifact",
			jsonData: `{}`,
		},
		{
			name:      "multiple apps",
			jsonData:  `{"app": ["App1.app", "App2.app"]}`,
			expectApp: true,
			appName:   "App1.app",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var artifact CaskArtifact
			if err := json.Unmarshal([]byte(tt.jsonData), &artifact); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			if tt.expectApp {
				if len(artifact.App) == 0 {
					t.Error("expected App to be set")
				}
				if artifact.App[0] != tt.appName {
					t.Errorf("App[0] = %s, want %s", artifact.App[0], tt.appName)
				}
			}

			if tt.expectPkg {
				if len(artifact.Pkg) == 0 {
					t.Error("expected Pkg to be set")
				}
				if artifact.Pkg[0] != tt.pkgName {
					t.Errorf("Pkg[0] = %s, want %s", artifact.Pkg[0], tt.pkgName)
				}
			}
		})
	}
}

func TestCaskNamePatternCompiled(t *testing.T) {
	// Verify the regex is compiled
	if caskNamePattern == nil {
		t.Error("caskNamePattern should be compiled")
	}

	// Test some specific patterns
	matches := []string{"firefox", "a", "1", "a1", "1a", "test-app", "test-app-1"}
	nonMatches := []string{"", "A", "Test", "-test", "test-"}

	for _, m := range matches {
		if !caskNamePattern.MatchString(m) {
			t.Errorf("pattern should match %q", m)
		}
	}

	for _, m := range nonMatches {
		if m != "" && caskNamePattern.MatchString(m) {
			t.Errorf("pattern should not match %q", m)
		}
	}
}
