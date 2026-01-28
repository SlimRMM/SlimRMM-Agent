package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDefaultPaths(t *testing.T) {
	paths := DefaultPaths()

	if paths.BaseDir == "" {
		t.Error("BaseDir should not be empty")
	}
	if paths.ConfigFile == "" {
		t.Error("ConfigFile should not be empty")
	}
	if paths.CertsDir == "" {
		t.Error("CertsDir should not be empty")
	}
	if paths.LogDir == "" {
		t.Error("LogDir should not be empty")
	}
	if paths.CACert == "" {
		t.Error("CACert should not be empty")
	}
	if paths.ClientCert == "" {
		t.Error("ClientCert should not be empty")
	}
	if paths.ClientKey == "" {
		t.Error("ClientKey should not be empty")
	}

	// Verify certs are in certs dir
	if !isInDir(paths.CACert, paths.CertsDir) {
		t.Error("CACert should be in CertsDir")
	}
	if !isInDir(paths.ClientCert, paths.CertsDir) {
		t.Error("ClientCert should be in CertsDir")
	}
	if !isInDir(paths.ClientKey, paths.CertsDir) {
		t.Error("ClientKey should be in CertsDir")
	}
}

func TestDefaultPathsOS(t *testing.T) {
	paths := DefaultPaths()

	switch runtime.GOOS {
	case "darwin":
		if paths.BaseDir != "/Applications/SlimRMM.app/Contents/Data" {
			t.Errorf("darwin BaseDir = %s, want /Applications/SlimRMM.app/Contents/Data", paths.BaseDir)
		}
	case "linux":
		if paths.BaseDir != "/var/lib/slimrmm" {
			t.Errorf("linux BaseDir = %s, want /var/lib/slimrmm", paths.BaseDir)
		}
		if paths.LogDir != "/var/log/slimrmm" {
			t.Errorf("linux LogDir = %s, want /var/log/slimrmm", paths.LogDir)
		}
	}
}

func TestLoad(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, configFileName)

	// Write valid config
	// Use pointer to avoid copying mutex (go vet warning)
	cfg := &Config{
		Server:      "https://example.com",
		UUID:        "test-uuid-123",
		MTLSEnabled: true,
		InstallDate: "2024-01-01T00:00:00Z",
	}
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Load config
	loaded, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Server != "https://example.com" {
		t.Errorf("Server = %s, want https://example.com", loaded.Server)
	}
	if loaded.UUID != "test-uuid-123" {
		t.Errorf("UUID = %s, want test-uuid-123", loaded.UUID)
	}
	if !loaded.MTLSEnabled {
		t.Error("MTLSEnabled should be true")
	}
}

func TestLoadNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.json")
	if err != ErrConfigNotFound {
		t.Errorf("Load should return ErrConfigNotFound, got %v", err)
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, configFileName)
	if err := os.WriteFile(configPath, []byte("invalid json{"), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err = Load(configPath)
	if err == nil {
		t.Error("Load should fail for invalid JSON")
	}
}

func TestLoadMissingServer(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, configFileName)
	// Use pointer to avoid copying mutex (go vet warning)
	cfg := &Config{UUID: "test-uuid"} // Missing server
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	_, err = Load(configPath)
	if err == nil {
		t.Error("Load should fail when server is missing")
	}
}

func TestSave(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, configFileName)

	cfg := &Config{
		Server:      "https://example.com",
		UUID:        "test-uuid",
		MTLSEnabled: true,
		filePath:    configPath,
	}

	if err := cfg.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file was written
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read saved config: %v", err)
	}

	var loaded Config
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("failed to parse saved config: %v", err)
	}

	if loaded.Server != "https://example.com" {
		t.Errorf("Server = %s, want https://example.com", loaded.Server)
	}
}

func TestSaveNoPath(t *testing.T) {
	cfg := &Config{
		Server: "https://example.com",
		// filePath not set
	}

	err := cfg.Save()
	if err == nil {
		t.Error("Save should fail when filePath is not set")
	}
}

func TestNew(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	paths := Paths{
		BaseDir:    tmpDir,
		ConfigFile: filepath.Join(tmpDir, configFileName),
		CertsDir:   filepath.Join(tmpDir, "certs"),
		LogDir:     filepath.Join(tmpDir, "log"),
	}

	cfg := New("https://example.com", paths)

	if cfg.Server != "https://example.com" {
		t.Errorf("Server = %s, want https://example.com", cfg.Server)
	}
	if !cfg.MTLSEnabled {
		t.Error("MTLSEnabled should default to true")
	}
	if cfg.InstallDate == "" {
		t.Error("InstallDate should be set")
	}
}

func TestConfigGetters(t *testing.T) {
	cfg := &Config{
		Server:               "https://example.com",
		UUID:                 "uuid-123",
		MTLSEnabled:          true,
		InstallDate:          "2024-01-01",
		LastConnection:       "2024-01-02",
		LastHeartbeat:        "2024-01-03",
		ReregistrationSecret: "secret",
		TamperProtection:     true,
		UninstallKeyHash:     "hash123",
		WatchdogEnabled:      true,
		TamperAlertEnabled:   true,
	}

	if cfg.GetServer() != "https://example.com" {
		t.Error("GetServer failed")
	}
	if cfg.GetUUID() != "uuid-123" {
		t.Error("GetUUID failed")
	}
	if !cfg.IsMTLSEnabled() {
		t.Error("IsMTLSEnabled failed")
	}
	if cfg.GetInstallDate() != "2024-01-01" {
		t.Error("GetInstallDate failed")
	}
	if cfg.GetLastConnection() != "2024-01-02" {
		t.Error("GetLastConnection failed")
	}
	if cfg.GetLastHeartbeat() != "2024-01-03" {
		t.Error("GetLastHeartbeat failed")
	}
	if cfg.GetReregistrationSecret() != "secret" {
		t.Error("GetReregistrationSecret failed")
	}
	if !cfg.IsTamperProtectionEnabled() {
		t.Error("IsTamperProtectionEnabled failed")
	}
	if cfg.GetUninstallKeyHash() != "hash123" {
		t.Error("GetUninstallKeyHash failed")
	}
	if !cfg.IsWatchdogEnabled() {
		t.Error("IsWatchdogEnabled failed")
	}
	if !cfg.IsTamperAlertEnabled() {
		t.Error("IsTamperAlertEnabled failed")
	}
}

func TestConfigSetters(t *testing.T) {
	cfg := &Config{}

	cfg.SetUUID("new-uuid")
	if cfg.UUID != "new-uuid" {
		t.Error("SetUUID failed")
	}

	cfg.SetLastConnection("2024-02-01")
	if cfg.LastConnection != "2024-02-01" {
		t.Error("SetLastConnection failed")
	}

	cfg.SetLastHeartbeat("2024-02-02")
	if cfg.LastHeartbeat != "2024-02-02" {
		t.Error("SetLastHeartbeat failed")
	}

	cfg.SetReregistrationSecret("new-secret")
	if cfg.ReregistrationSecret != "new-secret" {
		t.Error("SetReregistrationSecret failed")
	}

	cfg.SetTamperProtection(true)
	if !cfg.TamperProtection {
		t.Error("SetTamperProtection failed")
	}

	cfg.SetUninstallKeyHash("new-hash")
	if cfg.UninstallKeyHash != "new-hash" {
		t.Error("SetUninstallKeyHash failed")
	}

	cfg.SetWatchdogEnabled(true)
	if !cfg.WatchdogEnabled {
		t.Error("SetWatchdogEnabled failed")
	}

	cfg.SetTamperAlertEnabled(true)
	if !cfg.TamperAlertEnabled {
		t.Error("SetTamperAlertEnabled failed")
	}
}

func TestEnsureDirectories(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "config_ensure_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	paths := Paths{
		BaseDir:  filepath.Join(tmpDir, "base"),
		CertsDir: filepath.Join(tmpDir, "base", "certs"),
		LogDir:   filepath.Join(tmpDir, "log"),
	}

	if err := EnsureDirectories(paths); err != nil {
		t.Fatalf("EnsureDirectories failed: %v", err)
	}

	// Verify directories were created
	for _, dir := range []string{paths.BaseDir, paths.CertsDir, paths.LogDir} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Errorf("directory %s not created: %v", dir, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s should be a directory", dir)
		}
	}
}

func TestConstants(t *testing.T) {
	if configFileName != ".slimrmm_config.json" {
		t.Errorf("configFileName = %s, want .slimrmm_config.json", configFileName)
	}
	if configFileMode != 0600 {
		t.Errorf("configFileMode = %o, want 0600", configFileMode)
	}
	if certsDirMode != 0700 {
		t.Errorf("certsDirMode = %o, want 0700", certsDirMode)
	}
}

func TestErrors(t *testing.T) {
	if ErrConfigNotFound == nil {
		t.Error("ErrConfigNotFound should not be nil")
	}
	if ErrInvalidConfig == nil {
		t.Error("ErrInvalidConfig should not be nil")
	}

	if ErrConfigNotFound.Error() == "" {
		t.Error("ErrConfigNotFound should have a message")
	}
	if ErrInvalidConfig.Error() == "" {
		t.Error("ErrInvalidConfig should have a message")
	}
}

func TestConcurrentAccess(t *testing.T) {
	cfg := &Config{
		Server: "https://example.com",
		UUID:   "initial",
	}

	done := make(chan bool)

	// Concurrent readers
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = cfg.GetServer()
				_ = cfg.GetUUID()
				_ = cfg.IsMTLSEnabled()
			}
			done <- true
		}()
	}

	// Concurrent writers
	for i := 0; i < 5; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				cfg.SetUUID("uuid-" + string(rune('0'+id)))
				cfg.SetLastConnection("2024-01-01")
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 15; i++ {
		<-done
	}
}

func isInDir(file, dir string) bool {
	rel, err := filepath.Rel(dir, file)
	if err != nil {
		return false
	}
	return !filepath.IsAbs(rel) && rel[:2] != ".."
}
