package tamper

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.Enabled {
		t.Error("Enabled should default to true")
	}
	if !cfg.WatchdogEnabled {
		t.Error("WatchdogEnabled should default to true")
	}
	if !cfg.AlertOnTamper {
		t.Error("AlertOnTamper should default to true")
	}
}

func TestNew(t *testing.T) {
	cfg := DefaultConfig()

	// With nil logger
	p := New(cfg, nil)
	if p == nil {
		t.Fatal("New returned nil")
	}
	if p.logger == nil {
		t.Error("logger should be set to default")
	}

	// With custom logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	p = New(cfg, logger)
	if p == nil {
		t.Fatal("New returned nil")
	}
	if p.fileHashes == nil {
		t.Error("fileHashes map should be initialized")
	}
}

func TestSetTamperCallback(t *testing.T) {
	cfg := DefaultConfig()
	p := New(cfg, nil)

	called := false
	p.SetTamperCallback(func(event TamperEvent) {
		called = true
	})

	// Trigger a tamper event manually
	p.reportTamper(TamperEvent{
		Type:      TamperTypeUninstall,
		Details:   "test",
		Timestamp: time.Now(),
	})

	if !called {
		t.Error("tamper callback should have been called")
	}
}

func TestSetServiceStopCallback(t *testing.T) {
	cfg := DefaultConfig()
	p := New(cfg, nil)

	p.SetServiceStopCallback(func() bool {
		return true
	})

	if !p.CanStopService() {
		t.Error("CanStopService should return true from callback")
	}
}

func TestCanStopServiceDisabled(t *testing.T) {
	cfg := Config{Enabled: false}
	p := New(cfg, nil)

	if !p.CanStopService() {
		t.Error("CanStopService should return true when protection disabled")
	}
}

func TestCanStopServiceNoCallback(t *testing.T) {
	cfg := Config{Enabled: true}
	p := New(cfg, nil)

	// No callback set, should default to false
	if p.CanStopService() {
		t.Error("CanStopService should return false when no callback and protection enabled")
	}
}

func TestValidateUninstallKeyNoKey(t *testing.T) {
	cfg := Config{Enabled: true, UninstallKeyHash: ""}
	p := New(cfg, nil)

	// No key configured, should allow
	if err := p.ValidateUninstallKey("anything"); err != nil {
		t.Errorf("ValidateUninstallKey should allow when no key configured: %v", err)
	}
}

func TestValidateUninstallKeyValid(t *testing.T) {
	key := "test-key-123"
	hash := sha256.Sum256([]byte(key))
	hashStr := hex.EncodeToString(hash[:])

	cfg := Config{Enabled: true, UninstallKeyHash: hashStr}
	p := New(cfg, nil)

	if err := p.ValidateUninstallKey(key); err != nil {
		t.Errorf("ValidateUninstallKey should pass for valid key: %v", err)
	}
}

func TestValidateUninstallKeyInvalid(t *testing.T) {
	key := "test-key-123"
	hash := sha256.Sum256([]byte(key))
	hashStr := hex.EncodeToString(hash[:])

	cfg := Config{Enabled: true, UninstallKeyHash: hashStr}
	p := New(cfg, nil)

	err := p.ValidateUninstallKey("wrong-key")
	if err != ErrInvalidUninstallKey {
		t.Errorf("ValidateUninstallKey should return ErrInvalidUninstallKey, got %v", err)
	}
}

func TestSetUninstallKey(t *testing.T) {
	cfg := Config{Enabled: true}
	p := New(cfg, nil)

	key := "my-secure-key"
	hashStr := p.SetUninstallKey(key)

	if hashStr == "" {
		t.Error("SetUninstallKey should return hash string")
	}
	if len(hashStr) != 64 { // SHA-256 produces 64 hex chars
		t.Errorf("hash length = %d, want 64", len(hashStr))
	}

	// Verify the key now validates
	if err := p.ValidateUninstallKey(key); err != nil {
		t.Errorf("key should validate after SetUninstallKey: %v", err)
	}
}

func TestStartDisabled(t *testing.T) {
	cfg := Config{Enabled: false}
	p := New(cfg, nil)

	if err := p.Start(); err != nil {
		t.Errorf("Start should not error when disabled: %v", err)
	}
}

func TestStartAndStop(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tamper_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	cfg := Config{
		Enabled:         true,
		AlertOnTamper:   true,
		ProtectedPaths:  []string{testFile},
		WatchdogEnabled: false,
	}
	p := New(cfg, nil)

	if err := p.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Give the goroutine time to start
	time.Sleep(50 * time.Millisecond)

	p.Stop()
}

func TestHashFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "hash_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "test.txt")
	content := "test content for hashing"
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	cfg := DefaultConfig()
	p := New(cfg, nil)

	hash, err := p.hashFile(testFile)
	if err != nil {
		t.Fatalf("hashFile failed: %v", err)
	}

	if hash == "" {
		t.Error("hash should not be empty")
	}
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}

	// Hash again, should be the same
	hash2, err := p.hashFile(testFile)
	if err != nil {
		t.Fatalf("hashFile failed: %v", err)
	}
	if hash != hash2 {
		t.Error("same file should have same hash")
	}

	// Modify file, hash should change
	if err := os.WriteFile(testFile, []byte("different content"), 0644); err != nil {
		t.Fatalf("failed to modify file: %v", err)
	}

	hash3, err := p.hashFile(testFile)
	if err != nil {
		t.Fatalf("hashFile failed: %v", err)
	}
	if hash == hash3 {
		t.Error("modified file should have different hash")
	}
}

func TestHashFileNotFound(t *testing.T) {
	cfg := DefaultConfig()
	p := New(cfg, nil)

	_, err := p.hashFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("hashFile should fail for nonexistent file")
	}
}

func TestGetProtectedPaths(t *testing.T) {
	// With custom paths
	customPaths := []string{"/custom/path1", "/custom/path2"}
	cfg := Config{
		ProtectedPaths: customPaths,
	}
	p := New(cfg, nil)

	paths := p.getProtectedPaths()
	if len(paths) != 2 {
		t.Errorf("expected 2 custom paths, got %d", len(paths))
	}

	// Without custom paths (defaults)
	cfg = Config{}
	p = New(cfg, nil)

	paths = p.getProtectedPaths()
	// Should have default paths for the current OS
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" || runtime.GOOS == "windows" {
		if len(paths) == 0 {
			t.Error("should have default protected paths")
		}
	}
}

func TestGetBinaryPath(t *testing.T) {
	path := GetBinaryPath()
	if path == "" {
		t.Error("GetBinaryPath should return a path")
	}

	switch runtime.GOOS {
	case "darwin":
		if path != "/Applications/SlimRMM.app/Contents/MacOS/slimrmm-agent" {
			t.Errorf("darwin path = %s", path)
		}
	case "linux":
		if path != "/usr/local/bin/slimrmm-agent" {
			t.Errorf("linux path = %s", path)
		}
	}
}

func TestGetConfigPath(t *testing.T) {
	path := GetConfigPath()
	if path == "" {
		t.Error("GetConfigPath should return a path")
	}

	switch runtime.GOOS {
	case "darwin":
		if path != "/Applications/SlimRMM.app/Contents/Data/.slimrmm_config.json" {
			t.Errorf("darwin path = %s", path)
		}
	case "linux":
		if path != "/var/lib/slimrmm/.slimrmm_config.json" {
			t.Errorf("linux path = %s", path)
		}
	}
}

func TestTamperTypes(t *testing.T) {
	types := []TamperType{
		TamperTypeFileModified,
		TamperTypeFileDeleted,
		TamperTypeServiceStopped,
		TamperTypeUninstall,
		TamperTypeConfigChanged,
	}

	for _, tt := range types {
		if tt == "" {
			t.Error("TamperType should not be empty")
		}
	}
}

func TestTamperEvent(t *testing.T) {
	event := TamperEvent{
		Type:      TamperTypeFileModified,
		Path:      "/path/to/file",
		Details:   "file was modified",
		Timestamp: time.Now(),
	}

	if event.Type != TamperTypeFileModified {
		t.Error("Type not set correctly")
	}
	if event.Path != "/path/to/file" {
		t.Error("Path not set correctly")
	}
}

func TestErrors(t *testing.T) {
	if ErrInvalidUninstallKey == nil {
		t.Error("ErrInvalidUninstallKey should not be nil")
	}
	if ErrTamperDetected == nil {
		t.Error("ErrTamperDetected should not be nil")
	}
	if ErrProtectionActive == nil {
		t.Error("ErrProtectionActive should not be nil")
	}

	if ErrInvalidUninstallKey.Error() == "" {
		t.Error("ErrInvalidUninstallKey should have message")
	}
}

func TestPrepareForUpdateDisabled(t *testing.T) {
	cfg := Config{Enabled: false}
	p := New(cfg, nil)

	if err := p.PrepareForUpdate(); err != nil {
		t.Errorf("PrepareForUpdate should not error when disabled: %v", err)
	}
}

func TestRestoreAfterUpdateDisabled(t *testing.T) {
	cfg := Config{Enabled: false}
	p := New(cfg, nil)

	if err := p.RestoreAfterUpdate(); err != nil {
		t.Errorf("RestoreAfterUpdate should not error when disabled: %v", err)
	}
}

func TestInitializeFileHashes(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "hash_init_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test files
	file1 := filepath.Join(tmpDir, "file1.txt")
	file2 := filepath.Join(tmpDir, "file2.txt")
	if err := os.WriteFile(file1, []byte("content1"), 0644); err != nil {
		t.Fatalf("failed to create file1: %v", err)
	}
	if err := os.WriteFile(file2, []byte("content2"), 0644); err != nil {
		t.Fatalf("failed to create file2: %v", err)
	}

	cfg := Config{
		Enabled:        true,
		ProtectedPaths: []string{file1, file2, filepath.Join(tmpDir, "nonexistent")},
	}
	p := New(cfg, nil)

	if err := p.initializeFileHashes(); err != nil {
		t.Fatalf("initializeFileHashes failed: %v", err)
	}

	// Check hashes were stored
	p.mu.RLock()
	hash1, ok1 := p.fileHashes[file1]
	hash2, ok2 := p.fileHashes[file2]
	p.mu.RUnlock()

	if !ok1 || hash1 == "" {
		t.Error("file1 hash should be stored")
	}
	if !ok2 || hash2 == "" {
		t.Error("file2 hash should be stored")
	}
}

func TestReportTamperNoAlert(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		AlertOnTamper: false,
	}
	p := New(cfg, nil)

	called := false
	p.SetTamperCallback(func(event TamperEvent) {
		called = true
	})

	p.reportTamper(TamperEvent{
		Type:      TamperTypeFileModified,
		Details:   "test",
		Timestamp: time.Now(),
	})

	if called {
		t.Error("callback should not be called when AlertOnTamper is false")
	}
}

func TestCheckFileIntegrity(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "integrity_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("original"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	cfg := Config{
		Enabled:        true,
		AlertOnTamper:  true,
		ProtectedPaths: []string{testFile},
	}
	p := New(cfg, nil)

	// Initialize hashes
	if err := p.initializeFileHashes(); err != nil {
		t.Fatalf("initializeFileHashes failed: %v", err)
	}

	var tamperEvent *TamperEvent
	p.SetTamperCallback(func(event TamperEvent) {
		tamperEvent = &event
	})

	// Modify file
	if err := os.WriteFile(testFile, []byte("modified"), 0644); err != nil {
		t.Fatalf("failed to modify test file: %v", err)
	}

	// Check integrity
	p.checkFileIntegrity()

	if tamperEvent == nil {
		t.Error("should have detected file modification")
	} else if tamperEvent.Type != TamperTypeFileModified {
		t.Errorf("event type = %s, want %s", tamperEvent.Type, TamperTypeFileModified)
	}
}

func TestCheckFileIntegrityDeleted(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "integrity_delete_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("content"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	cfg := Config{
		Enabled:        true,
		AlertOnTamper:  true,
		ProtectedPaths: []string{testFile},
	}
	p := New(cfg, nil)

	if err := p.initializeFileHashes(); err != nil {
		t.Fatalf("initializeFileHashes failed: %v", err)
	}

	var tamperEvent *TamperEvent
	p.SetTamperCallback(func(event TamperEvent) {
		tamperEvent = &event
	})

	// Delete file
	if err := os.Remove(testFile); err != nil {
		t.Fatalf("failed to delete test file: %v", err)
	}

	p.checkFileIntegrity()

	if tamperEvent == nil {
		t.Error("should have detected file deletion")
	} else if tamperEvent.Type != TamperTypeFileDeleted {
		t.Errorf("event type = %s, want %s", tamperEvent.Type, TamperTypeFileDeleted)
	}
}
