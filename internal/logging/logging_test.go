package logging

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSetup(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "logging_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := Config{
		LogDir:      tmpDir,
		Debug:       true,
		LogToStdout: false,
	}

	logger, cleanup, err := Setup(cfg)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer cleanup()

	if logger == nil {
		t.Fatal("logger should not be nil")
	}

	// Log something
	logger.Info("test message", "key", "value")

	// Check that log file was created
	today := time.Now().Format("2006-01-02")
	logPath := filepath.Join(tmpDir, logFilePrefix+today+logFileSuffix)

	// Allow for file sync
	time.Sleep(100 * time.Millisecond)

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("log file not created: %v", err)
	}

	if info.Size() == 0 {
		t.Error("log file should have content")
	}
}

func TestSetupWithDefaults(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "logging_defaults_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logger, cleanup, err := SetupWithDefaults(tmpDir, false)
	if err != nil {
		t.Fatalf("SetupWithDefaults failed: %v", err)
	}
	defer cleanup()

	if logger == nil {
		t.Fatal("logger should not be nil")
	}
}

func TestSetupWithInvalidDir(t *testing.T) {
	// Try with unwritable directory
	cfg := Config{
		LogDir:      "/nonexistent/path/that/should/not/exist",
		Debug:       false,
		LogToStdout: false,
	}

	// Should fall back to stdout-only logging
	logger, cleanup, err := Setup(cfg)
	if err != nil {
		t.Fatalf("Setup should not error: %v", err)
	}
	defer cleanup()

	if logger == nil {
		t.Fatal("logger should not be nil even with invalid dir")
	}
}

func TestRotatingLoggerWrite(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "rotating_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := Config{
		LogDir:      tmpDir,
		Debug:       false,
		LogToStdout: false,
	}

	logger, cleanup, err := Setup(cfg)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer cleanup()

	// Write multiple log entries
	for i := 0; i < 10; i++ {
		logger.Info("test message", "index", i)
	}

	// Check log file content
	today := time.Now().Format("2006-01-02")
	logPath := filepath.Join(tmpDir, logFilePrefix+today+logFileSuffix)

	time.Sleep(100 * time.Millisecond)

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	if len(content) == 0 {
		t.Error("log file should have content")
	}

	// Should have multiple lines
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) < 10 {
		t.Errorf("expected at least 10 log lines, got %d", len(lines))
	}
}

func TestGetRotatingLogger(t *testing.T) {
	// Before setup, should return nil or existing logger
	_ = GetRotatingLogger()

	tmpDir, err := os.MkdirTemp("", "get_rotating_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := Config{
		LogDir:      tmpDir,
		Debug:       false,
		LogToStdout: false,
	}

	_, cleanup, err := Setup(cfg)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer cleanup()

	rl := GetRotatingLogger()
	if rl == nil {
		t.Fatal("GetRotatingLogger should return logger after Setup")
	}
}

func TestGetCurrentLogFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "current_log_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := Config{
		LogDir:      tmpDir,
		Debug:       false,
		LogToStdout: false,
	}

	_, cleanup, err := Setup(cfg)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer cleanup()

	currentFile := GetCurrentLogFile()
	if currentFile == "" {
		t.Error("GetCurrentLogFile should return path after Setup")
	}

	// Should contain today's date
	today := time.Now().Format("2006-01-02")
	if !strings.Contains(currentFile, today) {
		t.Errorf("current log file should contain today's date: %s", currentFile)
	}
}

func TestGetLogFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "get_logs_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create some log files
	dates := []string{"2024-01-01", "2024-01-02", "2024-01-03"}
	for _, date := range dates {
		path := filepath.Join(tmpDir, logFilePrefix+date+logFileSuffix)
		if err := os.WriteFile(path, []byte("test log"), logFileMode); err != nil {
			t.Fatalf("failed to create test log file: %v", err)
		}
	}

	files, err := GetLogFiles(tmpDir)
	if err != nil {
		t.Fatalf("GetLogFiles failed: %v", err)
	}

	if len(files) != 3 {
		t.Errorf("expected 3 log files, got %d", len(files))
	}

	// Should be sorted newest first
	if !strings.Contains(filepath.Base(files[0]), "2024-01-03") {
		t.Error("log files should be sorted newest first")
	}
}

func TestMarkLogUploaded(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mark_uploaded_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fileName := "agent-2024-01-01.log"
	MarkLogUploaded(tmpDir, fileName)

	// Check tracking file
	trackingPath := filepath.Join(tmpDir, uploadedFileName)
	data, err := os.ReadFile(trackingPath)
	if err != nil {
		t.Fatalf("failed to read tracking file: %v", err)
	}

	var uploaded uploadedLogs
	if err := json.Unmarshal(data, &uploaded); err != nil {
		t.Fatalf("failed to parse tracking file: %v", err)
	}

	if _, ok := uploaded.Files[fileName]; !ok {
		t.Error("log file should be marked as uploaded")
	}
}

func TestLoadUploadedLogs(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "load_uploaded_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Test with non-existent file
	uploaded := loadUploadedLogs(tmpDir)
	if uploaded == nil {
		t.Fatal("loadUploadedLogs should return non-nil")
	}
	if uploaded.Files == nil {
		t.Fatal("Files map should be initialized")
	}

	// Test with existing file
	trackingPath := filepath.Join(tmpDir, uploadedFileName)
	data := `{"files":{"agent-2024-01-01.log":"2024-01-01T12:00:00Z"}}`
	if err := os.WriteFile(trackingPath, []byte(data), logFileMode); err != nil {
		t.Fatalf("failed to write tracking file: %v", err)
	}

	uploaded = loadUploadedLogs(tmpDir)
	if len(uploaded.Files) != 1 {
		t.Errorf("expected 1 uploaded file, got %d", len(uploaded.Files))
	}
}

func TestLoadUploadedLogsInvalidJSON(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "invalid_json_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write invalid JSON
	trackingPath := filepath.Join(tmpDir, uploadedFileName)
	if err := os.WriteFile(trackingPath, []byte("invalid json{"), logFileMode); err != nil {
		t.Fatalf("failed to write tracking file: %v", err)
	}

	// Should return empty map instead of error
	uploaded := loadUploadedLogs(tmpDir)
	if uploaded == nil {
		t.Fatal("loadUploadedLogs should return non-nil even with invalid JSON")
	}
	if uploaded.Files == nil {
		t.Fatal("Files map should be initialized")
	}
}

func TestFindAgentLogFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "find_logs_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create agent log files
	for _, date := range []string{"2024-01-01", "2024-01-02"} {
		path := filepath.Join(tmpDir, logFilePrefix+date+logFileSuffix)
		if err := os.WriteFile(path, []byte("log"), logFileMode); err != nil {
			t.Fatalf("failed to create log file: %v", err)
		}
	}

	// Create non-agent files (should be ignored)
	if err := os.WriteFile(filepath.Join(tmpDir, "other.log"), []byte("other"), logFileMode); err != nil {
		t.Fatalf("failed to create other file: %v", err)
	}
	if err := os.Mkdir(filepath.Join(tmpDir, "subdir"), 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	files, err := findAgentLogFiles(tmpDir)
	if err != nil {
		t.Fatalf("findAgentLogFiles failed: %v", err)
	}

	if len(files) != 2 {
		t.Errorf("expected 2 agent log files, got %d", len(files))
	}
}

func TestConfigStruct(t *testing.T) {
	cfg := Config{
		LogDir:      "/var/log/slimrmm",
		Debug:       true,
		LogToStdout: true,
	}

	if cfg.LogDir != "/var/log/slimrmm" {
		t.Error("LogDir not set correctly")
	}
	if !cfg.Debug {
		t.Error("Debug should be true")
	}
	if !cfg.LogToStdout {
		t.Error("LogToStdout should be true")
	}
}

func TestConstants(t *testing.T) {
	if logFilePrefix != "agent-" {
		t.Errorf("logFilePrefix = %s, want agent-", logFilePrefix)
	}
	if logFileSuffix != ".log" {
		t.Errorf("logFileSuffix = %s, want .log", logFileSuffix)
	}
	if maxLogFiles < 1 {
		t.Error("maxLogFiles should be at least 1")
	}
}

func TestMarkCurrentLogUploaded(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mark_current_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := Config{
		LogDir:      tmpDir,
		Debug:       false,
		LogToStdout: false,
	}

	_, cleanup, err := Setup(cfg)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer cleanup()

	// Mark current log as uploaded
	MarkCurrentLogUploaded()

	// Check tracking file
	uploaded := loadUploadedLogs(tmpDir)
	today := time.Now().Format("2006-01-02")
	fileName := logFilePrefix + today + logFileSuffix

	if _, ok := uploaded.Files[fileName]; !ok {
		t.Error("current log file should be marked as uploaded")
	}
}

func TestSetupWithStdout(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "stdout_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := Config{
		LogDir:      tmpDir,
		Debug:       true,
		LogToStdout: true, // Enable stdout
	}

	logger, cleanup, err := Setup(cfg)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	defer cleanup()

	if logger == nil {
		t.Fatal("logger should not be nil")
	}

	// Should still write to file
	logger.Info("test with stdout")

	today := time.Now().Format("2006-01-02")
	logPath := filepath.Join(tmpDir, logFilePrefix+today+logFileSuffix)

	time.Sleep(100 * time.Millisecond)

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("log file not created: %v", err)
	}

	if info.Size() == 0 {
		t.Error("log file should have content even with stdout enabled")
	}
}
