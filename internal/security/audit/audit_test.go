package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditLogger(t *testing.T) {
	// Create temp directory for test logs
	tmpDir, err := os.MkdirTemp("", "audit_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "audit.log")
	cfg := Config{
		Enabled:     true,
		LogPath:     logPath,
		MaxFileSize: 1024 * 1024, // 1 MB
	}

	logger, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	// Test logging events
	ctx := context.Background()

	// Log a connect event
	logger.LogConnect(ctx, true, "https://example.com", nil)

	// Log a command event
	logger.LogCommand(ctx, "ls -la", "req-123", true, false, "", time.Second)

	// Log a blocked command
	logger.LogCommand(ctx, "rm -rf /", "req-456", false, true, "dangerous_command", 0)

	// Log a terminal event
	logger.LogTerminal(ctx, EventTerminalStart, "term-001", map[string]interface{}{
		"shell": "/bin/bash",
	})

	// Log a file operation
	logger.LogFileOp(ctx, EventFileRead, "/etc/hosts", true, nil)

	// Log a security event
	logger.LogSecurity(ctx, EventTamperDetected, SeverityCritical, map[string]interface{}{
		"path":   "/var/lib/slimrmm/config.json",
		"action": "modified",
	})

	// Check that log file was created and has content
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("log file not created: %v", err)
	}

	if info.Size() == 0 {
		t.Error("log file is empty")
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is a long string", 10, "this is a ..."},
		{"", 5, ""},
	}

	for _, tt := range tests {
		got := truncateString(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}

func TestSeverityToLevel(t *testing.T) {
	tests := []struct {
		severity Severity
		name     string
	}{
		{SeverityInfo, "info"},
		{SeverityWarning, "warning"},
		{SeverityError, "error"},
		{SeverityCritical, "critical"},
	}

	for _, tt := range tests {
		level := severityToLevel(tt.severity)
		if level < 0 && tt.severity != SeverityInfo {
			t.Errorf("unexpected level for severity %s", tt.name)
		}
	}
}

func TestLogBackupOperations(t *testing.T) {
	// Create temp directory for test logs
	tmpDir, err := os.MkdirTemp("", "audit_backup_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "audit.log")
	cfg := Config{
		Enabled:     true,
		LogPath:     logPath,
		MaxFileSize: 1024 * 1024,
	}

	logger, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	// Test LogBackupStart
	logger.LogBackupStart(ctx, "files_and_folders", "backup-123", map[string]interface{}{
		"paths": []string{"/home/user"},
	})

	// Test LogBackupComplete
	logger.LogBackupComplete(ctx, "files_and_folders", "backup-123", time.Second*5, map[string]interface{}{
		"files_count": 100,
		"total_size":  1024000,
	})

	// Test LogBackupFailed
	logger.LogBackupFailed(ctx, "postgresql", "backup-456",
		os.ErrNotExist, map[string]interface{}{
			"database": "mydb",
		})

	// Test LogDatabaseBackup success
	logger.LogDatabaseBackup(ctx, true, "postgresql", "production", time.Second*10, nil)

	// Test LogDatabaseBackup failure
	logger.LogDatabaseBackup(ctx, false, "mysql", "staging", time.Second*2, os.ErrPermission)

	// Test LogBackupPathAccess
	logger.LogBackupPathAccess(ctx, "/var/lib/data", "backup_read", true)

	// Verify log file exists and has content
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("log file not created: %v", err)
	}
	if info.Size() == 0 {
		t.Error("log file is empty")
	}
}

func TestLogSnapshot(t *testing.T) {
	// Create temp directory for test logs
	tmpDir, err := os.MkdirTemp("", "audit_snapshot_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "audit.log")
	cfg := Config{
		Enabled:     true,
		LogPath:     logPath,
		MaxFileSize: 1024 * 1024,
	}

	logger, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	// Test snapshot create success
	logger.LogSnapshot(ctx, EventSnapshotCreate, "snap-123", "uninstall-456", true,
		map[string]interface{}{
			"installation_type": "winget",
			"package_id":        "Microsoft.VSCode",
		}, nil)

	// Test snapshot create failure
	logger.LogSnapshot(ctx, EventSnapshotCreate, "snap-789", "uninstall-101", false,
		map[string]interface{}{
			"installation_type": "homebrew_cask",
		}, os.ErrPermission)

	// Test snapshot restore
	logger.LogSnapshot(ctx, EventSnapshotRestore, "snap-123", "uninstall-456", true, nil, nil)

	// Test snapshot delete
	logger.LogSnapshot(ctx, EventSnapshotDelete, "snap-123", "uninstall-456", true, nil, nil)

	// Verify log file exists and has content
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("log file not created: %v", err)
	}
	if info.Size() == 0 {
		t.Error("log file is empty")
	}
}

func TestLogRateLimitAndReplay(t *testing.T) {
	// Create temp directory for test logs
	tmpDir, err := os.MkdirTemp("", "audit_security_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	logPath := filepath.Join(tmpDir, "audit.log")
	cfg := Config{
		Enabled:     true,
		LogPath:     logPath,
		MaxFileSize: 1024 * 1024,
	}

	logger, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	// Test rate limit logging
	logger.LogRateLimit(ctx, "file_download", 100, 50)

	// Test replay attempt logging
	logger.LogReplayAttempt(ctx, "req-789", time.Now().Add(-time.Hour))

	// Verify log file exists and has content
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("log file not created: %v", err)
	}
	if info.Size() == 0 {
		t.Error("log file is empty")
	}
}

func TestDisabledLogger(t *testing.T) {
	cfg := Config{
		Enabled: false,
	}

	logger, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	// These should not panic even when disabled
	logger.LogConnect(ctx, true, "https://example.com", nil)
	logger.LogCommand(ctx, "ls", "req-1", true, false, "", time.Second)
	logger.LogSnapshot(ctx, EventSnapshotCreate, "snap-1", "uninstall-1", true, nil, nil)
	logger.LogBackupStart(ctx, "config", "backup-1", nil)
}

func TestEventTypes(t *testing.T) {
	// Test that all event type constants are defined
	eventTypes := []EventType{
		EventConnectAttempt, EventConnectSuccess, EventConnectFailure, EventDisconnect,
		EventAuthSuccess, EventAuthFailure, EventCertRenewal, EventCertExpiry,
		EventCommandRequest, EventCommandExecute, EventCommandBlocked, EventCommandComplete,
		EventTerminalStart, EventTerminalInput, EventTerminalStop,
		EventFileRead, EventFileWrite, EventFileDelete, EventFileBlocked,
		EventUploadStart, EventUploadChunk, EventUploadFinish, EventDownload, EventDownloadURL,
		EventTamperDetected, EventUninstallAttempt, EventRateLimitExceeded,
		EventReplayAttempt, EventPathTraversal, EventDangerousPattern,
		EventComplianceCheck, EventComplianceResult,
		EventBackupStart, EventBackupComplete, EventBackupFailed,
		EventBackupDatabaseStart, EventBackupDatabaseComplete, EventBackupDatabaseFailed,
		EventBackupPathAccess,
		EventSnapshotCreate, EventSnapshotRestore, EventSnapshotDelete,
	}

	for _, et := range eventTypes {
		if et == "" {
			t.Error("event type should not be empty")
		}
	}
}

func TestSeverityConstants(t *testing.T) {
	severities := []Severity{
		SeverityInfo,
		SeverityWarning,
		SeverityError,
		SeverityCritical,
	}

	for _, s := range severities {
		if s == "" {
			t.Error("severity should not be empty")
		}
	}
}
