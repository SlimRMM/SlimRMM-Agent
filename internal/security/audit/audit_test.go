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
