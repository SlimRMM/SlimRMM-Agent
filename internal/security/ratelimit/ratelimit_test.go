package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	// Create a limiter with 10 tokens/sec and burst of 5
	l := New(10, 5)

	// Should allow 5 immediate requests (burst)
	for i := 0; i < 5; i++ {
		if !l.Allow() {
			t.Errorf("request %d should be allowed (within burst)", i+1)
		}
	}

	// 6th request should be denied (exhausted burst)
	if l.Allow() {
		t.Error("6th request should be denied")
	}

	// Wait for token refresh
	time.Sleep(200 * time.Millisecond)

	// Should allow one more request (2 tokens regenerated at 10/sec)
	if !l.Allow() {
		t.Error("request after wait should be allowed")
	}
}

func TestLimiterReset(t *testing.T) {
	l := New(1, 3)

	// Exhaust tokens
	for i := 0; i < 3; i++ {
		l.Allow()
	}

	if l.Allow() {
		t.Error("should be rate limited")
	}

	// Reset
	l.Reset()

	// Should allow again
	if !l.Allow() {
		t.Error("should allow after reset")
	}
}

func TestActionLimiter(t *testing.T) {
	cfg := Config{
		GlobalRate:   100,
		GlobalBurst:  200,
		CommandRate:  5,
		CommandBurst: 10,
		TerminalRate: 50,
		TerminalBurst: 100,
		FileOpRate:   20,
		FileOpBurst:  50,
		UploadRate:   100,
		UploadBurst:  200,
	}

	al := NewActionLimiter(cfg)

	// Test command rate limiting
	for i := 0; i < 10; i++ {
		if !al.AllowCommand() {
			t.Errorf("command %d should be allowed (within burst)", i+1)
		}
	}

	// 11th command should be rate limited
	if al.AllowCommand() {
		t.Error("11th command should be rate limited")
	}

	// Test action mapping
	tests := []struct {
		action   string
		category string
	}{
		{"execute_command", "command"},
		{"terminal_input", "terminal"},
		{"list_dir", "file"},
		{"upload_chunk", "upload"},
		{"ping", "global"},
	}

	// Reset by creating new limiter
	al = NewActionLimiter(cfg)

	for _, tt := range tests {
		if !al.Allow(tt.action) {
			t.Errorf("action %s should be allowed initially", tt.action)
		}
	}
}

func TestGetStats(t *testing.T) {
	cfg := DefaultConfig()
	al := NewActionLimiter(cfg)

	stats := al.GetStats()

	expectedKeys := []string{
		"global_tokens",
		"command_tokens",
		"terminal_tokens",
		"file_tokens",
		"upload_tokens",
	}

	for _, key := range expectedKeys {
		if _, ok := stats[key]; !ok {
			t.Errorf("missing stat key: %s", key)
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.GlobalRate <= 0 {
		t.Error("GlobalRate should be positive")
	}
	if cfg.GlobalBurst <= 0 {
		t.Error("GlobalBurst should be positive")
	}
	if cfg.CommandRate <= 0 {
		t.Error("CommandRate should be positive")
	}
}
