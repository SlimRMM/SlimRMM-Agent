package terminal

import (
	"testing"
	"time"
)

func TestManager(t *testing.T) {
	cfg := Config{
		MaxSessions:         3,
		SessionTimeout:      time.Minute,
		InputRateLimit:      1000,
		MaxInputSize:        1024,
		AllowedShells:       []string{"/bin/bash", "/bin/sh"},
		AuditEnabled:        true,
		BlockDangerousInput: true,
	}

	m := NewManager(cfg)
	defer m.Stop()

	// Test session registration
	if !m.CanStartSession() {
		t.Error("should be able to start session")
	}

	err := m.RegisterSession("session-1", "/bin/bash")
	if err != nil {
		t.Errorf("failed to register session: %v", err)
	}

	if m.GetSessionCount() != 1 {
		t.Errorf("expected 1 session, got %d", m.GetSessionCount())
	}

	// Test session limit
	m.RegisterSession("session-2", "/bin/bash")
	m.RegisterSession("session-3", "/bin/bash")

	err = m.RegisterSession("session-4", "/bin/bash")
	if err != ErrMaxSessionsReached {
		t.Errorf("expected ErrMaxSessionsReached, got %v", err)
	}

	// Test unregister
	m.UnregisterSession("session-1")
	if m.GetSessionCount() != 2 {
		t.Errorf("expected 2 sessions after unregister, got %d", m.GetSessionCount())
	}
}

func TestShellValidation(t *testing.T) {
	cfg := Config{
		MaxSessions:   10,
		AllowedShells: []string{"/bin/bash", "/bin/sh"},
	}

	m := NewManager(cfg)
	defer m.Stop()

	// Allowed shell
	err := m.RegisterSession("test-1", "/bin/bash")
	if err != nil {
		t.Errorf("bash should be allowed: %v", err)
	}

	// Disallowed shell
	err = m.RegisterSession("test-2", "/bin/evil")
	if err != ErrShellNotAllowed {
		t.Errorf("expected ErrShellNotAllowed, got %v", err)
	}
}

func TestInputValidation(t *testing.T) {
	cfg := Config{
		MaxSessions:         10,
		MaxInputSize:        100,
		AllowedShells:       []string{"/bin/bash"},
		BlockDangerousInput: true,
	}

	m := NewManager(cfg)
	defer m.Stop()

	m.RegisterSession("test", "/bin/bash")

	// Valid input
	err := m.ValidateInput("test", []byte("ls -la"))
	if err != nil {
		t.Errorf("valid input should pass: %v", err)
	}

	// Input too large
	largeInput := make([]byte, 200)
	err = m.ValidateInput("test", largeInput)
	if err != ErrInputTooLarge {
		t.Errorf("expected ErrInputTooLarge, got %v", err)
	}

	// Session not found
	err = m.ValidateInput("nonexistent", []byte("test"))
	if err != ErrSessionNotFound {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestDangerousSequenceDetection(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		isDangerous bool
	}{
		{"normal text", []byte("hello world"), false},
		{"normal command", []byte("ls -la /home"), false},
		{"osc sequence", []byte("\x1b]test"), true},
		{"dcs sequence", []byte("\x1bPtest"), true},
		{"title manipulation", []byte("\x1b]0;evil"), true},
		{"cursor hiding", []byte("\x1b[?25l\x1b[test"), true},
		{"normal escape codes", []byte("\x1b[32mgreen\x1b[0m"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsDangerousSequence(tt.input)
			if got != tt.isDangerous {
				t.Errorf("containsDangerousSequence(%q) = %v, want %v", tt.input, got, tt.isDangerous)
			}
		})
	}
}

func TestSessionExpiry(t *testing.T) {
	cfg := Config{
		MaxSessions:    10,
		SessionTimeout: 100 * time.Millisecond,
		AllowedShells:  []string{"/bin/bash"},
	}

	m := NewManager(cfg)
	defer m.Stop()

	m.RegisterSession("expire-test", "/bin/bash")

	// Wait for expiry
	time.Sleep(200 * time.Millisecond)

	// Manually trigger cleanup
	expired := m.cleanupExpired()

	if len(expired) != 1 || expired[0] != "expire-test" {
		t.Errorf("expected expire-test to be expired, got %v", expired)
	}

	if m.GetSessionCount() != 0 {
		t.Errorf("expected 0 sessions after expiry, got %d", m.GetSessionCount())
	}
}

func TestActivityUpdate(t *testing.T) {
	cfg := Config{
		MaxSessions:    10,
		SessionTimeout: time.Hour,
		AllowedShells:  []string{"/bin/bash"},
	}

	m := NewManager(cfg)
	defer m.Stop()

	m.RegisterSession("activity-test", "/bin/bash")

	session, exists := m.GetSession("activity-test")
	if !exists {
		t.Fatal("session should exist")
	}

	originalTime := session.LastActivity

	time.Sleep(10 * time.Millisecond)
	m.UpdateActivity("activity-test")

	session, _ = m.GetSession("activity-test")
	if !session.LastActivity.After(originalTime) {
		t.Error("activity time should be updated")
	}
}

func TestGetStats(t *testing.T) {
	cfg := DefaultConfig()
	m := NewManager(cfg)
	defer m.Stop()

	m.RegisterSession("stats-1", "/bin/bash")
	m.RegisterSession("stats-2", "/bin/bash")

	stats := m.GetStats()

	if stats["active_sessions"].(int) != 2 {
		t.Errorf("expected 2 active sessions, got %v", stats["active_sessions"])
	}

	if stats["max_sessions"].(int) != cfg.MaxSessions {
		t.Errorf("expected max_sessions %d, got %v", cfg.MaxSessions, stats["max_sessions"])
	}
}
