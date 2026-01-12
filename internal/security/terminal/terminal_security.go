// Package terminal provides security controls for terminal sessions.
// It implements session limits, timeouts, and audit logging.
package terminal

import (
	"context"
	"sync"
	"time"
)

// Config holds terminal security configuration.
type Config struct {
	// MaxSessions is the maximum number of concurrent terminal sessions.
	MaxSessions int

	// SessionTimeout is the maximum duration for an idle terminal session.
	SessionTimeout time.Duration

	// InputRateLimit is the maximum input characters per second.
	InputRateLimit int

	// MaxInputSize is the maximum size of a single input in bytes.
	MaxInputSize int

	// AllowedShells lists shells that can be used for terminal sessions.
	AllowedShells []string

	// AuditEnabled enables audit logging for terminal sessions.
	AuditEnabled bool

	// BlockDangerousInput blocks potentially dangerous terminal input sequences.
	BlockDangerousInput bool
}

// DefaultConfig returns secure default configuration.
func DefaultConfig() Config {
	return Config{
		MaxSessions:         5,                  // Max 5 concurrent terminals
		SessionTimeout:      30 * time.Minute,  // 30 minute idle timeout
		InputRateLimit:      1000,              // 1000 chars/sec max
		MaxInputSize:        64 * 1024,         // 64 KB max input
		AllowedShells:       []string{"/bin/bash", "/bin/sh", "/bin/zsh", "cmd.exe", "powershell.exe"},
		AuditEnabled:        true,
		BlockDangerousInput: true,
	}
}

// Session tracks a terminal session with security metadata.
type Session struct {
	ID           string
	StartedAt    time.Time
	LastActivity time.Time
	InputBytes   int64
	OutputBytes  int64
	Shell        string
	mu           sync.Mutex
}

// Manager provides security controls for terminal sessions.
type Manager struct {
	config   Config
	sessions map[string]*Session
	mu       sync.RWMutex
	stopChan chan struct{}
	stopOnce sync.Once
}

// NewManager creates a new terminal security manager.
func NewManager(cfg Config) *Manager {
	m := &Manager{
		config:   cfg,
		sessions: make(map[string]*Session),
		stopChan: make(chan struct{}),
	}

	// Start session cleanup goroutine
	go m.cleanupLoop()

	return m
}

// CanStartSession checks if a new session can be started.
func (m *Manager) CanStartSession() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions) < m.config.MaxSessions
}

// RegisterSession registers a new terminal session.
func (m *Manager) RegisterSession(id, shell string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.sessions) >= m.config.MaxSessions {
		return ErrMaxSessionsReached
	}

	if !m.isShellAllowed(shell) {
		return ErrShellNotAllowed
	}

	now := time.Now()
	m.sessions[id] = &Session{
		ID:           id,
		StartedAt:    now,
		LastActivity: now,
		Shell:        shell,
	}

	return nil
}

// UnregisterSession removes a terminal session.
func (m *Manager) UnregisterSession(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
}

// ValidateInput validates and sanitizes terminal input.
func (m *Manager) ValidateInput(sessionID string, input []byte) error {
	if len(input) > m.config.MaxInputSize {
		return ErrInputTooLarge
	}

	m.mu.RLock()
	session, exists := m.sessions[sessionID]
	m.mu.RUnlock()

	if !exists {
		return ErrSessionNotFound
	}

	session.mu.Lock()
	session.InputBytes += int64(len(input))
	session.LastActivity = time.Now()
	session.mu.Unlock()

	// Check for dangerous input patterns if enabled
	if m.config.BlockDangerousInput {
		if containsDangerousSequence(input) {
			return ErrDangerousInput
		}
	}

	return nil
}

// UpdateActivity updates the last activity time for a session.
func (m *Manager) UpdateActivity(sessionID string) {
	m.mu.RLock()
	session, exists := m.sessions[sessionID]
	m.mu.RUnlock()

	if exists {
		session.mu.Lock()
		session.LastActivity = time.Now()
		session.mu.Unlock()
	}
}

// GetSession returns session information.
func (m *Manager) GetSession(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	session, exists := m.sessions[id]
	return session, exists
}

// GetSessionCount returns the current number of active sessions.
func (m *Manager) GetSessionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// GetStats returns session statistics.
func (m *Manager) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var totalInput, totalOutput int64
	for _, s := range m.sessions {
		s.mu.Lock()
		totalInput += s.InputBytes
		totalOutput += s.OutputBytes
		s.mu.Unlock()
	}

	return map[string]interface{}{
		"active_sessions": len(m.sessions),
		"max_sessions":    m.config.MaxSessions,
		"total_input":     totalInput,
		"total_output":    totalOutput,
	}
}

// isShellAllowed checks if a shell is in the allowed list.
func (m *Manager) isShellAllowed(shell string) bool {
	for _, allowed := range m.config.AllowedShells {
		if shell == allowed {
			return true
		}
	}
	return false
}

// cleanupLoop periodically cleans up expired sessions.
func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.cleanupExpired()
		}
	}
}

// cleanupExpired removes sessions that have exceeded the timeout.
func (m *Manager) cleanupExpired() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var expired []string
	cutoff := time.Now().Add(-m.config.SessionTimeout)

	for id, session := range m.sessions {
		session.mu.Lock()
		if session.LastActivity.Before(cutoff) {
			expired = append(expired, id)
			delete(m.sessions, id)
		}
		session.mu.Unlock()
	}

	return expired
}

// Stop stops the manager and cleanup goroutines.
func (m *Manager) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopChan)
	})
}

// containsDangerousSequence checks for dangerous terminal escape sequences.
// These could be used for terminal injection attacks.
func containsDangerousSequence(input []byte) bool {
	// Check for common dangerous patterns
	dangerousPatterns := [][]byte{
		// OSC (Operating System Command) sequences that could manipulate terminal
		[]byte("\x1b]"),
		// DCS (Device Control String) sequences
		[]byte("\x1bP"),
		// Terminal title manipulation that could hide commands
		[]byte("\x1b]0;"),
		[]byte("\x1b]2;"),
		// Cursor hiding/showing with potential exploit
		[]byte("\x1b[?25l\x1b["),
	}

	for _, pattern := range dangerousPatterns {
		if containsBytes(input, pattern) {
			return true
		}
	}

	return false
}

// containsBytes checks if b contains sub.
func containsBytes(b, sub []byte) bool {
	for i := 0; i <= len(b)-len(sub); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if b[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// Context key for terminal security context
type contextKey string

const (
	// TerminalContextKey is the context key for terminal security data.
	TerminalContextKey contextKey = "terminal_security"
)

// ContextWithSession adds session info to context.
func ContextWithSession(ctx context.Context, session *Session) context.Context {
	return context.WithValue(ctx, TerminalContextKey, session)
}

// SessionFromContext retrieves session info from context.
func SessionFromContext(ctx context.Context) (*Session, bool) {
	session, ok := ctx.Value(TerminalContextKey).(*Session)
	return session, ok
}
