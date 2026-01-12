// Package ratelimit provides rate limiting functionality for security protection.
// It prevents flooding attacks and excessive resource consumption.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter implements a token bucket rate limiter.
type Limiter struct {
	rate       float64   // Tokens per second
	burst      int       // Maximum burst size
	tokens     float64   // Current tokens
	lastUpdate time.Time // Last update time
	mu         sync.Mutex
}

// New creates a new rate limiter.
// rate is tokens per second, burst is maximum burst size.
func New(rate float64, burst int) *Limiter {
	return &Limiter{
		rate:       rate,
		burst:      burst,
		tokens:     float64(burst),
		lastUpdate: time.Now(),
	}
}

// Allow returns true if the action is allowed under the rate limit.
func (l *Limiter) Allow() bool {
	return l.AllowN(1)
}

// AllowN returns true if n tokens can be consumed.
func (l *Limiter) AllowN(n int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastUpdate).Seconds()
	l.lastUpdate = now

	// Add tokens based on elapsed time
	l.tokens += elapsed * l.rate
	if l.tokens > float64(l.burst) {
		l.tokens = float64(l.burst)
	}

	// Check if we have enough tokens
	if l.tokens >= float64(n) {
		l.tokens -= float64(n)
		return true
	}

	return false
}

// Tokens returns the current number of available tokens.
func (l *Limiter) Tokens() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastUpdate).Seconds()

	tokens := l.tokens + elapsed*l.rate
	if tokens > float64(l.burst) {
		tokens = float64(l.burst)
	}

	return tokens
}

// Reset resets the limiter to full capacity.
func (l *Limiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.tokens = float64(l.burst)
	l.lastUpdate = time.Now()
}

// ActionLimiter provides per-action rate limiting.
type ActionLimiter struct {
	limiters map[string]*Limiter
	defaults Config
	mu       sync.RWMutex
}

// Config holds rate limit configuration for different actions.
type Config struct {
	// Global limits
	GlobalRate  float64 // Overall messages per second
	GlobalBurst int     // Overall burst size

	// Per-action limits
	CommandRate     float64 // Command executions per second
	CommandBurst    int
	TerminalRate    float64 // Terminal inputs per second
	TerminalBurst   int
	FileOpRate      float64 // File operations per second
	FileOpBurst     int
	UploadRate      float64 // Upload chunks per second
	UploadBurst     int
}

// DefaultConfig returns secure default rate limits.
func DefaultConfig() Config {
	return Config{
		GlobalRate:    100, // 100 messages/sec total
		GlobalBurst:   200,
		CommandRate:   5,   // 5 commands/sec
		CommandBurst:  10,
		TerminalRate:  50,  // 50 terminal inputs/sec (typing)
		TerminalBurst: 100,
		FileOpRate:    20,  // 20 file operations/sec
		FileOpBurst:   50,
		UploadRate:    100, // 100 chunks/sec for uploads
		UploadBurst:   200,
	}
}

// NewActionLimiter creates a new per-action rate limiter.
func NewActionLimiter(cfg Config) *ActionLimiter {
	al := &ActionLimiter{
		limiters: make(map[string]*Limiter),
		defaults: cfg,
	}

	// Create default limiters
	al.limiters["global"] = New(cfg.GlobalRate, cfg.GlobalBurst)
	al.limiters["command"] = New(cfg.CommandRate, cfg.CommandBurst)
	al.limiters["terminal"] = New(cfg.TerminalRate, cfg.TerminalBurst)
	al.limiters["file"] = New(cfg.FileOpRate, cfg.FileOpBurst)
	al.limiters["upload"] = New(cfg.UploadRate, cfg.UploadBurst)

	return al
}

// AllowGlobal checks global rate limit.
func (al *ActionLimiter) AllowGlobal() bool {
	al.mu.RLock()
	defer al.mu.RUnlock()
	return al.limiters["global"].Allow()
}

// AllowCommand checks command rate limit.
func (al *ActionLimiter) AllowCommand() bool {
	al.mu.RLock()
	defer al.mu.RUnlock()

	// Must pass both global and command limits
	if !al.limiters["global"].Allow() {
		return false
	}
	return al.limiters["command"].Allow()
}

// AllowTerminal checks terminal rate limit.
func (al *ActionLimiter) AllowTerminal() bool {
	al.mu.RLock()
	defer al.mu.RUnlock()

	if !al.limiters["global"].Allow() {
		return false
	}
	return al.limiters["terminal"].Allow()
}

// AllowFileOp checks file operation rate limit.
func (al *ActionLimiter) AllowFileOp() bool {
	al.mu.RLock()
	defer al.mu.RUnlock()

	if !al.limiters["global"].Allow() {
		return false
	}
	return al.limiters["file"].Allow()
}

// AllowUpload checks upload rate limit.
func (al *ActionLimiter) AllowUpload() bool {
	al.mu.RLock()
	defer al.mu.RUnlock()

	if !al.limiters["global"].Allow() {
		return false
	}
	return al.limiters["upload"].Allow()
}

// Allow checks rate limit for a specific action type.
func (al *ActionLimiter) Allow(action string) bool {
	// Map actions to rate limit categories
	switch action {
	case "execute_command", "run_command", "shell":
		return al.AllowCommand()
	case "terminal", "terminal_input", "terminal_resize":
		return al.AllowTerminal()
	case "list_dir", "read_file", "write_file", "delete_entry", "download_file":
		return al.AllowFileOp()
	case "upload_chunk", "start_upload", "finish_upload":
		return al.AllowUpload()
	default:
		return al.AllowGlobal()
	}
}

// GetStats returns rate limiter statistics.
func (al *ActionLimiter) GetStats() map[string]float64 {
	al.mu.RLock()
	defer al.mu.RUnlock()

	stats := make(map[string]float64)
	for name, limiter := range al.limiters {
		stats[name+"_tokens"] = limiter.Tokens()
	}
	return stats
}
