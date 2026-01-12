// Package audit provides security event logging and audit trail functionality.
// It logs security-relevant events for compliance and intrusion detection.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// EventType represents the type of security event.
type EventType string

const (
	// Connection events
	EventConnectAttempt EventType = "connect_attempt"
	EventConnectSuccess EventType = "connect_success"
	EventConnectFailure EventType = "connect_failure"
	EventDisconnect     EventType = "disconnect"

	// Authentication events
	EventAuthSuccess EventType = "auth_success"
	EventAuthFailure EventType = "auth_failure"
	EventCertRenewal EventType = "cert_renewal"
	EventCertExpiry  EventType = "cert_expiry"

	// Command events
	EventCommandRequest  EventType = "command_request"
	EventCommandExecute  EventType = "command_execute"
	EventCommandBlocked  EventType = "command_blocked"
	EventCommandComplete EventType = "command_complete"

	// Terminal events
	EventTerminalStart EventType = "terminal_start"
	EventTerminalInput EventType = "terminal_input"
	EventTerminalStop  EventType = "terminal_stop"

	// File events
	EventFileRead     EventType = "file_read"
	EventFileWrite    EventType = "file_write"
	EventFileDelete   EventType = "file_delete"
	EventFileBlocked  EventType = "file_blocked"
	EventUploadStart  EventType = "upload_start"
	EventUploadChunk  EventType = "upload_chunk"
	EventUploadFinish EventType = "upload_finish"
	EventDownload     EventType = "download"
	EventDownloadURL  EventType = "download_url"

	// Security events
	EventTamperDetected    EventType = "tamper_detected"
	EventUninstallAttempt  EventType = "uninstall_attempt"
	EventRateLimitExceeded EventType = "rate_limit_exceeded"
	EventReplayAttempt     EventType = "replay_attempt"
	EventPathTraversal     EventType = "path_traversal"
	EventDangerousPattern  EventType = "dangerous_pattern"

	// Compliance events
	EventComplianceCheck  EventType = "compliance_check"
	EventComplianceResult EventType = "compliance_result"
)

// Severity represents the severity level of a security event.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

// Event represents a security audit event.
type Event struct {
	Timestamp   time.Time              `json:"timestamp"`
	EventType   EventType              `json:"event_type"`
	Severity    Severity               `json:"severity"`
	Source      string                 `json:"source"`
	Action      string                 `json:"action,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
	User        string                 `json:"user,omitempty"`
	RemoteAddr  string                 `json:"remote_addr,omitempty"`
	Path        string                 `json:"path,omitempty"`
	Command     string                 `json:"command,omitempty"`
	TerminalID  string                 `json:"terminal_id,omitempty"`
	Success     bool                   `json:"success"`
	Error       string                 `json:"error,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Duration    time.Duration          `json:"duration_ns,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	ProcessID   int                    `json:"pid"`
}

// Logger provides security audit logging functionality.
type Logger struct {
	logger      *slog.Logger
	file        *os.File
	mu          sync.Mutex
	sessionID   string
	enabled     bool
	logPath     string
	maxFileSize int64
}

// Config holds audit logger configuration.
type Config struct {
	Enabled     bool
	LogPath     string
	MaxFileSize int64 // Max size in bytes before rotation
}

// DefaultConfig returns the default audit configuration.
func DefaultConfig() Config {
	var logPath string
	switch runtime.GOOS {
	case "windows":
		logPath = filepath.Join(os.Getenv("ProgramFiles"), "SlimRMM", "log", "audit.log")
	case "darwin":
		logPath = "/Library/Logs/SlimRMM/audit.log"
	default:
		logPath = "/var/log/slimrmm/audit.log"
	}

	return Config{
		Enabled:     true,
		LogPath:     logPath,
		MaxFileSize: 50 * 1024 * 1024, // 50 MB
	}
}

var (
	globalLogger     *Logger
	globalLoggerOnce sync.Once
)

// GetLogger returns the global audit logger singleton.
func GetLogger() *Logger {
	globalLoggerOnce.Do(func() {
		cfg := DefaultConfig()
		logger, err := New(cfg, nil)
		if err != nil {
			// Fallback to stdout-only logging
			globalLogger = &Logger{
				logger:    slog.Default(),
				enabled:   true,
				sessionID: generateSessionID(),
			}
			return
		}
		globalLogger = logger
	})
	return globalLogger
}

// New creates a new audit logger.
func New(cfg Config, baseLogger *slog.Logger) (*Logger, error) {
	l := &Logger{
		enabled:     cfg.Enabled,
		logPath:     cfg.LogPath,
		maxFileSize: cfg.MaxFileSize,
		sessionID:   generateSessionID(),
	}

	if baseLogger != nil {
		l.logger = baseLogger
	} else {
		l.logger = slog.Default()
	}

	if cfg.LogPath != "" {
		// Ensure directory exists
		dir := filepath.Dir(cfg.LogPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("creating audit log directory: %w", err)
		}

		// Open audit log file
		file, err := os.OpenFile(cfg.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, fmt.Errorf("opening audit log: %w", err)
		}
		l.file = file
	}

	return l, nil
}

// generateSessionID creates a unique session ID for this agent instance.
func generateSessionID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
}

// Log records a security event.
func (l *Logger) Log(ctx context.Context, event Event) {
	if !l.enabled {
		return
	}

	event.Timestamp = time.Now().UTC()
	event.SessionID = l.sessionID
	event.ProcessID = os.Getpid()

	// Log to slog
	l.logger.LogAttrs(ctx, severityToLevel(event.Severity),
		fmt.Sprintf("[AUDIT] %s", event.EventType),
		slog.String("event_type", string(event.EventType)),
		slog.String("severity", string(event.Severity)),
		slog.String("source", event.Source),
		slog.Bool("success", event.Success),
		slog.Any("details", event.Details),
	)

	// Write to audit file
	if l.file != nil {
		l.mu.Lock()
		defer l.mu.Unlock()

		data, err := json.Marshal(event)
		if err == nil {
			l.file.Write(append(data, '\n'))
			l.maybeRotate()
		}
	}
}

// maybeRotate checks if the log file needs rotation.
func (l *Logger) maybeRotate() {
	if l.file == nil || l.maxFileSize == 0 {
		return
	}

	info, err := l.file.Stat()
	if err != nil {
		return
	}

	if info.Size() < l.maxFileSize {
		return
	}

	// Close current file
	l.file.Close()

	// Rotate file
	rotatedPath := fmt.Sprintf("%s.%d", l.logPath, time.Now().Unix())
	os.Rename(l.logPath, rotatedPath)

	// Open new file
	file, err := os.OpenFile(l.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		l.file = nil
		return
	}
	l.file = file
}

// severityToLevel converts Severity to slog.Level.
func severityToLevel(s Severity) slog.Level {
	switch s {
	case SeverityCritical:
		return slog.LevelError
	case SeverityError:
		return slog.LevelError
	case SeverityWarning:
		return slog.LevelWarn
	default:
		return slog.LevelInfo
	}
}

// Close closes the audit logger.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Convenience methods for common events

// LogConnect logs a connection event.
func (l *Logger) LogConnect(ctx context.Context, success bool, serverURL string, err error) {
	eventType := EventConnectSuccess
	severity := SeverityInfo
	if !success {
		eventType = EventConnectFailure
		severity = SeverityWarning
	}

	event := Event{
		EventType: eventType,
		Severity:  severity,
		Source:    "handler",
		Success:   success,
		Details: map[string]interface{}{
			"server_url": serverURL,
		},
	}
	if err != nil {
		event.Error = err.Error()
	}

	l.Log(ctx, event)
}

// LogCommand logs a command execution event.
func (l *Logger) LogCommand(ctx context.Context, command string, requestID string, success bool, blocked bool, blockReason string, duration time.Duration) {
	eventType := EventCommandExecute
	severity := SeverityInfo
	if blocked {
		eventType = EventCommandBlocked
		severity = SeverityWarning
	}

	event := Event{
		EventType: eventType,
		Severity:  severity,
		Source:    "commands",
		Command:   truncateString(command, 500), // Limit command length in logs
		RequestID: requestID,
		Success:   success,
		Duration:  duration,
		Details:   map[string]interface{}{},
	}
	if blocked {
		event.Details["block_reason"] = blockReason
	}

	l.Log(ctx, event)
}

// LogTerminal logs a terminal event.
func (l *Logger) LogTerminal(ctx context.Context, eventType EventType, terminalID string, details map[string]interface{}) {
	event := Event{
		EventType:  eventType,
		Severity:   SeverityInfo,
		Source:     "terminal",
		TerminalID: terminalID,
		Success:    true,
		Details:    details,
	}

	l.Log(ctx, event)
}

// LogFileOp logs a file operation event.
func (l *Logger) LogFileOp(ctx context.Context, eventType EventType, path string, success bool, err error) {
	severity := SeverityInfo
	if eventType == EventFileBlocked || eventType == EventPathTraversal {
		severity = SeverityWarning
	}

	event := Event{
		EventType: eventType,
		Severity:  severity,
		Source:    "files",
		Path:      path,
		Success:   success,
	}
	if err != nil {
		event.Error = err.Error()
	}

	l.Log(ctx, event)
}

// LogSecurity logs a security-related event.
func (l *Logger) LogSecurity(ctx context.Context, eventType EventType, severity Severity, details map[string]interface{}) {
	event := Event{
		EventType: eventType,
		Severity:  severity,
		Source:    "security",
		Success:   false, // Security events are typically failures/alerts
		Details:   details,
	}

	l.Log(ctx, event)
}

// LogRateLimit logs a rate limit event.
func (l *Logger) LogRateLimit(ctx context.Context, action string, count int, limit int) {
	l.LogSecurity(ctx, EventRateLimitExceeded, SeverityWarning, map[string]interface{}{
		"action":  action,
		"count":   count,
		"limit":   limit,
	})
}

// LogReplayAttempt logs a potential replay attack.
func (l *Logger) LogReplayAttempt(ctx context.Context, requestID string, originalTime time.Time) {
	l.LogSecurity(ctx, EventReplayAttempt, SeverityCritical, map[string]interface{}{
		"request_id":    requestID,
		"original_time": originalTime.Format(time.RFC3339),
	})
}

// truncateString truncates a string to the specified length.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
