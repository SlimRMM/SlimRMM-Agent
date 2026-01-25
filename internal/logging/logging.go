// Package logging provides logging setup and configuration for the agent.
// Logs are written to daily rotating files with configurable retention.
package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	logFilePrefix    = "agent-"
	logFileSuffix    = ".log"
	logFileMode      = 0600
	logDirMode       = 0755
	maxLogFiles      = 3
	uploadedFileName = ".uploaded_logs.json"
)

// Config holds logging configuration.
type Config struct {
	LogDir      string
	Debug       bool
	LogToStdout bool
}

// RotatingLogger manages daily log rotation with upload tracking.
type RotatingLogger struct {
	cfg         Config
	currentFile *os.File
	currentDate string
	mu          sync.Mutex
	writer      io.Writer
	logger      *slog.Logger
}

// uploadedLogs tracks which log files have been uploaded to the server.
type uploadedLogs struct {
	Files map[string]time.Time `json:"files"` // filename -> upload time
}

var (
	globalRotatingLogger *RotatingLogger
	globalLoggerMu       sync.Mutex
)

// GetRotatingLogger returns the global rotating logger instance.
func GetRotatingLogger() *RotatingLogger {
	globalLoggerMu.Lock()
	defer globalLoggerMu.Unlock()
	return globalRotatingLogger
}

// Setup initializes logging with daily rotation and optional stdout output.
// Returns the configured logger and a cleanup function to close the log file.
func Setup(cfg Config) (*slog.Logger, func(), error) {
	logLevel := slog.LevelInfo
	if cfg.Debug {
		logLevel = slog.LevelDebug
	}

	// Create log directory
	if err := os.MkdirAll(cfg.LogDir, logDirMode); err != nil {
		// Fall back to stdout-only logging
		logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: logLevel,
		}))
		return logger, func() {}, nil
	}

	// Create rotating logger
	rl := &RotatingLogger{
		cfg: cfg,
	}

	// Open initial log file
	if err := rl.openLogFile(); err != nil {
		// Fall back to stdout-only logging
		logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: logLevel,
		}))
		return logger, func() {}, nil
	}

	// Set up writer
	if cfg.LogToStdout {
		rl.writer = io.MultiWriter(rl, os.Stdout)
	} else {
		rl.writer = rl
	}

	// Create logger with JSON handler
	rl.logger = slog.New(slog.NewJSONHandler(rl.writer, &slog.HandlerOptions{
		Level: logLevel,
	}))

	// Store global reference
	globalLoggerMu.Lock()
	globalRotatingLogger = rl
	globalLoggerMu.Unlock()

	// Run initial cleanup
	go rl.cleanupOldLogs()

	// Cleanup function
	cleanup := func() {
		rl.mu.Lock()
		defer rl.mu.Unlock()
		if rl.currentFile != nil {
			rl.currentFile.Close()
		}
	}

	return rl.logger, cleanup, nil
}

// SetupWithDefaults creates a logger that writes to file and optionally stdout.
// When running as a service (SLIMRMM_SERVICE=1), stdout is disabled to prevent
// duplicate logs when the service manager also redirects stdout to the log file.
func SetupWithDefaults(logDir string, debug bool) (*slog.Logger, func(), error) {
	// Don't log to stdout when running as a service to prevent duplicate logs
	logToStdout := os.Getenv("SLIMRMM_SERVICE") != "1"

	return Setup(Config{
		LogDir:      logDir,
		Debug:       debug,
		LogToStdout: logToStdout,
	})
}

// Write implements io.Writer for the rotating logger.
// It checks if we need to rotate to a new daily log file.
func (rl *RotatingLogger) Write(p []byte) (n int, err error) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Check if we need to rotate to a new day
	today := time.Now().Format("2006-01-02")
	if today != rl.currentDate {
		if err := rl.rotateLogFile(); err != nil {
			// Log rotation failed, continue with current file
			slog.Error("failed to rotate log file", "error", err)
		}
	}

	if rl.currentFile == nil {
		return 0, fmt.Errorf("log file not open")
	}

	return rl.currentFile.Write(p)
}

// openLogFile opens or creates the log file for today.
func (rl *RotatingLogger) openLogFile() error {
	today := time.Now().Format("2006-01-02")
	logPath := filepath.Join(rl.cfg.LogDir, logFilePrefix+today+logFileSuffix)

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, logFileMode)
	if err != nil {
		return err
	}

	// Set file permissions (ignore errors on Windows)
	os.Chmod(logPath, logFileMode)

	rl.currentFile = file
	rl.currentDate = today

	return nil
}

// rotateLogFile closes the current log file and opens a new one for today.
func (rl *RotatingLogger) rotateLogFile() error {
	// Close current file
	if rl.currentFile != nil {
		rl.currentFile.Close()
		rl.currentFile = nil
	}

	// Open new log file
	if err := rl.openLogFile(); err != nil {
		return err
	}

	// Cleanup old logs in background
	go rl.cleanupOldLogs()

	return nil
}

// cleanupOldLogs removes old log files, keeping only maxLogFiles.
// Only deletes logs that have been uploaded to the server.
func (rl *RotatingLogger) cleanupOldLogs() {
	logFiles, err := findAgentLogFiles(rl.cfg.LogDir)
	if err != nil {
		return
	}

	// If we have more than maxLogFiles, try to delete old ones
	if len(logFiles) <= maxLogFiles {
		return
	}

	// Load uploaded logs tracking
	uploaded := loadUploadedLogs(rl.cfg.LogDir)

	// Files are sorted newest first, so we keep the first maxLogFiles
	// and try to delete the rest if they've been uploaded
	for i := maxLogFiles; i < len(logFiles); i++ {
		fileName := filepath.Base(logFiles[i])

		// Only delete if uploaded
		if _, wasUploaded := uploaded.Files[fileName]; wasUploaded {
			if err := os.Remove(logFiles[i]); err == nil {
				slog.Info("deleted old log file", "file", fileName)
				// Remove from tracking
				delete(uploaded.Files, fileName)
			}
		} else {
			slog.Debug("keeping old log file (not yet uploaded)", "file", fileName)
		}
	}

	// Save updated tracking
	saveUploadedLogs(rl.cfg.LogDir, uploaded)
}

// findAgentLogFiles returns all agent log files sorted by date (newest first).
func findAgentLogFiles(logDir string) ([]string, error) {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, logFilePrefix) && strings.HasSuffix(name, logFileSuffix) {
			files = append(files, filepath.Join(logDir, name))
		}
	}

	// Sort by name descending (newest date first)
	sort.Slice(files, func(i, j int) bool {
		return filepath.Base(files[i]) > filepath.Base(files[j])
	})

	return files, nil
}

// loadUploadedLogs loads the uploaded logs tracking file.
func loadUploadedLogs(logDir string) *uploadedLogs {
	trackingPath := filepath.Join(logDir, uploadedFileName)

	data, err := os.ReadFile(trackingPath)
	if err != nil {
		return &uploadedLogs{Files: make(map[string]time.Time)}
	}

	var uploaded uploadedLogs
	if err := json.Unmarshal(data, &uploaded); err != nil {
		return &uploadedLogs{Files: make(map[string]time.Time)}
	}

	if uploaded.Files == nil {
		uploaded.Files = make(map[string]time.Time)
	}

	return &uploaded
}

// saveUploadedLogs saves the uploaded logs tracking file.
func saveUploadedLogs(logDir string, uploaded *uploadedLogs) {
	trackingPath := filepath.Join(logDir, uploadedFileName)

	data, err := json.MarshalIndent(uploaded, "", "  ")
	if err != nil {
		return
	}

	os.WriteFile(trackingPath, data, logFileMode)
}

// MarkLogUploaded marks a log file as uploaded to the server.
// Call this after successfully uploading logs from a specific file.
func MarkLogUploaded(logDir, fileName string) {
	uploaded := loadUploadedLogs(logDir)
	uploaded.Files[fileName] = time.Now()
	saveUploadedLogs(logDir, uploaded)
}

// MarkCurrentLogUploaded marks the current log file as uploaded.
func MarkCurrentLogUploaded() {
	rl := GetRotatingLogger()
	if rl == nil {
		return
	}

	rl.mu.Lock()
	currentDate := rl.currentDate
	logDir := rl.cfg.LogDir
	rl.mu.Unlock()

	if currentDate != "" && logDir != "" {
		fileName := logFilePrefix + currentDate + logFileSuffix
		MarkLogUploaded(logDir, fileName)
	}
}

// GetLogFiles returns all agent log files for reading.
func GetLogFiles(logDir string) ([]string, error) {
	return findAgentLogFiles(logDir)
}

// GetCurrentLogFile returns the path to the current log file.
func GetCurrentLogFile() string {
	rl := GetRotatingLogger()
	if rl == nil {
		return ""
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.currentDate == "" {
		return ""
	}

	return filepath.Join(rl.cfg.LogDir, logFilePrefix+rl.currentDate+logFileSuffix)
}
