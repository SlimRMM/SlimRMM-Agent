// Package logging provides logging setup and configuration for the agent.
// Logs are written to both file and stdout by default.
package logging

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

const (
	logFileName = "agent.log"
	logFileMode = 0644
	logDirMode  = 0755
)

// Config holds logging configuration.
type Config struct {
	LogDir      string
	Debug       bool
	LogToStdout bool
}

// Setup initializes logging with both file and optional stdout output.
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

	// Create/open log file
	logPath := filepath.Join(cfg.LogDir, logFileName)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, logFileMode)
	if err != nil {
		// Fall back to stdout-only logging
		logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: logLevel,
		}))
		return logger, func() {}, nil
	}

	// Set file permissions (ignore errors on Windows)
	os.Chmod(logPath, logFileMode)

	var writer io.Writer
	if cfg.LogToStdout {
		// Multi-writer for both file and stdout
		writer = io.MultiWriter(logFile, os.Stdout)
	} else {
		writer = logFile
	}

	// Create logger with JSON handler for structured logging
	logger := slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{
		Level: logLevel,
	}))

	// Cleanup function to close log file
	cleanup := func() {
		logFile.Close()
	}

	return logger, cleanup, nil
}

// SetupWithDefaults creates a logger that writes to file and optionally stdout.
// When running as a service (SLIMRMM_SERVICE=1), stdout is disabled to prevent
// duplicate logs when the service manager also redirects stdout to the log file.
func SetupWithDefaults(logDir string, debug bool) (*slog.Logger, func(), error) {
	// Don't log to stdout when running as a service to prevent duplicate logs
	// Service managers (launchd, systemd) redirect stdout to the log file,
	// which causes duplicates when we also write directly to the file
	logToStdout := os.Getenv("SLIMRMM_SERVICE") != "1"

	return Setup(Config{
		LogDir:      logDir,
		Debug:       debug,
		LogToStdout: logToStdout,
	})
}
