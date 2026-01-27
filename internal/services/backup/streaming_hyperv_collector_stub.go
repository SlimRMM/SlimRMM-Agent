// Package backup provides stub implementations for non-Windows platforms.
//
//go:build !windows
// +build !windows

package backup

import (
	"context"
	"io"
	"log/slog"
)

// StreamingHyperVVMCollector stub for non-Windows platforms.
type StreamingHyperVVMCollector struct {
	logger *slog.Logger
}

// NewStreamingHyperVVMCollector creates a stub collector.
func NewStreamingHyperVVMCollector(logger *slog.Logger, tempDir string) *StreamingHyperVVMCollector {
	if logger == nil {
		logger = slog.Default()
	}
	return &StreamingHyperVVMCollector{logger: logger}
}

// Type returns the backup type.
func (c *StreamingHyperVVMCollector) Type() BackupType {
	return TypeHyperVVM
}

// SupportsStreaming returns false on non-Windows.
func (c *StreamingHyperVVMCollector) SupportsStreaming() bool {
	return false
}

// CollectStream returns an error on non-Windows platforms.
func (c *StreamingHyperVVMCollector) CollectStream(ctx context.Context, config CollectorConfig, w io.Writer) (int64, error) {
	return 0, &ErrFeatureUnavailable{Feature: "Hyper-V (Windows only)"}
}

// StreamingHyperVCheckpointCollector stub for non-Windows platforms.
type StreamingHyperVCheckpointCollector struct {
	logger *slog.Logger
}

// NewStreamingHyperVCheckpointCollector creates a stub collector.
func NewStreamingHyperVCheckpointCollector(logger *slog.Logger) *StreamingHyperVCheckpointCollector {
	if logger == nil {
		logger = slog.Default()
	}
	return &StreamingHyperVCheckpointCollector{logger: logger}
}

// Type returns the backup type.
func (c *StreamingHyperVCheckpointCollector) Type() BackupType {
	return TypeHyperVCheckpoint
}

// SupportsStreaming returns false on non-Windows.
func (c *StreamingHyperVCheckpointCollector) SupportsStreaming() bool {
	return false
}

// CollectStream returns an error on non-Windows platforms.
func (c *StreamingHyperVCheckpointCollector) CollectStream(ctx context.Context, config CollectorConfig, w io.Writer) (int64, error) {
	return 0, &ErrFeatureUnavailable{Feature: "Hyper-V (Windows only)"}
}

// StreamingHyperVConfigCollector stub for non-Windows platforms.
type StreamingHyperVConfigCollector struct {
	logger *slog.Logger
}

// NewStreamingHyperVConfigCollector creates a stub collector.
func NewStreamingHyperVConfigCollector(logger *slog.Logger) *StreamingHyperVConfigCollector {
	if logger == nil {
		logger = slog.Default()
	}
	return &StreamingHyperVConfigCollector{logger: logger}
}

// Type returns the backup type.
func (c *StreamingHyperVConfigCollector) Type() BackupType {
	return TypeHyperVConfig
}

// SupportsStreaming returns false on non-Windows.
func (c *StreamingHyperVConfigCollector) SupportsStreaming() bool {
	return false
}

// CollectStream returns an error on non-Windows platforms.
func (c *StreamingHyperVConfigCollector) CollectStream(ctx context.Context, config CollectorConfig, w io.Writer) (int64, error) {
	return 0, &ErrFeatureUnavailable{Feature: "Hyper-V (Windows only)"}
}
