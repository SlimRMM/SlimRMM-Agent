//go:build !windows
// +build !windows

// Package service provides platform-specific service support.
package service

import (
	"context"
	"log/slog"
)

// ServiceName is the service name (only used on Windows)
const ServiceName = "SlimRMMAgent"

// AgentRunner is the interface that the main agent must implement
type AgentRunner interface {
	Run(ctx context.Context) error
	Stop()
}

// RunAsService is a no-op on non-Windows platforms
func RunAsService(runner AgentRunner, logger *slog.Logger) error {
	// Not applicable on non-Windows platforms
	// The agent runs directly via systemd/launchd
	return nil
}

// IsRunningAsService always returns false on non-Windows platforms
func IsRunningAsService() bool {
	return false
}
