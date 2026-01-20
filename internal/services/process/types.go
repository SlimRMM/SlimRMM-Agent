// Package process provides process management services.
package process

import "context"

// ProcessInfo represents information about a running process.
type ProcessInfo struct {
	Name    string `json:"name"`
	PID     int    `json:"pid"`
	User    string `json:"user,omitempty"`
	CPU     string `json:"cpu,omitempty"`
	Mem     string `json:"mem,omitempty"`
	Command string `json:"command,omitempty"`
}

// Signal represents a process signal.
type Signal string

const (
	SignalTerm Signal = "TERM"
	SignalKill Signal = "KILL"
	SignalInt  Signal = "INT"
)

// ProcessService defines operations for process management.
type ProcessService interface {
	// GetProcessInfo returns detailed information about a process.
	GetProcessInfo(ctx context.Context, pid int) (*ProcessInfo, error)

	// GetProcessTree returns all child processes of a given PID.
	GetProcessTree(ctx context.Context, pid int) ([]int, error)

	// IsProcessRunning checks if a process is still running.
	IsProcessRunning(ctx context.Context, pid int) bool

	// SendSignal sends a signal to a process.
	SendSignal(ctx context.Context, pid int, signal Signal) error

	// KillProcess terminates a process.
	KillProcess(ctx context.Context, pid int, force bool) error

	// KillProcessTree kills a process and all its children.
	KillProcessTree(ctx context.Context, pid int, force bool) error
}
