//go:build !darwin
// +build !darwin

// Package homebrew provides stub implementations for non-macOS platforms.
package homebrew

import (
	"context"
	"fmt"
	"time"
)

// ZapStanza represents the parsed zap stanza from a Homebrew cask.
type ZapStanza struct {
	Trash     []string      `json:"trash,omitempty"`
	Delete    []string      `json:"delete,omitempty"`
	Launchctl []string      `json:"launchctl,omitempty"`
	Pkgutil   []string      `json:"pkgutil,omitempty"`
	Quit      []string      `json:"quit,omitempty"`
	Signal    []interface{} `json:"signal,omitempty"`
	Rmdir     []string      `json:"rmdir,omitempty"`
	Kext      []string      `json:"kext,omitempty"`
}

// ZapOperation represents a single zap operation result.
type ZapOperation struct {
	Operation  string    `json:"operation"`
	Target     string    `json:"target"`
	Command    string    `json:"command,omitempty"`
	Args       []string  `json:"args,omitempty"`
	Stdout     string    `json:"stdout,omitempty"`
	Stderr     string    `json:"stderr,omitempty"`
	ExitCode   int       `json:"exit_code"`
	Success    bool      `json:"success"`
	Error      string    `json:"error,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
	DurationMs int64     `json:"duration_ms"`
}

// ZapResult contains the results of executing a zap stanza.
type ZapResult struct {
	PathsRemoved      []string       `json:"paths_removed"`
	ServicesUnloaded  []string       `json:"services_unloaded"`
	ReceiptsForgotten []string       `json:"receipts_forgotten"`
	Operations        []ZapOperation `json:"operations"`
}

// FetchCaskInfoFull is a stub for non-macOS platforms.
func FetchCaskInfoFull(caskName string) (map[string]interface{}, error) {
	return nil, fmt.Errorf("Homebrew cask operations are only available on macOS")
}

// ParseZapStanza is a stub for non-macOS platforms.
func ParseZapStanza(cleanupInfo map[string]interface{}) ([]ZapStanza, error) {
	return nil, fmt.Errorf("Homebrew zap stanza parsing is only available on macOS")
}

// ExecuteZapStanza is a stub for non-macOS platforms.
func ExecuteZapStanza(ctx context.Context, cleanupInfo map[string]interface{}) (*ZapResult, error) {
	return &ZapResult{
		PathsRemoved:      make([]string, 0),
		ServicesUnloaded:  make([]string, 0),
		ReceiptsForgotten: make([]string, 0),
		Operations:        make([]ZapOperation, 0),
	}, fmt.Errorf("Homebrew zap stanza execution is only available on macOS")
}

// GetCurrentUID is a stub for non-macOS platforms.
func GetCurrentUID() string {
	return "0"
}

// GetCurrentUIDInt is a stub for non-macOS platforms.
func GetCurrentUIDInt() int {
	return 0
}
