//go:build windows
// +build windows

package registry

import (
	"context"
	"os/exec"
	"sync"
)

// WindowsService implements Service for Windows registry operations.
type WindowsService struct{}

var (
	defaultService *WindowsService
	serviceOnce    sync.Once
)

// New creates a new Windows registry service.
func New() *WindowsService {
	return &WindowsService{}
}

// GetDefault returns the default singleton registry service.
func GetDefault() Service {
	serviceOnce.Do(func() {
		defaultService = New()
	})
	return defaultService
}

// ExportKey exports a registry key to a file.
func (s *WindowsService) ExportKey(ctx context.Context, keyPath, outputPath string) error {
	cmd := exec.CommandContext(ctx, "reg", "export", keyPath, outputPath, "/y")
	return cmd.Run()
}

// IsAvailable returns true as registry operations are available on Windows.
func (s *WindowsService) IsAvailable() bool {
	return true
}
