//go:build !windows
// +build !windows

package registry

import (
	"context"
	"errors"
	"sync"
)

// ErrNotWindows is returned when registry operations are attempted on non-Windows systems.
var ErrNotWindows = errors.New("registry operations are only available on Windows")

// StubService implements Service as a stub for non-Windows platforms.
type StubService struct{}

var (
	defaultService *StubService
	serviceOnce    sync.Once
)

// New creates a new stub registry service.
func New() *StubService {
	return &StubService{}
}

// GetDefault returns the default singleton registry service.
func GetDefault() Service {
	serviceOnce.Do(func() {
		defaultService = New()
	})
	return defaultService
}

// ExportKey returns an error as registry operations are not available.
func (s *StubService) ExportKey(ctx context.Context, keyPath, outputPath string) error {
	return ErrNotWindows
}

// IsAvailable returns false as registry operations are not available on non-Windows.
func (s *StubService) IsAvailable() bool {
	return false
}
