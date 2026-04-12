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

// ListKey returns an error as registry operations are not available.
func (s *StubService) ListKey(ctx context.Context, hive, path string) (*ListKeyResult, error) {
	return nil, ErrNotWindows
}

// CreateKey returns an error as registry operations are not available.
func (s *StubService) CreateKey(ctx context.Context, hive, path string) error {
	return ErrNotWindows
}

// DeleteKey returns an error as registry operations are not available.
func (s *StubService) DeleteKey(ctx context.Context, hive, path string) error {
	return ErrNotWindows
}

// RenameKey returns an error as registry operations are not available.
func (s *StubService) RenameKey(ctx context.Context, hive, path, newName string) error {
	return ErrNotWindows
}

// SetValue returns an error as registry operations are not available.
func (s *StubService) SetValue(ctx context.Context, hive, path, name, valueType string, data interface{}) error {
	return ErrNotWindows
}

// DeleteValue returns an error as registry operations are not available.
func (s *StubService) DeleteValue(ctx context.Context, hive, path, name string) error {
	return ErrNotWindows
}

// RenameValue returns an error as registry operations are not available.
func (s *StubService) RenameValue(ctx context.Context, hive, path, oldName, newName string) error {
	return ErrNotWindows
}

// SearchKey returns an error as registry operations are not available.
func (s *StubService) SearchKey(ctx context.Context, hive, path, query string, maxResults int) (*SearchResult, error) {
	return nil, ErrNotWindows
}
