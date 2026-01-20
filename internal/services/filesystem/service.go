// Package filesystem provides file system operations as a service layer.
package filesystem

import (
	"io"
	"os"
	"sync"
)

// Service implements FileService using standard library os operations.
type Service struct{}

var (
	defaultService *Service
	serviceOnce    sync.Once
)

// New creates a new file system service.
func New() *Service {
	return &Service{}
}

// GetDefault returns the default singleton file system service.
func GetDefault() *Service {
	serviceOnce.Do(func() {
		defaultService = New()
	})
	return defaultService
}

// CreateFile creates a new file at the specified path.
func (s *Service) CreateFile(path string) (io.WriteCloser, error) {
	return os.Create(path)
}

// OpenFile opens a file with the specified flags and mode.
func (s *Service) OpenFile(path string, flag int, perm os.FileMode) (File, error) {
	return os.OpenFile(path, flag, perm)
}

// OpenRead opens a file for reading.
func (s *Service) OpenRead(path string) (io.ReadCloser, error) {
	return os.Open(path)
}

// FileExists checks if a file exists at the specified path.
func (s *Service) FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Stat returns file info for the specified path.
func (s *Service) Stat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

// Remove removes the file at the specified path.
func (s *Service) Remove(path string) error {
	return os.Remove(path)
}

// RemoveAll removes the path and all children.
func (s *Service) RemoveAll(path string) error {
	return os.RemoveAll(path)
}

// MkdirAll creates a directory and all parent directories.
func (s *Service) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// ReadFile reads the entire file content.
func (s *Service) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// WriteFile writes data to a file, creating it if necessary.
func (s *Service) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}
