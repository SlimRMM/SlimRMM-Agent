// Package filesystem provides file system operations as a service layer.
package filesystem

import (
	"io"
	"os"
)

// FileService defines the interface for file system operations.
type FileService interface {
	// CreateFile creates a new file at the specified path.
	CreateFile(path string) (io.WriteCloser, error)

	// OpenFile opens a file with the specified flags and mode.
	OpenFile(path string, flag int, perm os.FileMode) (File, error)

	// OpenRead opens a file for reading.
	OpenRead(path string) (io.ReadCloser, error)

	// FileExists checks if a file exists at the specified path.
	FileExists(path string) bool

	// Stat returns file info for the specified path.
	Stat(path string) (os.FileInfo, error)

	// Remove removes the file at the specified path.
	Remove(path string) error

	// RemoveAll removes the path and all children.
	RemoveAll(path string) error

	// MkdirAll creates a directory and all parent directories.
	MkdirAll(path string, perm os.FileMode) error

	// ReadFile reads the entire file content.
	ReadFile(path string) ([]byte, error)

	// WriteFile writes data to a file, creating it if necessary.
	WriteFile(path string, data []byte, perm os.FileMode) error

	// CommandExists checks if a command/executable exists in PATH.
	CommandExists(name string) bool
}

// File extends io.ReadWriteCloser with additional file operations.
type File interface {
	io.ReadWriteCloser
	io.WriterAt
	io.ReaderAt
	io.Seeker
	Name() string
	Stat() (os.FileInfo, error)
	Sync() error
	Truncate(size int64) error
}
