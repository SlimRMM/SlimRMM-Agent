package http

import (
	"os"
	"path/filepath"
)

// createFile creates a file at the given path, creating directories as needed.
func createFile(path string) (*os.File, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	return os.Create(path)
}
