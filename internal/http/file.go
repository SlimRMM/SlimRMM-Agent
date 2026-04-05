package http

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/slimrmm/slimrmm-agent/internal/security/pathval"
)

// validateDestPath validates the destination path for a downloaded file using
// the shared pathval validator. It checks both the parent directory (where the
// file will be created) and the final destination path to reject traversal
// attempts, forbidden system locations, and sensitive filename patterns.
//
// This prevents a compromised server from instructing the agent to overwrite
// arbitrary files on the host (e.g. via destPath = "../../../etc/passwd").
func validateDestPath(destPath string) error {
	if destPath == "" {
		return fmt.Errorf("destination path is empty")
	}

	// Resolve to absolute so prefix/symlink checks are meaningful regardless of
	// the caller's current working directory.
	abs, err := filepath.Abs(destPath)
	if err != nil {
		return fmt.Errorf("resolving absolute path: %w", err)
	}

	v := pathval.New()

	// Validate the parent directory (must exist or be creatable under an
	// allowed path). ValidateWithSymlinkResolution walks up to the nearest
	// existing ancestor, so it is safe to call on a not-yet-created dir.
	parent := filepath.Dir(abs)
	if err := v.ValidateWithSymlinkResolution(parent); err != nil {
		return fmt.Errorf("destination path validation failed: %w", err)
	}

	// Validate the final path too — this catches forbidden *filename*
	// patterns (id_rsa, shadow, .env, ...) that a compromised server might
	// attempt to plant.
	if err := v.ValidateWithSymlinkResolution(abs); err != nil {
		return fmt.Errorf("destination path validation failed: %w", err)
	}

	return nil
}

// createFile creates a file at the given path, creating directories as needed.
// The caller MUST have already validated path via validateDestPath.
func createFile(path string) (*os.File, error) {
	if err := validateDestPath(path); err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	return os.Create(path)
}
