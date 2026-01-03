// Package pathval provides path validation to prevent directory traversal attacks.
// It validates paths against allowed and forbidden path lists.
package pathval

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	ErrPathTraversal    = errors.New("path traversal detected")
	ErrForbiddenPath    = errors.New("access to path is forbidden")
	ErrPathNotAllowed   = errors.New("path is not in allowed list")
	ErrSymlinkTraversal = errors.New("symlink resolves outside allowed paths")
)

// AllowedPaths contains paths that users can access.
// Using "/" as base allows access to most paths, with ForbiddenPaths blocking sensitive areas.
var AllowedPaths = []string{
	"/",
}

// AllowedPathsWindows contains allowed paths for Windows.
// Allow common drive letters, with ForbiddenPathsWindows blocking sensitive areas.
var AllowedPathsWindows = []string{
	"C:\\",
	"D:\\",
	"E:\\",
	"F:\\",
}

// ForbiddenPaths contains paths that should never be accessed.
var ForbiddenPaths = []string{
	// Sensitive authentication files
	"/etc/shadow",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/sudoers.d",
	// SSH keys
	"/etc/ssh/ssh_host",
	"/root/.ssh",
	// Agent's own directories
	"/var/lib/slimrmm",
	"/var/lib/rmm",
	"/opt/slimrmm/agent/.proxmox_token.json",
	// Kubernetes secrets
	"/var/run/secrets",
	"/run/secrets",
}

// ForbiddenPathsWindows contains forbidden paths for Windows.
var ForbiddenPathsWindows = []string{
	"C:\\Windows\\System32\\config",
	"C:\\Windows\\System32\\SAM",
	"C:\\ProgramData\\SlimRMM",
}

// Validator validates file paths.
type Validator struct {
	allowedPaths   []string
	forbiddenPaths []string
}

// New creates a new path validator with OS-appropriate paths.
func New() *Validator {
	v := &Validator{}

	if runtime.GOOS == "windows" {
		v.allowedPaths = AllowedPathsWindows
		v.forbiddenPaths = ForbiddenPathsWindows
	} else {
		v.allowedPaths = AllowedPaths
		v.forbiddenPaths = ForbiddenPaths
	}

	return v
}

// NewWithPaths creates a validator with custom path lists.
func NewWithPaths(allowed, forbidden []string) *Validator {
	return &Validator{
		allowedPaths:   allowed,
		forbiddenPaths: forbidden,
	}
}

// Validate checks if a path is safe to access.
func (v *Validator) Validate(path string) error {
	// Clean and normalize the path
	cleanPath := filepath.Clean(path)

	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		// Resolve the actual path
		absPath, err := filepath.Abs(cleanPath)
		if err != nil {
			return ErrPathTraversal
		}
		cleanPath = absPath
	}

	// Check forbidden paths first
	for _, forbidden := range v.forbiddenPaths {
		if strings.HasPrefix(cleanPath, forbidden) {
			return ErrForbiddenPath
		}
	}

	// Check if path is within allowed paths
	allowed := false
	for _, allowedPath := range v.allowedPaths {
		if strings.HasPrefix(cleanPath, allowedPath) {
			allowed = true
			break
		}
	}

	if !allowed {
		return ErrPathNotAllowed
	}

	return nil
}

// ValidateWithSymlinkResolution validates the path and resolves symlinks.
func (v *Validator) ValidateWithSymlinkResolution(path string) error {
	// First validate the path itself
	if err := v.Validate(path); err != nil {
		return err
	}

	// Check if path exists
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Path doesn't exist yet, that's OK for creation
			return nil
		}
		return err
	}

	// If it's a symlink, resolve it and validate the target
	if info.Mode()&os.ModeSymlink != 0 {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}

		if err := v.Validate(resolved); err != nil {
			return ErrSymlinkTraversal
		}
	}

	return nil
}

// IsPathSafe is a convenience function using the default validator.
func IsPathSafe(path string) bool {
	return New().Validate(path) == nil
}

// SanitizePath cleans and normalizes a path.
func SanitizePath(path string) string {
	// Clean the path
	cleaned := filepath.Clean(path)

	// Convert to absolute if possible
	if abs, err := filepath.Abs(cleaned); err == nil {
		return abs
	}

	return cleaned
}
