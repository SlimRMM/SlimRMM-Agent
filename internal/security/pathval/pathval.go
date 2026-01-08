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
// Allow all drive letters (A-Z), with ForbiddenPathsWindows blocking sensitive areas.
var AllowedPathsWindows = []string{
	"A:\\", "B:\\", "C:\\", "D:\\", "E:\\", "F:\\", "G:\\", "H:\\",
	"I:\\", "J:\\", "K:\\", "L:\\", "M:\\", "N:\\", "O:\\", "P:\\",
	"Q:\\", "R:\\", "S:\\", "T:\\", "U:\\", "V:\\", "W:\\", "X:\\",
	"Y:\\", "Z:\\",
}

// ForbiddenPaths contains paths that should never be accessed.
var ForbiddenPaths = []string{
	// Sensitive authentication files
	"/etc/shadow",
	"/etc/gshadow",
	"/etc/passwd",
	"/etc/group",
	"/etc/sudoers",
	"/etc/sudoers.d",
	"/etc/crypttab",
	// SSH keys and config
	"/etc/ssh/ssh_host",
	"/root/.ssh",
	// Home directory SSH keys (validated separately with pattern matching)
	// Agent's own directories and config
	"/var/lib/slimrmm",
	"/var/lib/rmm",
	"/opt/slimrmm",
	"/etc/slimrmm",
	// Kubernetes and container secrets
	"/var/run/secrets",
	"/run/secrets",
	// Process information that could leak secrets
	"/proc/1/environ",
	"/proc/self/environ",
	// System security
	"/boot",
	"/sys/firmware",
}

// ForbiddenPatterns contains filename patterns that should never be accessed.
var ForbiddenPatterns = []string{
	".ssh",
	".gnupg",
	".env",
	".pem",
	".key",
	".p12",
	".pfx",
	"id_rsa",
	"id_ed25519",
	"id_ecdsa",
	"id_dsa",
	"known_hosts",
	"authorized_keys",
	"shadow",
	"gshadow",
	"passwd",
	".proxmox_token",
}

// ForbiddenPathsWindows contains forbidden paths for Windows.
var ForbiddenPathsWindows = []string{
	"C:\\Windows\\System32\\config",
	"C:\\Windows\\System32\\SAM",
	"C:\\ProgramData\\SlimRMM",
	"C:\\Windows\\System32\\drivers\\etc",
	"C:\\Users\\*\\.ssh",
	"C:\\Users\\*\\.gnupg",
}

// ForbiddenPatternsWindows contains filename patterns forbidden on Windows.
var ForbiddenPatternsWindows = []string{
	".ssh",
	".gnupg",
	".env",
	".pem",
	".key",
	".p12",
	".pfx",
	"id_rsa",
	"id_ed25519",
	"id_ecdsa",
	"id_dsa",
	"known_hosts",
	"authorized_keys",
}

// Validator validates file paths.
type Validator struct {
	allowedPaths      []string
	forbiddenPaths    []string
	forbiddenPatterns []string
}

// New creates a new path validator with OS-appropriate paths.
func New() *Validator {
	v := &Validator{}

	if runtime.GOOS == "windows" {
		v.allowedPaths = AllowedPathsWindows
		v.forbiddenPaths = ForbiddenPathsWindows
		v.forbiddenPatterns = ForbiddenPatternsWindows
	} else {
		v.allowedPaths = AllowedPaths
		v.forbiddenPaths = ForbiddenPaths
		v.forbiddenPatterns = ForbiddenPatterns
	}

	return v
}

// NewWithPaths creates a validator with custom path lists.
func NewWithPaths(allowed, forbidden, patterns []string) *Validator {
	return &Validator{
		allowedPaths:      allowed,
		forbiddenPaths:    forbidden,
		forbiddenPatterns: patterns,
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

	// Check forbidden patterns in filename and path components
	pathLower := strings.ToLower(cleanPath)
	for _, pattern := range v.forbiddenPatterns {
		patternLower := strings.ToLower(pattern)
		// Check if pattern appears in the path
		if strings.Contains(pathLower, patternLower) {
			return ErrForbiddenPath
		}
		// Also check the base filename
		baseLower := strings.ToLower(filepath.Base(cleanPath))
		if strings.Contains(baseLower, patternLower) {
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
