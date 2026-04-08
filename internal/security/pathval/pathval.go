// Package pathval provides path validation to prevent directory traversal attacks.
// It validates paths against allowed and forbidden path lists.
package pathval

import (
	"errors"
	"fmt"
	"io/fs"
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
			if len(cleanPath) == len(forbidden) || cleanPath[len(forbidden)] == '/' || cleanPath[len(forbidden)] == filepath.Separator {
				return ErrForbiddenPath
			}
		}
	}

	// Check forbidden patterns in individual path components
	for _, pattern := range v.forbiddenPatterns {
		patternLower := strings.ToLower(pattern)
		for _, component := range strings.Split(cleanPath, string(filepath.Separator)) {
			if strings.Contains(strings.ToLower(component), patternLower) {
				return ErrForbiddenPath
			}
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

// resolveSafe attempts to resolve all symlinks in a path. If the path does not
// exist, it walks up parent directories until it finds an existing ancestor,
// resolves symlinks on that ancestor, and rejoins the non-existing tail.
// This allows safe symlink resolution even for paths that do not yet exist
// (e.g. files about to be created). Fails closed: any unexpected error is
// returned so callers can reject.
//
// NOTE: TOCTOU windows are inherent to stat/open-based resolution. A concurrent
// attacker that can mutate the filesystem between this resolution and the
// caller's subsequent open(2) may still swap directory entries. For strict
// guarantees use openat2(RESOLVE_NO_SYMLINKS) on Linux, which performs
// resolution atomically at the syscall level. This implementation minimizes
// the window by issuing the minimum number of stat calls: the happy path
// performs a single EvalSymlinks call and inspects the returned error rather
// than doing a separate Lstat probe first.
func resolveSafe(path string) (string, error) {
	cleaned := filepath.Clean(path)

	// Fast path: one syscall. EvalSymlinks both checks existence and
	// resolves symlinks atomically (per-call), eliminating the prior
	// Lstat->EvalSymlinks TOCTOU window.
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		// Unexpected error (permission, I/O) — fail closed.
		return "", err
	}

	// Path does not exist — walk up parents until we find an existing
	// ancestor we can resolve. We call EvalSymlinks directly on each
	// candidate parent (no separate Lstat), again minimizing syscalls.
	tail := ""
	ancestor := cleaned
	for {
		parent := filepath.Dir(ancestor)
		base := filepath.Base(ancestor)
		if tail == "" {
			tail = base
		} else {
			tail = filepath.Join(base, tail)
		}

		if parent == ancestor {
			// Reached filesystem root without finding existing ancestor.
			return "", os.ErrNotExist
		}

		resolvedParent, evalErr := filepath.EvalSymlinks(parent)
		if evalErr == nil {
			return filepath.Join(resolvedParent, tail), nil
		}
		if !errors.Is(evalErr, fs.ErrNotExist) {
			// Unexpected error — fail closed.
			return "", evalErr
		}
		ancestor = parent
	}
}

// pathMatchesForbidden checks whether a (already cleaned) path matches any
// forbidden entry — either a direct prefix match in forbiddenPaths or a
// substring match against any of the forbiddenPatterns.
func pathMatchesForbidden(cleanPath string, forbiddenPaths, forbiddenPatterns []string) bool {
	for _, forbidden := range forbiddenPaths {
		if strings.HasPrefix(cleanPath, forbidden) {
			return true
		}
	}
	pathLower := strings.ToLower(cleanPath)
	baseLower := strings.ToLower(filepath.Base(cleanPath))
	for _, pattern := range forbiddenPatterns {
		patternLower := strings.ToLower(pattern)
		if strings.Contains(pathLower, patternLower) {
			return true
		}
		if strings.Contains(baseLower, patternLower) {
			return true
		}
	}
	return false
}

// ValidateWithSymlinkResolution validates the path and resolves symlinks.
// It checks both the cleaned input path and the fully symlink-resolved path
// against forbiddenPaths/forbiddenPatterns. Any mismatch where the resolved
// path differs from the cleaned path AND the resolved path hits a forbidden
// entry is rejected with a clear error that mentions symlink resolution.
// Fails closed: any error from resolveSafe (other than a clean non-existent
// path that still resolves via parent walk) causes rejection.
func (v *Validator) ValidateWithSymlinkResolution(path string) error {
	// First validate the path itself via the standard checks.
	if err := v.Validate(path); err != nil {
		return err
	}

	cleaned := filepath.Clean(path)

	// Resolve symlinks safely (walks up to existing ancestor if needed).
	resolved, err := resolveSafe(path)
	if err != nil {
		// Fail closed on any resolution error.
		return fmt.Errorf("%w: could not resolve symlinks: %v", ErrSymlinkTraversal, err)
	}

	// If resolution changed the path, re-check the resolved path against
	// the forbidden lists to ensure a symlink did not redirect us into
	// a sensitive location, and also verify that it still lies within
	// the allowed paths so a symlink cannot be used to escape the
	// allowlist.
	if resolved != cleaned {
		if pathMatchesForbidden(resolved, v.forbiddenPaths, v.forbiddenPatterns) {
			return fmt.Errorf("%w: symlink resolution redirected %q to forbidden target %q",
				ErrSymlinkTraversal, cleaned, resolved)
		}
		if len(v.allowedPaths) > 0 {
			allowed := false
			for _, allowedPath := range v.allowedPaths {
				if strings.HasPrefix(resolved, allowedPath) {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("%w: symlink resolution redirected %q outside allowed paths to %q",
					ErrSymlinkTraversal, cleaned, resolved)
			}
		}
	}

	return nil
}

// IsPathSafe is a convenience function that checks if a path is safe using the default validator.
// Returns true if the path passes all security validations (no traversal, no forbidden paths).
// Thread-safe: creates a new validator instance for each call.
func IsPathSafe(path string) bool {
	return New().Validate(path) == nil
}

// SanitizePath cleans and normalizes a path by removing redundant separators,
// resolving . and .. elements, and converting to an absolute path when possible.
// This does NOT validate the path for security - use Validate() for that.
func SanitizePath(path string) string {
	// Clean the path
	cleaned := filepath.Clean(path)

	// Convert to absolute if possible
	if abs, err := filepath.Abs(cleaned); err == nil {
		return abs
	}

	return cleaned
}
