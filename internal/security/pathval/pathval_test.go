// Package pathval provides path validation tests.
package pathval

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNew(t *testing.T) {
	v := New()
	if v == nil {
		t.Fatal("New() returned nil")
	}

	if runtime.GOOS == "windows" {
		if len(v.allowedPaths) != len(AllowedPathsWindows) {
			t.Error("Windows allowed paths not set correctly")
		}
		if len(v.forbiddenPaths) != len(ForbiddenPathsWindows) {
			t.Error("Windows forbidden paths not set correctly")
		}
	} else {
		if len(v.allowedPaths) != len(AllowedPaths) {
			t.Error("Unix allowed paths not set correctly")
		}
		if len(v.forbiddenPaths) != len(ForbiddenPaths) {
			t.Error("Unix forbidden paths not set correctly")
		}
	}
}

func TestNewWithPaths(t *testing.T) {
	allowed := []string{"/home/user"}
	forbidden := []string{"/home/user/secret"}
	patterns := []string{".env"}

	v := NewWithPaths(allowed, forbidden, patterns)
	if v == nil {
		t.Fatal("NewWithPaths() returned nil")
	}

	if len(v.allowedPaths) != 1 {
		t.Error("custom allowed paths not set correctly")
	}
	if len(v.forbiddenPaths) != 1 {
		t.Error("custom forbidden paths not set correctly")
	}
	if len(v.forbiddenPatterns) != 1 {
		t.Error("custom forbidden patterns not set correctly")
	}
}

func TestValidate_AllowedPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix path tests on Windows")
	}

	v := NewWithPaths([]string{"/"}, []string{}, []string{})

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"root", "/", false},
		{"home", "/home", false},
		{"usr", "/usr/bin", false},
		{"tmp", "/tmp/test", false},
		{"var", "/var/log", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidate_ForbiddenPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix path tests on Windows")
	}

	v := New()

	forbiddenPaths := []string{
		"/etc/shadow",
		"/etc/gshadow",
		"/etc/passwd",
		"/root/.ssh",
		"/var/lib/slimrmm",
		"/proc/1/environ",
		"/proc/self/environ",
		"/boot/vmlinuz",
	}

	for _, path := range forbiddenPaths {
		t.Run(path, func(t *testing.T) {
			err := v.Validate(path)
			if err != ErrForbiddenPath {
				t.Errorf("Validate(%q) = %v, want ErrForbiddenPath", path, err)
			}
		})
	}
}

func TestValidate_ForbiddenPatterns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix path tests on Windows")
	}

	v := New()

	patternPaths := []string{
		"/home/user/.ssh/id_rsa",
		"/home/user/.gnupg/private-keys-v1.d",
		"/home/user/.env",
		"/home/user/server.pem",
		"/home/user/private.key",
		"/home/user/cert.p12",
		"/home/user/cert.pfx",
		"/home/user/.ssh/id_ed25519",
		"/home/user/.ssh/known_hosts",
		"/home/user/.ssh/authorized_keys",
	}

	for _, path := range patternPaths {
		t.Run(path, func(t *testing.T) {
			err := v.Validate(path)
			if err != ErrForbiddenPath {
				t.Errorf("Validate(%q) = %v, want ErrForbiddenPath", path, err)
			}
		})
	}
}

func TestValidate_PathTraversal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix path tests on Windows")
	}

	// Path traversal that escapes allowed paths should be blocked
	v := NewWithPaths([]string{"/home/user"}, []string{}, []string{})

	tests := []struct {
		name    string
		path    string
		wantErr error
	}{
		// These paths traverse outside /home/user and should not be allowed
		{"escape to etc", "/home/user/../etc/passwd", ErrPathNotAllowed},
		{"escape to root", "/home/user/../../etc/shadow", ErrPathNotAllowed},
		{"escape via dots", "/home/user/./../../var/log", ErrPathNotAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.path)
			if err != tt.wantErr {
				t.Errorf("Validate(%q) = %v, want %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidate_NotAllowed(t *testing.T) {
	v := NewWithPaths([]string{"/home/user"}, []string{}, []string{})

	tests := []struct {
		name string
		path string
	}{
		{"outside allowed", "/var/log"},
		{"different tree", "/opt/app"},
		{"root", "/etc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.path)
			if err != ErrPathNotAllowed {
				t.Errorf("Validate(%q) = %v, want ErrPathNotAllowed", tt.path, err)
			}
		})
	}
}

func TestValidateWithSymlinkResolution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping symlink tests on Windows")
	}

	// Create temp directory for symlink tests
	tmpDir, err := os.MkdirTemp("", "pathval_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Resolve the temp directory to handle systems where /tmp is a symlink
	// (e.g., macOS where /var -> /private/var)
	resolvedTmpDir, err := filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	// Create a safe target file
	safeFile := filepath.Join(resolvedTmpDir, "safe.txt")
	if err := os.WriteFile(safeFile, []byte("safe"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a symlink to safe file
	safeLink := filepath.Join(resolvedTmpDir, "safe_link")
	if err := os.Symlink(safeFile, safeLink); err != nil {
		t.Fatal(err)
	}

	// Use the resolved path as allowed
	v := NewWithPaths([]string{resolvedTmpDir}, []string{}, []string{})

	t.Run("safe symlink", func(t *testing.T) {
		err := v.ValidateWithSymlinkResolution(safeLink)
		if err != nil {
			t.Errorf("ValidateWithSymlinkResolution() = %v, want nil", err)
		}
	})

	t.Run("non-existent path", func(t *testing.T) {
		err := v.ValidateWithSymlinkResolution(filepath.Join(resolvedTmpDir, "nonexistent"))
		if err != nil {
			t.Errorf("ValidateWithSymlinkResolution() for non-existent = %v, want nil", err)
		}
	})

	t.Run("regular file", func(t *testing.T) {
		err := v.ValidateWithSymlinkResolution(safeFile)
		if err != nil {
			t.Errorf("ValidateWithSymlinkResolution() for regular file = %v, want nil", err)
		}
	})
}

func TestValidateWithSymlinkResolution_Escape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping symlink tests on Windows")
	}

	// Create temp directories for symlink escape test
	tmpDir, err := os.MkdirTemp("", "pathval_allowed")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	outsideDir, err := os.MkdirTemp("", "pathval_outside")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(outsideDir)

	// Create a file outside allowed path
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a symlink that escapes to outside
	escapeLink := filepath.Join(tmpDir, "escape_link")
	if err := os.Symlink(outsideFile, escapeLink); err != nil {
		t.Fatal(err)
	}

	v := NewWithPaths([]string{tmpDir}, []string{}, []string{})

	t.Run("symlink escape attempt", func(t *testing.T) {
		err := v.ValidateWithSymlinkResolution(escapeLink)
		if err != ErrSymlinkTraversal {
			t.Errorf("ValidateWithSymlinkResolution() = %v, want ErrSymlinkTraversal", err)
		}
	})
}

func TestIsPathSafe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix path tests on Windows")
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"safe path", "/home/user/documents", true},
		{"forbidden path", "/etc/shadow", false},
		{"forbidden pattern", "/home/user/.ssh/id_rsa", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsPathSafe(tt.path)
			if got != tt.want {
				t.Errorf("IsPathSafe(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"clean path", "/home/user"},
		{"with dots", "/home/user/../user"},
		{"with double slash", "/home//user"},
		{"relative", "relative/path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizePath(tt.input)
			if result == "" {
				t.Error("SanitizePath returned empty string")
			}
			// Result should be cleaned
			if result != filepath.Clean(result) {
				t.Errorf("SanitizePath result not clean: %q", result)
			}
		})
	}
}

func TestErrorTypes(t *testing.T) {
	// Verify error types are defined
	if ErrPathTraversal == nil {
		t.Error("ErrPathTraversal is nil")
	}
	if ErrForbiddenPath == nil {
		t.Error("ErrForbiddenPath is nil")
	}
	if ErrPathNotAllowed == nil {
		t.Error("ErrPathNotAllowed is nil")
	}
	if ErrSymlinkTraversal == nil {
		t.Error("ErrSymlinkTraversal is nil")
	}

	// Verify they have meaningful messages
	if ErrPathTraversal.Error() == "" {
		t.Error("ErrPathTraversal has empty message")
	}
	if ErrForbiddenPath.Error() == "" {
		t.Error("ErrForbiddenPath has empty message")
	}
}

func TestForbiddenLists(t *testing.T) {
	// Verify forbidden lists are populated
	if len(ForbiddenPaths) == 0 {
		t.Error("ForbiddenPaths is empty")
	}
	if len(ForbiddenPatterns) == 0 {
		t.Error("ForbiddenPatterns is empty")
	}
	if len(ForbiddenPathsWindows) == 0 {
		t.Error("ForbiddenPathsWindows is empty")
	}
	if len(ForbiddenPatternsWindows) == 0 {
		t.Error("ForbiddenPatternsWindows is empty")
	}
}

func TestCaseInsensitivePatterns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix path tests on Windows")
	}

	v := New()

	// Test case variations of forbidden patterns
	casePaths := []string{
		"/home/user/.SSH/id_rsa",
		"/home/user/.Env",
		"/home/user/SERVER.PEM",
		"/home/user/Private.KEY",
	}

	for _, path := range casePaths {
		t.Run(path, func(t *testing.T) {
			err := v.Validate(path)
			if err != ErrForbiddenPath {
				t.Errorf("Validate(%q) = %v, want ErrForbiddenPath (case insensitive)", path, err)
			}
		})
	}
}
