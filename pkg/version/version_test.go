package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestGet(t *testing.T) {
	info := Get()

	// Check that default values are set
	if info.Version == "" {
		t.Error("Version should not be empty")
	}

	if info.GitCommit == "" {
		t.Error("GitCommit should not be empty")
	}

	if info.BuildDate == "" {
		t.Error("BuildDate should not be empty")
	}

	// Check runtime values
	if info.GoVersion != runtime.Version() {
		t.Errorf("GoVersion = %s, want %s", info.GoVersion, runtime.Version())
	}

	if info.OS != runtime.GOOS {
		t.Errorf("OS = %s, want %s", info.OS, runtime.GOOS)
	}

	if info.Arch != runtime.GOARCH {
		t.Errorf("Arch = %s, want %s", info.Arch, runtime.GOARCH)
	}
}

func TestInfoString(t *testing.T) {
	tests := []struct {
		name     string
		info     Info
		contains []string
	}{
		{
			name: "normal commit",
			info: Info{
				Version:   "1.0.0",
				GitCommit: "abc12345def67890",
				BuildDate: "2024-01-01",
				GoVersion: "go1.21.0",
			},
			contains: []string{"SlimRMM Agent", "1.0.0", "abc12345", "2024-01-01", "go1.21.0"},
		},
		{
			name: "short commit",
			info: Info{
				Version:   "dev",
				GitCommit: "abc",
				BuildDate: "unknown",
				GoVersion: "go1.22.0",
			},
			contains: []string{"SlimRMM Agent", "dev", "abc", "unknown"},
		},
		{
			name: "exactly 8 char commit",
			info: Info{
				Version:   "2.0.0",
				GitCommit: "12345678",
				BuildDate: "2024-06-15",
				GoVersion: "go1.23.0",
			},
			contains: []string{"12345678"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.info.String()

			for _, want := range tt.contains {
				if !strings.Contains(s, want) {
					t.Errorf("String() = %q, should contain %q", s, want)
				}
			}
		})
	}
}

func TestInfoStringCommitTruncation(t *testing.T) {
	info := Info{
		Version:   "1.0.0",
		GitCommit: "abcdefghijklmnop",
		BuildDate: "2024-01-01",
		GoVersion: "go1.21.0",
	}

	s := info.String()

	// Should contain truncated commit (first 8 chars)
	if !strings.Contains(s, "abcdefgh") {
		t.Error("should contain first 8 chars of commit")
	}

	// Should NOT contain full commit
	if strings.Contains(s, "abcdefghijklmnop") {
		t.Error("should NOT contain full commit")
	}
}

func TestDefaultVersionValues(t *testing.T) {
	// Test that default values are set correctly
	if Version == "" {
		t.Error("Version should have a default value")
	}

	if GitCommit == "" {
		t.Error("GitCommit should have a default value")
	}

	if BuildDate == "" {
		t.Error("BuildDate should have a default value")
	}
}
