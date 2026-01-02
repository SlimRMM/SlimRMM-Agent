// Package version provides build version information.
// Version is set at build time using ldflags.
package version

import (
	"fmt"
	"runtime"
)

// Build-time variables set via ldflags
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

// Info contains version information.
type Info struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Get returns the current version info.
func Get() Info {
	return Info{
		Version:   Version,
		GitCommit: GitCommit,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

// String returns a human-readable version string.
func (i Info) String() string {
	commit := i.GitCommit
	if len(commit) > 8 {
		commit = commit[:8]
	}
	return fmt.Sprintf("SlimRMM Agent %s (%s) built %s with %s",
		i.Version, commit, i.BuildDate, i.GoVersion)
}
