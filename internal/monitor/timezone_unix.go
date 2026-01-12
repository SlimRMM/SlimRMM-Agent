//go:build !windows

package monitor

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// getSystemTimezone returns the system's IANA timezone.
// On Unix systems, this reads /etc/timezone or resolves /etc/localtime.
func getSystemTimezone() string {
	// Try /etc/timezone first (Debian-based systems)
	if data, err := os.ReadFile("/etc/timezone"); err == nil {
		tz := strings.TrimSpace(string(data))
		if tz != "" {
			return tz
		}
	}

	// Try to resolve /etc/localtime symlink (most Linux and macOS)
	if link, err := os.Readlink("/etc/localtime"); err == nil {
		// /etc/localtime -> /usr/share/zoneinfo/America/New_York
		// or /var/db/timezone/zoneinfo/America/New_York (macOS)
		parts := strings.Split(link, "/zoneinfo/")
		if len(parts) == 2 {
			return parts[1]
		}
	}

	// Try to find timezone from realpath of /etc/localtime
	if realPath, err := filepath.EvalSymlinks("/etc/localtime"); err == nil {
		parts := strings.Split(realPath, "/zoneinfo/")
		if len(parts) == 2 {
			return parts[1]
		}
	}

	// macOS: Try reading /var/db/timezone/tz
	if data, err := os.ReadFile("/var/db/timezone/tz"); err == nil {
		tz := strings.TrimSpace(string(data))
		if tz != "" {
			return tz
		}
	}

	// Fall back to Go's local timezone name
	name, _ := time.Now().Zone()
	if name != "" && name != "Local" {
		return name
	}

	// Last resort: use time.Local
	return time.Local.String()
}
