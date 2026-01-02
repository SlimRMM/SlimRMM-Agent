//go:build windows
// +build windows

package actions

import (
	"os"
)

// getFileOwnership returns owner and group for a file on Windows.
// Windows doesn't use Unix-style uid/gid, so we return empty strings.
func getFileOwnership(info os.FileInfo) (owner, group string) {
	// Windows uses ACLs instead of Unix permissions
	// Could be extended with Windows-specific code if needed
	return "", ""
}
