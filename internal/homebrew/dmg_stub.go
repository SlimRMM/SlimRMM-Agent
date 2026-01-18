//go:build !darwin

package homebrew

import (
	"context"
	"fmt"
)

// MountDMG is not available on non-macOS platforms.
func MountDMG(ctx context.Context, dmgPath string) (string, error) {
	return "", fmt.Errorf("DMG mounting only available on macOS")
}

// UnmountDMG is not available on non-macOS platforms.
func UnmountDMG(ctx context.Context, mountPoint string) error {
	return fmt.Errorf("DMG unmounting only available on macOS")
}

// InstallAppFromDMG is not available on non-macOS platforms.
func InstallAppFromDMG(ctx context.Context, dmgPath, appName string) error {
	return fmt.Errorf("DMG installation only available on macOS")
}
