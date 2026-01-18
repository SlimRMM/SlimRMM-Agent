//go:build darwin

package homebrew

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// MountDMG mounts a DMG file and returns the mount point.
func MountDMG(ctx context.Context, dmgPath string) (string, error) {
	slog.Info("[HOMEBREW] MountDMG called", "dmg_path", dmgPath)

	// hdiutil attach with -nobrowse to avoid Finder opening
	cmd := exec.CommandContext(ctx, "hdiutil", "attach",
		"-nobrowse",           // Don't show in Finder
		"-readonly",           // Read-only mount
		"-mountrandom", "/tmp", // Random mount point in /tmp
		dmgPath,
	)

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			slog.Error("[HOMEBREW] hdiutil attach failed", "stderr", string(exitErr.Stderr))
			return "", fmt.Errorf("hdiutil attach failed: %s", string(exitErr.Stderr))
		}
		slog.Error("[HOMEBREW] hdiutil attach error", "error", err)
		return "", fmt.Errorf("hdiutil attach: %w", err)
	}
	slog.Info("[HOMEBREW] hdiutil output", "output", string(output))

	// Parse output to find mount point - it's the last field in the output
	// On macOS, /tmp is a symlink to /private/tmp, so we need to check both
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			// Last field is the mount point
			mountPoint := fields[len(fields)-1]
			if strings.HasPrefix(mountPoint, "/tmp/") ||
				strings.HasPrefix(mountPoint, "/private/tmp/") ||
				strings.HasPrefix(mountPoint, "/Volumes/") {
				slog.Info("[HOMEBREW] DMG mount point found", "mount_point", mountPoint)
				return mountPoint, nil
			}
		}
	}

	slog.Error("[HOMEBREW] No mount point found in hdiutil output")
	return "", fmt.Errorf("no mount point found in hdiutil output")
}

// UnmountDMG unmounts a mounted DMG.
func UnmountDMG(ctx context.Context, mountPoint string) error {
	cmd := exec.CommandContext(ctx, "hdiutil", "detach", mountPoint, "-force")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("hdiutil detach: %w", err)
	}
	return nil
}

// InstallAppFromDMG mounts DMG, copies .app to /Applications, unmounts.
func InstallAppFromDMG(ctx context.Context, dmgPath, appName string) error {
	// Mount DMG
	mountPoint, err := MountDMG(ctx, dmgPath)
	if err != nil {
		return fmt.Errorf("mount DMG: %w", err)
	}
	defer UnmountDMG(ctx, mountPoint)

	// Find .app in mount point
	appPath := filepath.Join(mountPoint, appName)
	if !strings.HasSuffix(appPath, ".app") {
		appPath += ".app"
	}

	if _, err := os.Stat(appPath); os.IsNotExist(err) {
		// Try to find any .app in mount point
		entries, _ := os.ReadDir(mountPoint)
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".app") {
				appPath = filepath.Join(mountPoint, entry.Name())
				appName = entry.Name()
				break
			}
		}
	}

	if _, err := os.Stat(appPath); os.IsNotExist(err) {
		return fmt.Errorf("app not found in DMG: %s", appName)
	}

	// Destination in /Applications
	destPath := filepath.Join("/Applications", filepath.Base(appPath))

	// Remove existing app if present
	if _, err := os.Stat(destPath); err == nil {
		if err := os.RemoveAll(destPath); err != nil {
			return fmt.Errorf("remove existing app: %w", err)
		}
	}

	// Copy .app bundle to /Applications
	if err := copyDir(appPath, destPath); err != nil {
		return fmt.Errorf("copy app: %w", err)
	}

	// Remove quarantine flag
	exec.CommandContext(ctx, "xattr", "-rd", "com.apple.quarantine", destPath).Run()

	return nil
}

// copyDir recursively copies a directory.
func copyDir(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// copyFile copies a single file.
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}
