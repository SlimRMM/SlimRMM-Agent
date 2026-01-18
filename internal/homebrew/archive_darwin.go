//go:build darwin

package homebrew

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ArtifactType represents the type of installable artifact found.
type ArtifactType string

const (
	ArtifactApp     ArtifactType = "app"
	ArtifactPkg     ArtifactType = "pkg"
	ArtifactDmg     ArtifactType = "dmg"
	ArtifactZip     ArtifactType = "zip"
	ArtifactUnknown ArtifactType = "unknown"
)

// ExtractedArtifact represents the result of extracting/finding installable content.
type ExtractedArtifact struct {
	Type    ArtifactType
	Path    string   // Path to the artifact
	AppName string   // For .app, the name like "Firefox.app"
	Cleanup []string // Paths to clean up after installation
}

// DetectArtifactType determines the type of file based on extension.
func DetectArtifactType(filePath string) ArtifactType {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".app":
		return ArtifactApp
	case ".pkg":
		return ArtifactPkg
	case ".dmg":
		return ArtifactDmg
	case ".zip":
		return ArtifactZip
	default:
		return ArtifactUnknown
	}
}

// ExtractAndFindArtifact handles all container formats and returns the installable artifact.
// This function recursively extracts nested containers until it finds .app or .pkg.
func ExtractAndFindArtifact(ctx context.Context, downloadPath, tempDir string) (*ExtractedArtifact, error) {
	artifactType := DetectArtifactType(downloadPath)

	switch artifactType {
	case ArtifactZip:
		return extractZipAndFind(ctx, downloadPath, tempDir)
	case ArtifactDmg:
		return extractDmgAndFind(ctx, downloadPath, tempDir)
	case ArtifactPkg:
		return &ExtractedArtifact{
			Type: ArtifactPkg,
			Path: downloadPath,
		}, nil
	case ArtifactApp:
		return &ExtractedArtifact{
			Type:    ArtifactApp,
			Path:    downloadPath,
			AppName: filepath.Base(downloadPath),
		}, nil
	default:
		return nil, fmt.Errorf("unknown artifact type for: %s", downloadPath)
	}
}

// extractZipAndFind extracts a ZIP and recursively finds the installable artifact.
func extractZipAndFind(ctx context.Context, zipPath, tempDir string) (*ExtractedArtifact, error) {
	extractDir := filepath.Join(tempDir, "zip_extract")
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return nil, fmt.Errorf("create extract dir: %w", err)
	}

	// Extract ZIP
	if err := extractZip(zipPath, extractDir); err != nil {
		return nil, fmt.Errorf("extract zip: %w", err)
	}

	// Search for artifacts in order of preference: .app, .pkg, .dmg
	artifact, err := findArtifactInDir(ctx, extractDir, tempDir)
	if err != nil {
		return nil, err
	}

	artifact.Cleanup = append(artifact.Cleanup, extractDir)
	return artifact, nil
}

// extractDmgAndFind mounts a DMG and finds the installable artifact inside.
func extractDmgAndFind(ctx context.Context, dmgPath, tempDir string) (*ExtractedArtifact, error) {
	// Mount DMG
	mountPoint, err := MountDMG(ctx, dmgPath)
	if err != nil {
		return nil, fmt.Errorf("mount dmg: %w", err)
	}

	// Find artifact in mounted DMG
	artifact, err := findArtifactInDir(ctx, mountPoint, tempDir)
	if err != nil {
		UnmountDMG(ctx, mountPoint)
		return nil, err
	}

	// If we found a nested DMG or ZIP, we need to copy it out before unmounting
	if artifact.Type == ArtifactDmg || artifact.Type == ArtifactZip {
		copyPath := filepath.Join(tempDir, filepath.Base(artifact.Path))
		if err := copyFile(artifact.Path, copyPath); err != nil {
			UnmountDMG(ctx, mountPoint)
			return nil, fmt.Errorf("copy nested archive: %w", err)
		}
		UnmountDMG(ctx, mountPoint)

		// Recursively process the nested archive
		return ExtractAndFindArtifact(ctx, copyPath, tempDir)
	}

	// For .app, copy it out before unmounting
	if artifact.Type == ArtifactApp {
		copyPath := filepath.Join(tempDir, filepath.Base(artifact.Path))
		if err := copyDir(artifact.Path, copyPath); err != nil {
			UnmountDMG(ctx, mountPoint)
			return nil, fmt.Errorf("copy app from dmg: %w", err)
		}
		UnmountDMG(ctx, mountPoint)
		artifact.Path = copyPath
		return artifact, nil
	}

	// For .pkg, we can run installer directly from mount point
	artifact.Cleanup = append(artifact.Cleanup, "unmount:"+mountPoint)
	return artifact, nil
}

// findArtifactInDir searches a directory for installable artifacts.
// Priority: .app > .pkg > .dmg > .zip
func findArtifactInDir(ctx context.Context, dir, tempDir string) (*ExtractedArtifact, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir: %w", err)
	}

	var apps, pkgs, dmgs, zips []string

	for _, entry := range entries {
		name := entry.Name()
		// Skip hidden files and __MACOSX
		if strings.HasPrefix(name, ".") || name == "__MACOSX" {
			continue
		}

		fullPath := filepath.Join(dir, name)

		if strings.HasSuffix(name, ".app") {
			apps = append(apps, fullPath)
		} else if strings.HasSuffix(name, ".pkg") {
			pkgs = append(pkgs, fullPath)
		} else if strings.HasSuffix(name, ".dmg") {
			dmgs = append(dmgs, fullPath)
		} else if strings.HasSuffix(name, ".zip") {
			zips = append(zips, fullPath)
		} else if entry.IsDir() {
			// Recursively search subdirectories (but not too deep)
			subArtifact, err := findArtifactInDir(ctx, fullPath, tempDir)
			if err == nil && subArtifact != nil {
				return subArtifact, nil
			}
		}
	}

	// Return first found in priority order
	if len(apps) > 0 {
		return &ExtractedArtifact{
			Type:    ArtifactApp,
			Path:    apps[0],
			AppName: filepath.Base(apps[0]),
		}, nil
	}
	if len(pkgs) > 0 {
		return &ExtractedArtifact{
			Type: ArtifactPkg,
			Path: pkgs[0],
		}, nil
	}
	if len(dmgs) > 0 {
		// Nested DMG - need to process recursively
		return &ExtractedArtifact{
			Type: ArtifactDmg,
			Path: dmgs[0],
		}, nil
	}
	if len(zips) > 0 {
		// Nested ZIP - need to process recursively
		return &ExtractedArtifact{
			Type: ArtifactZip,
			Path: zips[0],
		}, nil
	}

	return nil, fmt.Errorf("no installable artifact found in: %s", dir)
}

// extractZip extracts a ZIP file to the destination directory.
func extractZip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		// Security: prevent zip slip
		destPath := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(destPath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path in zip: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(destPath, f.Mode())
			continue
		}

		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return err
		}

		destFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		srcFile, err := f.Open()
		if err != nil {
			destFile.Close()
			return err
		}

		_, err = io.Copy(destFile, srcFile)
		srcFile.Close()
		destFile.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

// CleanupArtifact cleans up temporary files and unmounts DMGs.
func CleanupArtifact(ctx context.Context, artifact *ExtractedArtifact) {
	if artifact == nil {
		return
	}

	for _, path := range artifact.Cleanup {
		if strings.HasPrefix(path, "unmount:") {
			mountPoint := strings.TrimPrefix(path, "unmount:")
			UnmountDMG(ctx, mountPoint)
		} else {
			os.RemoveAll(path)
		}
	}
}

// InstallArtifact installs the extracted artifact.
func InstallArtifact(ctx context.Context, artifact *ExtractedArtifact) (string, int, error) {
	switch artifact.Type {
	case ArtifactApp:
		return installApp(ctx, artifact.Path)
	case ArtifactPkg:
		return installPkg(ctx, artifact.Path)
	default:
		return "", 1, fmt.Errorf("cannot install artifact type: %s", artifact.Type)
	}
}

// installApp copies .app to /Applications.
func installApp(ctx context.Context, appPath string) (string, int, error) {
	appName := filepath.Base(appPath)
	destPath := filepath.Join("/Applications", appName)

	// Remove existing app if present
	if _, err := os.Stat(destPath); err == nil {
		if err := os.RemoveAll(destPath); err != nil {
			return fmt.Sprintf("Failed to remove existing app: %v", err), 1, err
		}
	}

	// Copy app bundle
	if err := copyDir(appPath, destPath); err != nil {
		return fmt.Sprintf("Failed to copy app: %v", err), 1, err
	}

	// Remove quarantine flag
	exec.CommandContext(ctx, "xattr", "-rd", "com.apple.quarantine", destPath).Run()

	return fmt.Sprintf("Successfully installed %s to /Applications", appName), 0, nil
}

// installPkg runs the macOS installer for a .pkg file.
func installPkg(ctx context.Context, pkgPath string) (string, int, error) {
	cmd := exec.CommandContext(ctx, "installer",
		"-pkg", pkgPath,
		"-target", "/",
		"-verboseR",
	)

	output, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return string(output), exitCode, err
}
