// Package validation provides pre-uninstall validation services.
//go:build darwin

package validation

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/slimrmm/slimrmm-agent/internal/homebrew"
)

// PKGValidator validates macOS PKG installations.
type PKGValidator struct {
	logger *slog.Logger
}

// NewPKGValidator creates a new PKG validator.
func NewPKGValidator(logger *slog.Logger) *PKGValidator {
	return &PKGValidator{logger: logger}
}

// CanHandle returns true for PKG installations.
func (v *PKGValidator) CanHandle(installationType string) bool {
	return installationType == "pkg"
}

// IsAvailable returns true if pkgutil is available.
func (v *PKGValidator) IsAvailable() bool {
	_, err := exec.LookPath("pkgutil")
	return err == nil
}

// Validate validates a macOS PKG installation.
func (v *PKGValidator) Validate(ctx context.Context, req *ValidationRequest) (*ValidationResult, error) {
	result := &ValidationResult{
		InstallType:    "pkg",
		PackageManager: "pkgutil",
	}

	packageID := req.PackageIdentifier

	// Check if package is installed via pkgutil
	cmd := exec.CommandContext(ctx, "pkgutil", "--pkg-info", packageID)
	output, err := cmd.Output()
	if err != nil {
		result.IsInstalled = false
		result.Errors = append(result.Errors, "Package not found via pkgutil")
		return result, nil
	}

	result.IsInstalled = true

	// Parse pkgutil output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			switch key {
			case "version":
				result.CurrentVersion = value
			case "location":
				result.InstallLocation = value
			}
		}
	}

	// Get file list and estimate size
	cmd = exec.CommandContext(ctx, "pkgutil", "--files", packageID)
	filesOutput, _ := cmd.Output()
	files := strings.Split(strings.TrimSpace(string(filesOutput)), "\n")

	var totalSize int64
	baseLocation := result.InstallLocation
	if baseLocation == "" {
		baseLocation = "/"
	}

	for _, file := range files {
		if file != "" {
			fullPath := filepath.Join(baseLocation, file)
			if info, err := os.Stat(fullPath); err == nil {
				totalSize += info.Size()
			}
		}
	}
	result.EstimatedSpaceBytes = totalSize

	return result, nil
}

// CaskValidator validates Homebrew Cask installations.
type CaskValidator struct {
	logger *slog.Logger
}

// NewCaskValidator creates a new Cask validator.
func NewCaskValidator(logger *slog.Logger) *CaskValidator {
	return &CaskValidator{logger: logger}
}

// CanHandle returns true for Homebrew Cask installations.
func (v *CaskValidator) CanHandle(installationType string) bool {
	return installationType == "homebrew_cask"
}

// IsAvailable returns true if brew is available.
func (v *CaskValidator) IsAvailable() bool {
	_, err := exec.LookPath("brew")
	return err == nil
}

// Validate validates a Homebrew Cask installation.
func (v *CaskValidator) Validate(ctx context.Context, req *ValidationRequest) (*ValidationResult, error) {
	result := &ValidationResult{
		InstallType:    "homebrew_cask",
		PackageManager: "brew",
	}

	caskName := req.CaskName
	if caskName == "" {
		caskName = req.PackageIdentifier
	}

	// Validate cask name
	if !homebrew.IsValidCaskName(caskName) {
		result.Errors = append(result.Errors, "Invalid cask name")
		return result, nil
	}

	// Check if cask is installed
	cmd := exec.CommandContext(ctx, "brew", "list", "--cask", caskName)
	if err := cmd.Run(); err != nil {
		result.IsInstalled = false
		result.Errors = append(result.Errors, "Cask not installed")
		return result, nil
	}

	result.IsInstalled = true

	// Get cask info
	info, err := homebrew.FetchCaskInfo(ctx, caskName)
	if err == nil && info != nil {
		result.CurrentVersion = info.Version
	}

	// Find app bundle and estimate size
	appPaths := []string{
		filepath.Join("/Applications", req.AppName+".app"),
		filepath.Join(os.Getenv("HOME"), "Applications", req.AppName+".app"),
	}

	for _, appPath := range appPaths {
		if info, err := os.Stat(appPath); err == nil {
			result.InstallLocation = appPath
			result.EstimatedSpaceBytes = getDirSize(appPath)
			_ = info
			break
		}
	}

	// Get zap stanza for additional cleanup paths
	if fullInfo, err := homebrew.FetchCaskInfoFull(caskName); err == nil {
		if zapItems, _ := homebrew.ParseZapStanza(fullInfo); len(zapItems) > 0 {
			for _, zap := range zapItems {
				for _, path := range append(zap.Trash, zap.Delete...) {
					expandedPath := expandPath(path)
					if size := getDirSize(expandedPath); size > 0 {
						result.EstimatedSpaceBytes += size
					}
				}
			}
		}
	}

	// Check for running processes
	if req.AppName != "" {
		result.RunningProcesses = v.findRunningProcesses(ctx, req.AppName)
	}

	return result, nil
}

// findRunningProcesses finds running processes for an app on macOS.
func (v *CaskValidator) findRunningProcesses(ctx context.Context, appName string) []ProcessInfo {
	var processes []ProcessInfo

	cmd := exec.CommandContext(ctx, "pgrep", "-fl", appName)
	output, err := cmd.Output()
	if err != nil {
		return processes
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, " ", 2)
		if len(parts) >= 2 {
			var pid int
			if _, err := strings.NewReader(parts[0]).Read([]byte(parts[0])); err == nil {
				pid = 0
				for _, ch := range parts[0] {
					if ch >= '0' && ch <= '9' {
						pid = pid*10 + int(ch-'0')
					}
				}
			}
			processes = append(processes, ProcessInfo{
				Name: parts[1],
				PID:  pid,
			})
		}
	}

	return processes
}

// getDirSize recursively calculates directory size.
func getDirSize(path string) int64 {
	var size int64
	filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size
}

// expandPath expands home directory and environment variables.
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, path[2:])
		}
	}
	return os.ExpandEnv(path)
}
