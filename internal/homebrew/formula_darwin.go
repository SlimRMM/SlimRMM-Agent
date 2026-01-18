//go:build darwin

package homebrew

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

const (
	// BrewPathAppleSilicon is the standard Homebrew installation path on Apple Silicon.
	BrewPathAppleSilicon = "/opt/homebrew"
	// BrewPathIntel is the standard Homebrew installation path on Intel Macs.
	BrewPathIntel = "/usr/local"
)

// IsBrewInstalled checks if Homebrew is available.
func IsBrewInstalled() bool {
	// Check Apple Silicon path first
	if _, err := os.Stat(filepath.Join(BrewPathAppleSilicon, "bin", "brew")); err == nil {
		return true
	}
	// Check Intel path
	if _, err := os.Stat(filepath.Join(BrewPathIntel, "bin", "brew")); err == nil {
		return true
	}
	return false
}

// GetBrewPath returns the path to brew binary.
func GetBrewPath() string {
	if _, err := os.Stat(filepath.Join(BrewPathAppleSilicon, "bin", "brew")); err == nil {
		return filepath.Join(BrewPathAppleSilicon, "bin", "brew")
	}
	return filepath.Join(BrewPathIntel, "bin", "brew")
}

// EnsureBrewUser finds or uses the non-root user for Homebrew operations.
func EnsureBrewUser(ctx context.Context) error {
	// We need to find a non-root user to run Homebrew
	// Homebrew refuses to run as root
	_, err := GetNonRootUser(ctx)
	return err
}

// GetNonRootUser finds the primary non-root user on the system.
func GetNonRootUser(ctx context.Context) (string, error) {
	// Try to find the console user (the user currently logged in)
	cmd := exec.CommandContext(ctx, "stat", "-f", "%Su", "/dev/console")
	output, err := cmd.Output()
	if err == nil {
		username := strings.TrimSpace(string(output))
		if username != "" && username != "root" {
			return username, nil
		}
	}

	// Fallback: look for users with UID >= 500 (regular users on macOS)
	users, err := user.Current()
	if err == nil && users.Uid != "0" {
		return users.Username, nil
	}

	// Try common user directories
	entries, err := os.ReadDir("/Users")
	if err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() && name != "Shared" && !strings.HasPrefix(name, ".") {
				return name, nil
			}
		}
	}

	return "", fmt.Errorf("no non-root user found for Homebrew operations")
}

// InstallHomebrew installs Homebrew for a non-root user.
func InstallHomebrew(ctx context.Context) error {
	if IsBrewInstalled() {
		return nil
	}

	username, err := GetNonRootUser(ctx)
	if err != nil {
		return err
	}

	// Download and run Homebrew installer as the non-root user
	script := `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`

	cmd := exec.CommandContext(ctx, "sudo", "-u", username, "bash", "-c", script)
	cmd.Env = append(os.Environ(), "NONINTERACTIVE=1")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("install homebrew: %w\nOutput: %s", err, output)
	}

	return nil
}

// InstallFormula installs a Homebrew formula.
func InstallFormula(ctx context.Context, formulaName string) (string, int, error) {
	// Ensure Homebrew is installed
	if err := InstallHomebrew(ctx); err != nil {
		return "", -1, fmt.Errorf("ensure homebrew: %w", err)
	}

	username, err := GetNonRootUser(ctx)
	if err != nil {
		return "", -1, fmt.Errorf("get non-root user: %w", err)
	}

	brewPath := GetBrewPath()

	// Run brew install as non-root user
	cmd := exec.CommandContext(ctx, "sudo", "-u", username, brewPath, "install", formulaName)
	output, err := cmd.CombinedOutput()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return string(output), exitCode, err
}

// UninstallFormula uninstalls a Homebrew formula.
func UninstallFormula(ctx context.Context, formulaName string) (string, int, error) {
	if !IsBrewInstalled() {
		return "", -1, fmt.Errorf("Homebrew is not installed")
	}

	username, err := GetNonRootUser(ctx)
	if err != nil {
		return "", -1, fmt.Errorf("get non-root user: %w", err)
	}

	brewPath := GetBrewPath()

	// Run brew uninstall as non-root user
	cmd := exec.CommandContext(ctx, "sudo", "-u", username, brewPath, "uninstall", formulaName)
	output, err := cmd.CombinedOutput()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return string(output), exitCode, err
}
