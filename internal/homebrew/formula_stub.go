//go:build !darwin

// Package homebrew provides Homebrew cask and formula management for macOS.
package homebrew

import (
	"context"
	"fmt"
)

// IsBrewInstalled always returns false on non-macOS platforms.
func IsBrewInstalled() bool {
	return false
}

// GetBrewPath returns an empty string on non-macOS platforms.
func GetBrewPath() string {
	return ""
}

// EnsureBrewUser is not available on non-macOS platforms.
func EnsureBrewUser(ctx context.Context) error {
	return fmt.Errorf("Homebrew only available on macOS")
}

// GetNonRootUser is not available on non-macOS platforms.
func GetNonRootUser(ctx context.Context) (string, error) {
	return "", fmt.Errorf("Homebrew only available on macOS")
}

// InstallHomebrew is not available on non-macOS platforms.
func InstallHomebrew(ctx context.Context) error {
	return fmt.Errorf("Homebrew only available on macOS")
}

// InstallFormula is not available on non-macOS platforms.
func InstallFormula(ctx context.Context, formulaName string) (string, int, error) {
	return "", -1, fmt.Errorf("Homebrew formula installation only available on macOS")
}

// UninstallFormula is not available on non-macOS platforms.
func UninstallFormula(ctx context.Context, formulaName string) (string, int, error) {
	return "", -1, fmt.Errorf("Homebrew formula uninstallation only available on macOS")
}
