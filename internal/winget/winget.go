// Package winget provides Windows Package Manager (winget) detection and installation.
package winget

import (
	"context"
	"log/slog"
	"runtime"
	"sync"
)

// Client provides winget detection and management capabilities.
type Client struct {
	binaryPath string
	version    string
	mu         sync.RWMutex
}

// Status represents the current winget installation status.
type Status struct {
	Available   bool   `json:"available"`
	Version     string `json:"version,omitempty"`
	BinaryPath  string `json:"binary_path,omitempty"`
	SystemLevel bool   `json:"system_level"`
}

var (
	// Singleton client instance
	defaultClient *Client
	clientOnce    sync.Once
)

// New creates a new winget client and detects winget installation.
func New() *Client {
	c := &Client{}
	c.detect()
	return c
}

// GetDefault returns the default singleton winget client.
func GetDefault() *Client {
	clientOnce.Do(func() {
		defaultClient = New()
	})
	return defaultClient
}

// detect looks for winget installation.
func (c *Client) detect() {
	if runtime.GOOS != "windows" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.binaryPath = findWingetBinary()
	if c.binaryPath != "" {
		c.version = getWingetVersion(c.binaryPath)
	}
}

// Refresh re-detects winget installation status.
func (c *Client) Refresh() {
	c.detect()
}

// IsAvailable returns true if winget is installed and accessible.
func (c *Client) IsAvailable() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.binaryPath != ""
}

// GetVersion returns the installed winget version.
func (c *Client) GetVersion() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.version
}

// GetBinaryPath returns the path to the winget executable.
func (c *Client) GetBinaryPath() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.binaryPath
}

// GetStatus returns the complete winget status.
func (c *Client) GetStatus() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return Status{
		Available:   c.binaryPath != "",
		Version:     c.version,
		BinaryPath:  c.binaryPath,
		SystemLevel: c.binaryPath != "" && isSystemLevelInstall(c.binaryPath),
	}
}

// Install attempts to install winget on the system.
// This is only supported on Windows.
func (c *Client) Install(ctx context.Context) error {
	if runtime.GOOS != "windows" {
		return ErrNotWindows
	}
	return c.install(ctx)
}

// EnsureInstalled checks if winget is installed and installs it if not.
func EnsureInstalled(ctx context.Context, logger *slog.Logger) error {
	if runtime.GOOS != "windows" {
		logger.Debug("winget is only available on Windows, skipping")
		return nil
	}

	client := GetDefault()
	if client.IsAvailable() {
		logger.Info("winget already installed",
			"version", client.GetVersion(),
			"path", client.GetBinaryPath(),
		)
		return nil
	}

	logger.Info("winget not found, attempting installation")
	if err := client.Install(ctx); err != nil {
		logger.Error("failed to install winget", "error", err)
		return err
	}

	// Re-detect after installation
	client.Refresh()
	if client.IsAvailable() {
		logger.Info("winget installed successfully",
			"version", client.GetVersion(),
			"path", client.GetBinaryPath(),
		)
		return nil
	}

	logger.Warn("winget installation completed but binary not found")
	return ErrInstallFailed
}
