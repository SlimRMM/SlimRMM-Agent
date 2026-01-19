// Package winget provides Windows Package Manager (winget) detection and installation.
package winget

import (
	"context"
	"log/slog"
	"regexp"
	"runtime"
	"sync"
	"time"
)

// packageIDPattern validates Winget package IDs (alphanumeric with dots, hyphens, underscores).
var packageIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// IsValidPackageID checks if a Winget package ID is valid.
func IsValidPackageID(id string) bool {
	if len(id) == 0 || len(id) > 256 {
		return false
	}
	return packageIDPattern.MatchString(id)
}

// Client provides winget detection and management capabilities.
type Client struct {
	binaryPath string
	version    string
	mu         sync.RWMutex
}

// Status represents the current winget installation status.
type Status struct {
	Available                   bool   `json:"available"`
	Version                     string `json:"version,omitempty"`
	BinaryPath                  string `json:"binary_path,omitempty"`
	SystemLevel                 bool   `json:"system_level"`
	PowerShell7Available        bool   `json:"powershell7_available"`
	WinGetClientModuleAvailable bool   `json:"winget_client_module_available"`
	LastRepair                  string `json:"last_repair,omitempty"`
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

	slog.Debug("detecting winget installation")
	c.binaryPath = findWingetBinary()

	if c.binaryPath != "" {
		c.version = getWingetVersion(c.binaryPath)
		slog.Info("winget detected",
			"path", c.binaryPath,
			"version", c.version,
		)
	} else {
		c.version = ""
		slog.Info("winget not detected on this system")
	}
}

// Refresh re-detects winget installation status.
func (c *Client) Refresh() {
	c.detect()
}

// RefreshWithRetry re-detects winget installation status with retries.
// This is useful after installation as the binary may not be immediately available.
func (c *Client) RefreshWithRetry(maxAttempts int, initialDelay time.Duration) bool {
	delay := initialDelay
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		slog.Info("attempting winget detection",
			"attempt", attempt,
			"max_attempts", maxAttempts,
		)
		c.detect()
		if c.IsAvailable() {
			slog.Info("winget detected after retry",
				"attempt", attempt,
				"path", c.GetBinaryPath(),
				"version", c.GetVersion(),
			)
			return true
		}
		if attempt < maxAttempts {
			slog.Debug("winget not found, waiting before retry",
				"delay", delay,
			)
			time.Sleep(delay)
			delay *= 2 // Exponential backoff
			if delay > 10*time.Second {
				delay = 10 * time.Second
			}
		}
	}
	slog.Warn("winget not found after all retry attempts",
		"attempts", maxAttempts,
	)
	return false
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

	ps7Available, moduleAvailable := detectPowerShell7AndModule()

	return Status{
		Available:                   c.binaryPath != "",
		Version:                     c.version,
		BinaryPath:                  c.binaryPath,
		SystemLevel:                 c.binaryPath != "" && isSystemLevelInstall(c.binaryPath),
		PowerShell7Available:        ps7Available,
		WinGetClientModuleAvailable: moduleAvailable,
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

	// Re-detect after installation with retries
	// After Add-AppxProvisionedPackage, the binary may not be immediately available
	if client.RefreshWithRetry(5, 2*time.Second) {
		logger.Info("winget installed successfully",
			"version", client.GetVersion(),
			"path", client.GetBinaryPath(),
		)
		return nil
	}

	logger.Warn("winget installation completed but binary not found after retries")
	return ErrInstallFailed
}

// EnsureSystemOnly removes any per-user winget installations and ensures
// only the system-wide installation exists. This prevents having to update
// winget in multiple places.
func EnsureSystemOnly(ctx context.Context, logger *slog.Logger) error {
	if runtime.GOOS != "windows" {
		return nil
	}

	client := GetDefault()
	return client.ensureSystemOnly(ctx, logger)
}

// IsSystemLevel returns true if winget is installed system-wide.
func (c *Client) IsSystemLevel() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.binaryPath != "" && isSystemLevelInstall(c.binaryPath)
}

// Update checks if winget has an update available and installs it.
// This updates winget system-wide using the same method as initial installation.
func (c *Client) Update(ctx context.Context) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	return c.update(ctx)
}

// CheckAndUpdate checks if winget needs updating and updates it if necessary.
// Returns true if an update was performed.
func CheckAndUpdate(ctx context.Context, logger *slog.Logger) (bool, error) {
	if runtime.GOOS != "windows" {
		return false, nil
	}

	client := GetDefault()
	return client.checkAndUpdate(ctx, logger)
}
