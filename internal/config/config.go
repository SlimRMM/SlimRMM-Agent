// Package config handles agent configuration loading and saving.
// Configuration is stored in JSON format with restricted permissions (0600).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const (
	configFileName = ".slimrmm_config.json"
	configFileMode = 0600
	certsDirMode   = 0700
)

// Config holds the agent configuration.
type Config struct {
	Server               string `json:"server"`
	UUID                 string `json:"uuid"`
	MTLSEnabled          bool   `json:"mtls_enabled"`
	InstallDate          string `json:"install_date,omitempty"`
	LastConnection       string `json:"last_connection,omitempty"`
	LastHeartbeat        string `json:"last_heartbeat,omitempty"`
	ReregistrationSecret string `json:"reregistration_secret,omitempty"`

	// Tamper protection settings
	TamperProtection   bool   `json:"tamper_protection,omitempty"`
	UninstallKeyHash   string `json:"uninstall_key_hash,omitempty"`
	WatchdogEnabled    bool   `json:"watchdog_enabled,omitempty"`
	TamperAlertEnabled bool   `json:"tamper_alert_enabled,omitempty"`

	mu       sync.RWMutex
	filePath string
}

// Paths holds the various paths used by the agent.
type Paths struct {
	BaseDir    string
	ConfigFile string
	CertsDir   string
	LogDir     string
	CACert     string
	ClientCert string
	ClientKey  string
}

var (
	ErrConfigNotFound = errors.New("configuration file not found")
	ErrInvalidConfig  = errors.New("invalid configuration")
)

// DefaultPaths returns the default paths for the current OS.
// Uses OS-native locations:
// - macOS: /Applications/SlimRMM.app/Contents/Data/
// - Linux: /var/lib/slimrmm/
// - Windows: C:\Program Files\SlimRMM\
func DefaultPaths() Paths {
	var baseDir, logDir string

	switch runtime.GOOS {
	case "darwin":
		baseDir = "/Applications/SlimRMM.app/Contents/Data"
		logDir = "/Library/Logs/SlimRMM" // Apple-recommended location for system daemons
	case "windows":
		baseDir = filepath.Join(os.Getenv("ProgramFiles"), "SlimRMM")
		logDir = filepath.Join(baseDir, "log")
	default: // linux
		baseDir = "/var/lib/slimrmm"
		logDir = "/var/log/slimrmm"
	}

	certsDir := filepath.Join(baseDir, "certs")

	return Paths{
		BaseDir:    baseDir,
		ConfigFile: filepath.Join(baseDir, configFileName),
		CertsDir:   certsDir,
		LogDir:     logDir,
		CACert:     filepath.Join(certsDir, "ca.crt"),
		ClientCert: filepath.Join(certsDir, "client.crt"),
		ClientKey:  filepath.Join(certsDir, "client.key"),
	}
}

// Load reads the configuration from disk.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrConfigNotFound
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if cfg.Server == "" {
		return nil, fmt.Errorf("%w: server is required", ErrInvalidConfig)
	}

	cfg.filePath = path
	return &cfg, nil
}

// Save writes the configuration to disk with restricted permissions.
func (c *Config) Save() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.filePath == "" {
		return errors.New("config file path not set")
	}

	// Ensure directory exists
	dir := filepath.Dir(c.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}

	if err := os.WriteFile(c.filePath, data, configFileMode); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	// Explicitly enforce 0600 permissions. os.WriteFile only applies the mode
	// on file creation (subject to umask) — an existing file keeps its old
	// perms. Chmod is a no-op with respect to unix perms on Windows.
	if err := os.Chmod(c.filePath, configFileMode); err != nil {
		return fmt.Errorf("setting config permissions: %w", err)
	}

	return nil
}

// redact returns a fixed placeholder for non-empty secrets and an empty string
// for empty ones, so redacted repr still conveys presence/absence without
// leaking values.
func redact(s string) string {
	if s == "" {
		return ""
	}
	return "***REDACTED***"
}

// String implements fmt.Stringer. It returns a human-readable representation
// of the Config with all secret fields redacted. JSON serialisation is
// unaffected because it does not consult String().
func (c *Config) String() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return fmt.Sprintf("Config{Server:%q UUID:%q MTLSEnabled:%t InstallDate:%q "+
		"LastConnection:%q LastHeartbeat:%q ReregistrationSecret:%q "+
		"TamperProtection:%t UninstallKeyHash:%q WatchdogEnabled:%t TamperAlertEnabled:%t}",
		c.Server, c.UUID, c.MTLSEnabled, c.InstallDate,
		c.LastConnection, c.LastHeartbeat, redact(c.ReregistrationSecret),
		c.TamperProtection, redact(c.UninstallKeyHash), c.WatchdogEnabled, c.TamperAlertEnabled)
}

// GoString implements fmt.GoStringer (used by %#v) with the same redaction as
// String so debug dumps do not leak secrets.
func (c *Config) GoString() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return fmt.Sprintf("config.Config{Server:%q, UUID:%q, MTLSEnabled:%t, InstallDate:%q, "+
		"LastConnection:%q, LastHeartbeat:%q, ReregistrationSecret:%q, "+
		"TamperProtection:%t, UninstallKeyHash:%q, WatchdogEnabled:%t, TamperAlertEnabled:%t}",
		c.Server, c.UUID, c.MTLSEnabled, c.InstallDate,
		c.LastConnection, c.LastHeartbeat, redact(c.ReregistrationSecret),
		c.TamperProtection, redact(c.UninstallKeyHash), c.WatchdogEnabled, c.TamperAlertEnabled)
}

// SetUUID updates the agent UUID.
func (c *Config) SetUUID(uuid string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.UUID = uuid
}

// GetServer returns the server URL.
func (c *Config) GetServer() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Server
}

// GetUUID returns the agent UUID.
func (c *Config) GetUUID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.UUID
}

// IsMTLSEnabled returns whether mTLS is enabled.
func (c *Config) IsMTLSEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.MTLSEnabled
}

// GetInstallDate returns the installation date.
func (c *Config) GetInstallDate() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.InstallDate
}

// GetLastConnection returns the last connection time.
func (c *Config) GetLastConnection() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.LastConnection
}

// SetLastConnection updates the last connection time.
func (c *Config) SetLastConnection(t string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.LastConnection = t
}

// GetLastHeartbeat returns the last heartbeat time.
func (c *Config) GetLastHeartbeat() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.LastHeartbeat
}

// SetLastHeartbeat updates the last heartbeat time.
func (c *Config) SetLastHeartbeat(t string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.LastHeartbeat = t
}

// GetReregistrationSecret returns the re-registration secret.
func (c *Config) GetReregistrationSecret() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ReregistrationSecret
}

// SetReregistrationSecret updates the re-registration secret.
func (c *Config) SetReregistrationSecret(secret string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ReregistrationSecret = secret
}

// IsTamperProtectionEnabled returns whether tamper protection is enabled.
func (c *Config) IsTamperProtectionEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.TamperProtection
}

// SetTamperProtection enables or disables tamper protection.
func (c *Config) SetTamperProtection(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.TamperProtection = enabled
}

// GetUninstallKeyHash returns the hashed uninstall key.
func (c *Config) GetUninstallKeyHash() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.UninstallKeyHash
}

// SetUninstallKeyHash sets the hashed uninstall key.
func (c *Config) SetUninstallKeyHash(hash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.UninstallKeyHash = hash
}

// IsWatchdogEnabled returns whether the watchdog is enabled.
func (c *Config) IsWatchdogEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.WatchdogEnabled
}

// SetWatchdogEnabled enables or disables the watchdog.
func (c *Config) SetWatchdogEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.WatchdogEnabled = enabled
}

// IsTamperAlertEnabled returns whether tamper alerts are enabled.
func (c *Config) IsTamperAlertEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.TamperAlertEnabled
}

// SetTamperAlertEnabled enables or disables tamper alerts.
func (c *Config) SetTamperAlertEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.TamperAlertEnabled = enabled
}

// New creates a new configuration with the given server.
func New(server string, paths Paths) *Config {
	return &Config{
		Server:      server,
		MTLSEnabled: true,
		InstallDate: time.Now().UTC().Format(time.RFC3339),
		filePath:    paths.ConfigFile,
	}
}

// EnsureDirectories creates all necessary directories with proper permissions.
func EnsureDirectories(paths Paths) error {
	dirs := []struct {
		path string
		mode os.FileMode
	}{
		{paths.BaseDir, 0755},
		{paths.CertsDir, certsDirMode},
		{paths.LogDir, 0755},
	}

	for _, d := range dirs {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return fmt.Errorf("creating directory %s: %w", d.path, err)
		}
		// Ensure correct permissions even if directory exists
		if err := os.Chmod(d.path, d.mode); err != nil {
			return fmt.Errorf("setting permissions on %s: %w", d.path, err)
		}
	}

	return nil
}
