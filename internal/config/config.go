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
	Server                 string `json:"server"`
	UUID                   string `json:"uuid"`
	MTLSEnabled            bool   `json:"mtls_enabled"`
	InstallDate            string `json:"install_date,omitempty"`
	LastConnection         string `json:"last_connection,omitempty"`
	LastHeartbeat          string `json:"last_heartbeat,omitempty"`
	ReregistrationSecret   string `json:"reregistration_secret,omitempty"`

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
		logDir = "/var/log/slimrmm"
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

	return nil
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
