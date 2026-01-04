// Package tamper provides tamper protection mechanisms for the agent.
// It includes watchdog functionality, uninstall protection, and file integrity monitoring.
package tamper

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

var (
	// ErrInvalidUninstallKey is returned when the uninstall key doesn't match.
	ErrInvalidUninstallKey = errors.New("invalid uninstall key")

	// ErrTamperDetected is returned when tampering is detected.
	ErrTamperDetected = errors.New("tampering detected")

	// ErrProtectionActive is returned when trying to stop a protected service.
	ErrProtectionActive = errors.New("tamper protection is active")
)

// Config holds tamper protection configuration.
type Config struct {
	// Enabled controls whether tamper protection is active.
	Enabled bool `json:"enabled"`

	// UninstallKeyHash is the SHA-256 hash of the uninstall key.
	// This key is required to uninstall or stop the agent.
	UninstallKeyHash string `json:"uninstall_key_hash,omitempty"`

	// WatchdogEnabled controls whether the watchdog is active.
	WatchdogEnabled bool `json:"watchdog_enabled"`

	// AlertOnTamper controls whether to send alerts when tampering is detected.
	AlertOnTamper bool `json:"alert_on_tamper"`

	// ProtectedPaths lists paths that should be monitored for changes.
	ProtectedPaths []string `json:"protected_paths,omitempty"`
}

// DefaultConfig returns the default tamper protection configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:         true,
		WatchdogEnabled: true,
		AlertOnTamper:   true,
	}
}

// Protection provides tamper protection functionality.
type Protection struct {
	config     Config
	logger     *slog.Logger
	fileHashes map[string]string
	mu         sync.RWMutex

	// Callbacks
	onTamperDetected func(event TamperEvent)
	onServiceStop    func() bool // Returns true if stop is allowed

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// TamperEvent represents a detected tampering attempt.
type TamperEvent struct {
	Type      TamperType `json:"type"`
	Path      string     `json:"path,omitempty"`
	Details   string     `json:"details"`
	Timestamp time.Time  `json:"timestamp"`
}

// TamperType identifies the type of tampering detected.
type TamperType string

const (
	TamperTypeFileModified   TamperType = "file_modified"
	TamperTypeFileDeleted    TamperType = "file_deleted"
	TamperTypeServiceStopped TamperType = "service_stopped"
	TamperTypeUninstall      TamperType = "uninstall_attempt"
	TamperTypeConfigChanged  TamperType = "config_changed"
)

// New creates a new Protection instance.
func New(config Config, logger *slog.Logger) *Protection {
	if logger == nil {
		logger = slog.Default()
	}

	return &Protection{
		config:     config,
		logger:     logger,
		fileHashes: make(map[string]string),
		stopCh:     make(chan struct{}),
	}
}

// SetTamperCallback sets the callback for tamper detection events.
func (p *Protection) SetTamperCallback(cb func(TamperEvent)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onTamperDetected = cb
}

// SetServiceStopCallback sets the callback for service stop attempts.
// The callback should return true if the stop is allowed.
func (p *Protection) SetServiceStopCallback(cb func() bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onServiceStop = cb
}

// Start begins the tamper protection monitoring.
func (p *Protection) Start() error {
	if !p.config.Enabled {
		p.logger.Info("tamper protection is disabled")
		return nil
	}

	// Calculate initial hashes for protected files
	if err := p.initializeFileHashes(); err != nil {
		p.logger.Warn("failed to initialize file hashes", "error", err)
	}

	// Protect critical files
	if err := p.protectFiles(); err != nil {
		p.logger.Warn("failed to protect files", "error", err)
	}

	// Start file integrity monitoring
	p.wg.Add(1)
	go p.monitorFileIntegrity()

	p.logger.Info("tamper protection started")
	return nil
}

// Stop stops the tamper protection monitoring.
func (p *Protection) Stop() {
	close(p.stopCh)
	p.wg.Wait()
	p.logger.Info("tamper protection stopped")
}

// ValidateUninstallKey checks if the provided key matches the stored hash.
func (p *Protection) ValidateUninstallKey(key string) error {
	if p.config.UninstallKeyHash == "" {
		// No key configured, allow uninstall
		return nil
	}

	hash := sha256.Sum256([]byte(key))
	provided := hex.EncodeToString(hash[:])

	if subtle.ConstantTimeCompare([]byte(provided), []byte(p.config.UninstallKeyHash)) != 1 {
		p.reportTamper(TamperEvent{
			Type:      TamperTypeUninstall,
			Details:   "invalid uninstall key provided",
			Timestamp: time.Now(),
		})
		return ErrInvalidUninstallKey
	}

	return nil
}

// SetUninstallKey sets a new uninstall key.
func (p *Protection) SetUninstallKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	hashStr := hex.EncodeToString(hash[:])

	p.mu.Lock()
	p.config.UninstallKeyHash = hashStr
	p.mu.Unlock()

	return hashStr
}

// CanStopService checks if the service is allowed to stop.
func (p *Protection) CanStopService() bool {
	if !p.config.Enabled {
		return true
	}

	p.mu.RLock()
	cb := p.onServiceStop
	p.mu.RUnlock()

	if cb != nil {
		return cb()
	}

	// By default, don't allow stopping if protection is enabled
	return false
}

// initializeFileHashes calculates SHA-256 hashes for all protected files.
func (p *Protection) initializeFileHashes() error {
	paths := p.getProtectedPaths()

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, path := range paths {
		hash, err := p.hashFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				p.logger.Warn("failed to hash file", "path", path, "error", err)
			}
			continue
		}
		p.fileHashes[path] = hash
	}

	return nil
}

// getProtectedPaths returns the list of paths to protect.
func (p *Protection) getProtectedPaths() []string {
	if len(p.config.ProtectedPaths) > 0 {
		return p.config.ProtectedPaths
	}

	// Default protected paths based on OS
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"/Applications/SlimRMM.app/Contents/MacOS/slimrmm-agent",
			"/Applications/SlimRMM.app/Contents/Data/.slimrmm_config.json",
			"/Library/LaunchDaemons/io.slimrmm.agent.plist",
		}
	case "linux":
		return []string{
			"/usr/local/bin/slimrmm-agent",
			"/var/lib/slimrmm/.slimrmm_config.json",
			"/etc/systemd/system/slimrmm-agent.service",
		}
	case "windows":
		return []string{
			`C:\Program Files\SlimRMM\slimrmm-agent.exe`,
			`C:\ProgramData\SlimRMM\.slimrmm_config.json`,
		}
	default:
		return nil
	}
}

// hashFile calculates the SHA-256 hash of a file.
func (p *Protection) hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// monitorFileIntegrity periodically checks protected files for modifications.
func (p *Protection) monitorFileIntegrity() {
	defer p.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.checkFileIntegrity()
		}
	}
}

// checkFileIntegrity verifies that protected files haven't been modified.
func (p *Protection) checkFileIntegrity() {
	paths := p.getProtectedPaths()

	p.mu.RLock()
	originalHashes := make(map[string]string)
	for k, v := range p.fileHashes {
		originalHashes[k] = v
	}
	p.mu.RUnlock()

	for _, path := range paths {
		originalHash, exists := originalHashes[path]
		if !exists {
			continue
		}

		// Check if file still exists
		if _, err := os.Stat(path); os.IsNotExist(err) {
			p.reportTamper(TamperEvent{
				Type:      TamperTypeFileDeleted,
				Path:      path,
				Details:   "protected file was deleted",
				Timestamp: time.Now(),
			})
			continue
		}

		// Check if hash changed
		currentHash, err := p.hashFile(path)
		if err != nil {
			p.logger.Warn("failed to hash file during integrity check", "path", path, "error", err)
			continue
		}

		if currentHash != originalHash {
			p.reportTamper(TamperEvent{
				Type:      TamperTypeFileModified,
				Path:      path,
				Details:   fmt.Sprintf("file hash changed from %s to %s", originalHash[:16], currentHash[:16]),
				Timestamp: time.Now(),
			})
		}
	}
}

// reportTamper handles a detected tampering event.
func (p *Protection) reportTamper(event TamperEvent) {
	p.logger.Warn("tampering detected",
		"type", event.Type,
		"path", event.Path,
		"details", event.Details,
	)

	if !p.config.AlertOnTamper {
		return
	}

	p.mu.RLock()
	cb := p.onTamperDetected
	p.mu.RUnlock()

	if cb != nil {
		cb(event)
	}
}

// protectFiles applies OS-specific file protection to critical files.
func (p *Protection) protectFiles() error {
	paths := p.getProtectedPaths()

	for _, path := range paths {
		if err := p.protectFile(path); err != nil {
			p.logger.Debug("failed to protect file", "path", path, "error", err)
		}
	}

	return nil
}

// protectFile applies OS-specific protection to a single file.
// Implementation is in platform-specific files.
func (p *Protection) protectFile(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	return p.protectFilePlatform(path)
}

// unprotectFile removes OS-specific protection from a file.
// Implementation is in platform-specific files.
func (p *Protection) unprotectFile(path string) error {
	return p.unprotectFilePlatform(path)
}

// PrepareForUpdate temporarily removes protection for updates.
func (p *Protection) PrepareForUpdate() error {
	if !p.config.Enabled {
		return nil
	}

	p.logger.Info("temporarily disabling tamper protection for update")

	paths := p.getProtectedPaths()
	for _, path := range paths {
		if err := p.unprotectFile(path); err != nil {
			p.logger.Debug("failed to unprotect file", "path", path, "error", err)
		}
	}

	return nil
}

// RestoreAfterUpdate re-enables protection after updates.
func (p *Protection) RestoreAfterUpdate() error {
	if !p.config.Enabled {
		return nil
	}

	p.logger.Info("restoring tamper protection after update")

	// Recalculate hashes for updated files
	if err := p.initializeFileHashes(); err != nil {
		p.logger.Warn("failed to reinitialize file hashes", "error", err)
	}

	// Reapply protection
	return p.protectFiles()
}

// GetBinaryPath returns the path to the agent binary.
func GetBinaryPath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Applications/SlimRMM.app/Contents/MacOS/slimrmm-agent"
	case "linux":
		return "/usr/local/bin/slimrmm-agent"
	case "windows":
		return filepath.Join(os.Getenv("ProgramFiles"), "SlimRMM", "slimrmm-agent.exe")
	default:
		exe, _ := os.Executable()
		return exe
	}
}

// GetConfigPath returns the path to the agent config file.
func GetConfigPath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Applications/SlimRMM.app/Contents/Data/.slimrmm_config.json"
	case "linux":
		return "/var/lib/slimrmm/.slimrmm_config.json"
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "SlimRMM", ".slimrmm_config.json")
	default:
		return ".slimrmm_config.json"
	}
}
