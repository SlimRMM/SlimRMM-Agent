// Package security provides centralized security configuration and utilities.
package security

import (
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/security/antireplay"
	"github.com/slimrmm/slimrmm-agent/internal/security/audit"
	"github.com/slimrmm/slimrmm-agent/internal/security/ratelimit"
	"github.com/slimrmm/slimrmm-agent/internal/security/terminal"
)

// Config holds all security configuration options.
type Config struct {
	// RateLimit configuration
	RateLimit ratelimit.Config

	// AntiReplay configuration
	AntiReplay antireplay.Config

	// Audit logging configuration
	Audit audit.Config

	// Terminal security configuration
	Terminal terminal.Config

	// TLS configuration
	TLS TLSConfig

	// Authentication configuration
	Auth AuthConfig
}

// TLSConfig holds TLS security settings.
type TLSConfig struct {
	// MinVersion is the minimum TLS version (default: TLS 1.3)
	MinVersion uint16

	// RequireClientCert enables mTLS client certificate verification
	RequireClientCert bool

	// InsecureSkipVerify is intentionally NOT configurable (always false)
	// Certificate verification must always be enabled
}

// AuthConfig holds authentication settings.
type AuthConfig struct {
	// CertRenewalInterval is how often to check for certificate renewal
	CertRenewalInterval time.Duration

	// MaxFailedAttempts before lockout
	MaxFailedAttempts int

	// LockoutDuration after max failed attempts
	LockoutDuration time.Duration
}

// DefaultConfig returns secure default configuration.
// These defaults prioritize security over convenience.
func DefaultConfig() Config {
	return Config{
		RateLimit:  ratelimit.DefaultConfig(),
		AntiReplay: antireplay.DefaultConfig(),
		Audit:      audit.DefaultConfig(),
		Terminal:   terminal.DefaultConfig(),
		TLS: TLSConfig{
			MinVersion:        0x0304, // TLS 1.3
			RequireClientCert: true,
		},
		Auth: AuthConfig{
			CertRenewalInterval: 24 * time.Hour,
			MaxFailedAttempts:   5,
			LockoutDuration:     15 * time.Minute,
		},
	}
}

// Hardened returns a hardened security configuration.
// Use this for high-security deployments.
func Hardened() Config {
	cfg := DefaultConfig()

	// Stricter rate limits
	cfg.RateLimit.GlobalRate = 50
	cfg.RateLimit.GlobalBurst = 100
	cfg.RateLimit.CommandRate = 2
	cfg.RateLimit.CommandBurst = 5

	// Shorter anti-replay window
	cfg.AntiReplay.MaxAge = 2 * time.Minute
	cfg.AntiReplay.FutureWindow = 10 * time.Second

	// Fewer terminal sessions
	cfg.Terminal.MaxSessions = 2
	cfg.Terminal.SessionTimeout = 15 * time.Minute

	// More aggressive auth lockout
	cfg.Auth.MaxFailedAttempts = 3
	cfg.Auth.LockoutDuration = 30 * time.Minute

	return cfg
}

// SecurityLevel represents the security level of the configuration.
type SecurityLevel int

const (
	// SecurityLevelStandard is the default security level.
	SecurityLevelStandard SecurityLevel = iota

	// SecurityLevelHardened is for high-security deployments.
	SecurityLevelHardened

	// SecurityLevelMaximum is the most restrictive level.
	SecurityLevelMaximum
)

// ForLevel returns configuration for the specified security level.
func ForLevel(level SecurityLevel) Config {
	switch level {
	case SecurityLevelHardened:
		return Hardened()
	case SecurityLevelMaximum:
		return maximum()
	default:
		return DefaultConfig()
	}
}

// maximum returns maximum security configuration.
func maximum() Config {
	cfg := Hardened()

	// Even stricter settings
	cfg.RateLimit.GlobalRate = 20
	cfg.RateLimit.GlobalBurst = 40
	cfg.RateLimit.CommandRate = 1
	cfg.RateLimit.CommandBurst = 2

	cfg.AntiReplay.MaxAge = time.Minute

	cfg.Terminal.MaxSessions = 1
	cfg.Terminal.SessionTimeout = 5 * time.Minute

	cfg.Auth.MaxFailedAttempts = 2
	cfg.Auth.LockoutDuration = time.Hour

	return cfg
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.RateLimit.GlobalRate <= 0 {
		return ErrInvalidConfig("rate limit global rate must be positive")
	}
	if c.AntiReplay.MaxAge <= 0 {
		return ErrInvalidConfig("anti-replay max age must be positive")
	}
	if c.Terminal.MaxSessions <= 0 {
		return ErrInvalidConfig("terminal max sessions must be positive")
	}
	if c.Auth.MaxFailedAttempts <= 0 {
		return ErrInvalidConfig("auth max failed attempts must be positive")
	}
	return nil
}

// ErrInvalidConfig is returned when configuration is invalid.
type ErrInvalidConfig string

func (e ErrInvalidConfig) Error() string {
	return "invalid security config: " + string(e)
}
