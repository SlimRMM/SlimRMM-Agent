package security

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Test TLS defaults
	if cfg.TLS.MinVersion != 0x0304 {
		t.Errorf("TLS.MinVersion = 0x%04x, want 0x0304 (TLS 1.3)", cfg.TLS.MinVersion)
	}
	if !cfg.TLS.RequireClientCert {
		t.Error("TLS.RequireClientCert should be true")
	}

	// Test Auth defaults
	if cfg.Auth.CertRenewalInterval != 24*time.Hour {
		t.Errorf("Auth.CertRenewalInterval = %v, want 24h", cfg.Auth.CertRenewalInterval)
	}
	if cfg.Auth.MaxFailedAttempts != 5 {
		t.Errorf("Auth.MaxFailedAttempts = %d, want 5", cfg.Auth.MaxFailedAttempts)
	}
	if cfg.Auth.LockoutDuration != 15*time.Minute {
		t.Errorf("Auth.LockoutDuration = %v, want 15m", cfg.Auth.LockoutDuration)
	}
}

func TestHardened(t *testing.T) {
	cfg := Hardened()

	// Test stricter rate limits
	if cfg.RateLimit.GlobalRate != 50 {
		t.Errorf("GlobalRate = %.0f, want 50", cfg.RateLimit.GlobalRate)
	}
	if cfg.RateLimit.GlobalBurst != 100 {
		t.Errorf("GlobalBurst = %d, want 100", cfg.RateLimit.GlobalBurst)
	}
	if cfg.RateLimit.CommandRate != 2 {
		t.Errorf("CommandRate = %.0f, want 2", cfg.RateLimit.CommandRate)
	}

	// Test shorter anti-replay window
	if cfg.AntiReplay.MaxAge != 2*time.Minute {
		t.Errorf("AntiReplay.MaxAge = %v, want 2m", cfg.AntiReplay.MaxAge)
	}

	// Test fewer terminal sessions
	if cfg.Terminal.MaxSessions != 2 {
		t.Errorf("Terminal.MaxSessions = %d, want 2", cfg.Terminal.MaxSessions)
	}

	// Test more aggressive auth lockout
	if cfg.Auth.MaxFailedAttempts != 3 {
		t.Errorf("Auth.MaxFailedAttempts = %d, want 3", cfg.Auth.MaxFailedAttempts)
	}
	if cfg.Auth.LockoutDuration != 30*time.Minute {
		t.Errorf("Auth.LockoutDuration = %v, want 30m", cfg.Auth.LockoutDuration)
	}
}

func TestForLevel(t *testing.T) {
	tests := []struct {
		level   SecurityLevel
		name    string
		wantMax int // Check MaxFailedAttempts as indicator
	}{
		{SecurityLevelStandard, "standard", 5},
		{SecurityLevelHardened, "hardened", 3},
		{SecurityLevelMaximum, "maximum", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ForLevel(tt.level)
			if cfg.Auth.MaxFailedAttempts != tt.wantMax {
				t.Errorf("ForLevel(%v) MaxFailedAttempts = %d, want %d",
					tt.level, cfg.Auth.MaxFailedAttempts, tt.wantMax)
			}
		})
	}
}

func TestMaximum(t *testing.T) {
	cfg := maximum()

	// Test most restrictive settings
	if cfg.RateLimit.GlobalRate != 20 {
		t.Errorf("GlobalRate = %.0f, want 20", cfg.RateLimit.GlobalRate)
	}
	if cfg.RateLimit.CommandRate != 1 {
		t.Errorf("CommandRate = %.0f, want 1", cfg.RateLimit.CommandRate)
	}
	if cfg.AntiReplay.MaxAge != time.Minute {
		t.Errorf("AntiReplay.MaxAge = %v, want 1m", cfg.AntiReplay.MaxAge)
	}
	if cfg.Terminal.MaxSessions != 1 {
		t.Errorf("Terminal.MaxSessions = %d, want 1", cfg.Terminal.MaxSessions)
	}
	if cfg.Auth.MaxFailedAttempts != 2 {
		t.Errorf("Auth.MaxFailedAttempts = %d, want 2", cfg.Auth.MaxFailedAttempts)
	}
	if cfg.Auth.LockoutDuration != time.Hour {
		t.Errorf("Auth.LockoutDuration = %v, want 1h", cfg.Auth.LockoutDuration)
	}
}

func TestConfigValidate(t *testing.T) {
	// Valid config
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid config should not error: %v", err)
	}

	// Invalid rate limit
	cfg = DefaultConfig()
	cfg.RateLimit.GlobalRate = 0
	if err := cfg.Validate(); err == nil {
		t.Error("config with zero GlobalRate should error")
	}

	// Invalid anti-replay
	cfg = DefaultConfig()
	cfg.AntiReplay.MaxAge = 0
	if err := cfg.Validate(); err == nil {
		t.Error("config with zero MaxAge should error")
	}

	// Invalid terminal sessions
	cfg = DefaultConfig()
	cfg.Terminal.MaxSessions = 0
	if err := cfg.Validate(); err == nil {
		t.Error("config with zero MaxSessions should error")
	}

	// Invalid auth attempts
	cfg = DefaultConfig()
	cfg.Auth.MaxFailedAttempts = 0
	if err := cfg.Validate(); err == nil {
		t.Error("config with zero MaxFailedAttempts should error")
	}
}

func TestErrInvalidConfig(t *testing.T) {
	err := ErrInvalidConfig("test error message")

	if err.Error() == "" {
		t.Error("error should have a message")
	}

	expected := "invalid security config: test error message"
	if err.Error() != expected {
		t.Errorf("error = %q, want %q", err.Error(), expected)
	}
}

func TestSecurityLevelConstants(t *testing.T) {
	levels := []SecurityLevel{
		SecurityLevelStandard,
		SecurityLevelHardened,
		SecurityLevelMaximum,
	}

	// Verify each level has a different value
	seen := make(map[SecurityLevel]bool)
	for _, level := range levels {
		if seen[level] {
			t.Errorf("duplicate security level: %d", level)
		}
		seen[level] = true
	}
}

func TestConfigStruct(t *testing.T) {
	cfg := Config{
		TLS: TLSConfig{
			MinVersion:        0x0304,
			RequireClientCert: true,
		},
		Auth: AuthConfig{
			CertRenewalInterval: time.Hour,
			MaxFailedAttempts:   5,
			LockoutDuration:     time.Minute,
		},
	}

	if cfg.TLS.MinVersion != 0x0304 {
		t.Error("TLS.MinVersion not set correctly")
	}
	if !cfg.TLS.RequireClientCert {
		t.Error("TLS.RequireClientCert not set correctly")
	}
	if cfg.Auth.CertRenewalInterval != time.Hour {
		t.Error("Auth.CertRenewalInterval not set correctly")
	}
}

func TestTLSConfig(t *testing.T) {
	tlsCfg := TLSConfig{
		MinVersion:        0x0304,
		RequireClientCert: true,
	}

	if tlsCfg.MinVersion != 0x0304 {
		t.Errorf("MinVersion = 0x%04x, want 0x0304", tlsCfg.MinVersion)
	}
}

func TestAuthConfig(t *testing.T) {
	authCfg := AuthConfig{
		CertRenewalInterval: 12 * time.Hour,
		MaxFailedAttempts:   3,
		LockoutDuration:     30 * time.Minute,
	}

	if authCfg.CertRenewalInterval != 12*time.Hour {
		t.Error("CertRenewalInterval not set correctly")
	}
	if authCfg.MaxFailedAttempts != 3 {
		t.Error("MaxFailedAttempts not set correctly")
	}
	if authCfg.LockoutDuration != 30*time.Minute {
		t.Error("LockoutDuration not set correctly")
	}
}
