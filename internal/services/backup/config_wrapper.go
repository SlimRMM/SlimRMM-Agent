// Package backup provides backup collection services for the RMM agent.
package backup

import (
	"github.com/slimrmm/slimrmm-agent/internal/config"
)

// ConfigWrapper wraps the config.Config to implement the AgentConfig interface.
type ConfigWrapper struct {
	cfg *config.Config
}

// NewConfigWrapper creates a new ConfigWrapper.
func NewConfigWrapper(cfg *config.Config) *ConfigWrapper {
	return &ConfigWrapper{cfg: cfg}
}

// GetUUID returns the agent UUID.
func (w *ConfigWrapper) GetUUID() string {
	return w.cfg.GetUUID()
}

// IsMTLSEnabled returns whether mTLS is enabled.
func (w *ConfigWrapper) IsMTLSEnabled() bool {
	return w.cfg.IsMTLSEnabled()
}
