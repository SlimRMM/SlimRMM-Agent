// Package remotedesktop provides RustDesk remote desktop installation,
// configuration, and management for the RMM agent.
package remotedesktop

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Config holds the RustDesk server configuration.
type Config struct {
	RelayServer string `json:"relay_server"`
	IDServer    string `json:"id_server"`
	PublicKey   string `json:"public_key"`
	Password    string `json:"password,omitempty"`
}

// Status represents the current state of the RustDesk installation.
type Status struct {
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
	ID        string `json:"id,omitempty"`
	Running   bool   `json:"running"`
}

// Service manages the RustDesk remote desktop client.
type Service struct {
	logger *slog.Logger
}

// New creates a new remote desktop service.
func New(logger *slog.Logger) *Service {
	return &Service{logger: logger}
}

// GetStatus returns the current status of the RustDesk installation.
func (s *Service) GetStatus(ctx context.Context) (*Status, error) {
	status := &Status{}

	version, err := s.GetVersion()
	if err != nil {
		s.logger.Debug("rustdesk not installed or version unavailable", "error", err)
		return status, nil
	}

	status.Installed = true
	status.Version = version
	status.Running = s.IsRunning()

	id, err := s.GetID()
	if err != nil {
		s.logger.Warn("failed to retrieve rustdesk id", "error", err)
	} else {
		status.ID = id
	}

	return status, nil
}

// RequestConsent prompts the local user for permission before a remote
// desktop connection is established. It returns true if the user granted
// access, false otherwise.
func (s *Service) RequestConsent(ctx context.Context, requesterName string, timeout time.Duration) (bool, error) {
	if requesterName == "" {
		return false, fmt.Errorf("requester name must not be empty")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	return s.requestConsentPlatform(ctx, requesterName, timeout)
}
