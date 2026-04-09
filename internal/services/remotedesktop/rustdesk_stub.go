//go:build !linux && !darwin && !windows

package remotedesktop

import (
	"context"
	"fmt"
	"runtime"
	"time"
)

var errUnsupported = fmt.Errorf("remote desktop is not supported on %s", runtime.GOOS)

// Install is not supported on this platform.
func (s *Service) Install(ctx context.Context, cfg Config) error {
	return errUnsupported
}

// Configure is not supported on this platform.
func (s *Service) Configure(cfg Config) error {
	return errUnsupported
}

// GetID is not supported on this platform.
func (s *Service) GetID() (string, error) {
	return "", errUnsupported
}

// GetVersion is not supported on this platform.
func (s *Service) GetVersion() (string, error) {
	return "", errUnsupported
}

// IsRunning always returns false on unsupported platforms.
func (s *Service) IsRunning() bool {
	return false
}

// SetPassword is not supported on this platform.
func (s *Service) SetPassword(password string) error {
	return errUnsupported
}

// Uninstall is not supported on this platform.
func (s *Service) Uninstall(ctx context.Context) error {
	return errUnsupported
}

// requestConsentPlatform is not supported on this platform.
func (s *Service) requestConsentPlatform(ctx context.Context, requesterName string, timeout time.Duration) (bool, error) {
	return false, errUnsupported
}
