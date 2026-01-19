// Package validation provides pre-uninstall validation services.
//go:build !darwin

package validation

import (
	"context"
	"log/slog"
)

// PKGValidator stub for non-macOS platforms.
type PKGValidator struct {
	logger *slog.Logger
}

// NewPKGValidator creates a new PKG validator stub.
func NewPKGValidator(logger *slog.Logger) *PKGValidator {
	return &PKGValidator{logger: logger}
}

// CanHandle returns false on non-macOS platforms.
func (v *PKGValidator) CanHandle(installationType string) bool {
	return false
}

// IsAvailable returns false on non-macOS platforms.
func (v *PKGValidator) IsAvailable() bool {
	return false
}

// Validate is not available on non-macOS platforms.
func (v *PKGValidator) Validate(ctx context.Context, req *ValidationRequest) (*ValidationResult, error) {
	return nil, nil
}

// CaskValidator stub for non-macOS platforms.
type CaskValidator struct {
	logger *slog.Logger
}

// NewCaskValidator creates a new Cask validator stub.
func NewCaskValidator(logger *slog.Logger) *CaskValidator {
	return &CaskValidator{logger: logger}
}

// CanHandle returns false on non-macOS platforms.
func (v *CaskValidator) CanHandle(installationType string) bool {
	return false
}

// IsAvailable returns false on non-macOS platforms.
func (v *CaskValidator) IsAvailable() bool {
	return false
}

// Validate is not available on non-macOS platforms.
func (v *CaskValidator) Validate(ctx context.Context, req *ValidationRequest) (*ValidationResult, error) {
	return nil, nil
}
