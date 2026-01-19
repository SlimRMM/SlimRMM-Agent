// Package validation provides pre-uninstall validation services.
//go:build !linux

package validation

import (
	"context"
	"log/slog"
)

// DEBValidator stub for non-Linux platforms.
type DEBValidator struct {
	logger *slog.Logger
}

// NewDEBValidator creates a new DEB validator stub.
func NewDEBValidator(logger *slog.Logger) *DEBValidator {
	return &DEBValidator{logger: logger}
}

// CanHandle returns false on non-Linux platforms.
func (v *DEBValidator) CanHandle(installationType string) bool {
	return false
}

// IsAvailable returns false on non-Linux platforms.
func (v *DEBValidator) IsAvailable() bool {
	return false
}

// Validate is not available on non-Linux platforms.
func (v *DEBValidator) Validate(ctx context.Context, req *ValidationRequest) (*ValidationResult, error) {
	return nil, nil
}

// RPMValidator stub for non-Linux platforms.
type RPMValidator struct {
	logger *slog.Logger
}

// NewRPMValidator creates a new RPM validator stub.
func NewRPMValidator(logger *slog.Logger) *RPMValidator {
	return &RPMValidator{logger: logger}
}

// CanHandle returns false on non-Linux platforms.
func (v *RPMValidator) CanHandle(installationType string) bool {
	return false
}

// IsAvailable returns false on non-Linux platforms.
func (v *RPMValidator) IsAvailable() bool {
	return false
}

// Validate is not available on non-Linux platforms.
func (v *RPMValidator) Validate(ctx context.Context, req *ValidationRequest) (*ValidationResult, error) {
	return nil, nil
}
