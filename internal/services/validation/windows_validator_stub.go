// Package validation provides pre-uninstall validation services.
//go:build !windows

package validation

import (
	"context"
	"log/slog"
)

// WingetValidator stub for non-Windows platforms.
type WingetValidator struct {
	logger *slog.Logger
}

// NewWingetValidator creates a new Winget validator stub.
func NewWingetValidator(logger *slog.Logger) *WingetValidator {
	return &WingetValidator{logger: logger}
}

// CanHandle returns false on non-Windows platforms.
func (v *WingetValidator) CanHandle(installationType string) bool {
	return false
}

// IsAvailable returns false on non-Windows platforms.
func (v *WingetValidator) IsAvailable() bool {
	return false
}

// Validate is not available on non-Windows platforms.
func (v *WingetValidator) Validate(ctx context.Context, req *ValidationRequest) (*ValidationResult, error) {
	return nil, nil
}

// MSIValidator stub for non-Windows platforms.
type MSIValidator struct {
	logger *slog.Logger
}

// NewMSIValidator creates a new MSI validator stub.
func NewMSIValidator(logger *slog.Logger) *MSIValidator {
	return &MSIValidator{logger: logger}
}

// CanHandle returns false on non-Windows platforms.
func (v *MSIValidator) CanHandle(installationType string) bool {
	return false
}

// IsAvailable returns false on non-Windows platforms.
func (v *MSIValidator) IsAvailable() bool {
	return false
}

// Validate is not available on non-Windows platforms.
func (v *MSIValidator) Validate(ctx context.Context, req *ValidationRequest) (*ValidationResult, error) {
	return nil, nil
}

// parseHumanSize stub for non-Windows platforms.
func parseHumanSize(sizeStr string) int64 {
	return 0
}
