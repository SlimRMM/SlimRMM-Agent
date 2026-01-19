// Package validation provides pre-uninstall validation services.
package validation

import (
	"log/slog"
)

// NewServices creates all validation services with proper dependencies.
func NewServices(logger *slog.Logger) *DefaultValidationService {
	validators := []PlatformValidator{
		NewWingetValidator(logger),
		NewMSIValidator(logger),
		NewPKGValidator(logger),
		NewCaskValidator(logger),
		NewDEBValidator(logger),
		NewRPMValidator(logger),
	}

	return NewValidationService(logger, validators...)
}
