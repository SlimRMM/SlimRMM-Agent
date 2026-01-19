// Package validation provides pre-uninstall validation services.
package validation

import (
	"context"
	"fmt"
	"log/slog"
)

// DefaultValidationService implements ValidationService using platform-specific validators.
type DefaultValidationService struct {
	logger     *slog.Logger
	validators []PlatformValidator
}

// NewValidationService creates a new validation service with the provided validators.
func NewValidationService(logger *slog.Logger, validators ...PlatformValidator) *DefaultValidationService {
	return &DefaultValidationService{
		logger:     logger,
		validators: validators,
	}
}

// Validate validates if a package can be uninstalled.
func (s *DefaultValidationService) Validate(ctx context.Context, req *ValidationRequest) (*ValidationResult, error) {
	s.logger.Info("validating uninstall",
		"installation_type", req.InstallationType,
		"package_identifier", req.PackageIdentifier,
	)

	// Find a validator that can handle this installation type
	for _, validator := range s.validators {
		if validator.CanHandle(req.InstallationType) && validator.IsAvailable() {
			result, err := validator.Validate(ctx, req)
			if err != nil {
				s.logger.Error("validation failed",
					"installation_type", req.InstallationType,
					"error", err,
				)
				return nil, err
			}

			s.logger.Info("validation completed",
				"installation_type", req.InstallationType,
				"is_installed", result.IsInstalled,
				"running_processes", len(result.RunningProcesses),
			)

			return result, nil
		}
	}

	return nil, fmt.Errorf("no validator available for installation type: %s", req.InstallationType)
}
