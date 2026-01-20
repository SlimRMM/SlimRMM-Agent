// Package compliance provides compliance check services.
package compliance

import (
	"log/slog"
)

// NewServices creates a compliance service with all dependencies configured.
// Uses the default osquery adapter for query execution.
func NewServices(logger *slog.Logger) *DefaultComplianceService {
	// Create osquery adapter
	osqueryAdapter := NewOsqueryAdapter()

	opts := []ServiceOption{
		WithQueryExecutor(osqueryAdapter),
	}

	return NewComplianceService(logger, opts...)
}

// NewServicesWithExecutor creates a compliance service with a custom query executor.
// Useful for testing or when using a different query backend.
func NewServicesWithExecutor(logger *slog.Logger, queryExecutor QueryExecutor) *DefaultComplianceService {
	opts := []ServiceOption{}

	if queryExecutor != nil {
		opts = append(opts, WithQueryExecutor(queryExecutor))
	}

	return NewComplianceService(logger, opts...)
}
