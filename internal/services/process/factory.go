// Package process provides process management services.
package process

import "log/slog"

// NewServices creates a new process service.
func NewServices(logger *slog.Logger) *DefaultProcessService {
	return NewProcessService(logger)
}
