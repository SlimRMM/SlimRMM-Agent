// Package backup provides backup collection services for the RMM agent.
package backup

import (
	"context"

	"github.com/slimrmm/slimrmm-agent/internal/osquery"
)

// OsqueryWrapper wraps the osquery.Client to implement the OsqueryClient interface.
type OsqueryWrapper struct {
	client *osquery.Client
}

// NewOsqueryWrapper creates a new OsqueryWrapper.
func NewOsqueryWrapper() *OsqueryWrapper {
	return &OsqueryWrapper{
		client: osquery.New(),
	}
}

// IsAvailable checks if osquery is available.
func (w *OsqueryWrapper) IsAvailable() bool {
	return w.client.IsAvailable()
}

// GetSystemInfo returns system information via osquery.
func (w *OsqueryWrapper) GetSystemInfo(ctx context.Context) (*OsqueryResult, error) {
	result, err := w.client.Query(ctx, "SELECT * FROM system_info")
	if err != nil {
		return nil, err
	}
	return &OsqueryResult{Rows: result.Rows}, nil
}

// Query executes an osquery query and returns the results.
func (w *OsqueryWrapper) Query(ctx context.Context, query string) (*OsqueryResult, error) {
	result, err := w.client.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	return &OsqueryResult{Rows: result.Rows}, nil
}
