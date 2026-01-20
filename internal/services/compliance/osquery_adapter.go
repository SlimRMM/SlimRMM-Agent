// Package compliance provides compliance check services.
package compliance

import (
	"context"
	"fmt"

	"github.com/slimrmm/slimrmm-agent/internal/osquery"
)

// OsqueryAdapter wraps the osquery.Client to implement QueryExecutor interface.
type OsqueryAdapter struct {
	client *osquery.Client
}

// NewOsqueryAdapter creates a new OsqueryAdapter.
func NewOsqueryAdapter() *OsqueryAdapter {
	return &OsqueryAdapter{
		client: osquery.New(),
	}
}

// NewOsqueryAdapterWithClient creates a new OsqueryAdapter with a specific client.
func NewOsqueryAdapterWithClient(client *osquery.Client) *OsqueryAdapter {
	return &OsqueryAdapter{
		client: client,
	}
}

// IsAvailable checks if osquery is available.
func (a *OsqueryAdapter) IsAvailable() bool {
	return a.client.IsAvailable()
}

// ExecuteQuery executes an osquery query and returns the results.
// Converts []map[string]string to []map[string]interface{} for the compliance service.
func (a *OsqueryAdapter) ExecuteQuery(ctx context.Context, query string) ([]map[string]interface{}, error) {
	if !a.client.IsAvailable() {
		return nil, fmt.Errorf("osquery not available")
	}

	result, err := a.client.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query execution failed: %w", err)
	}

	if result.Error != "" {
		return nil, fmt.Errorf("query error: %s", result.Error)
	}

	// Convert []map[string]string to []map[string]interface{}
	rows := make([]map[string]interface{}, 0, len(result.Rows))
	for _, row := range result.Rows {
		converted := make(map[string]interface{}, len(row))
		for k, v := range row {
			converted[k] = v
		}
		rows = append(rows, converted)
	}

	return rows, nil
}
