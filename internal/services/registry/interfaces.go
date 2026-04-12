// Package registry provides Windows registry operations as a service layer.
package registry

import "context"

// ListKeyResult contains subkeys and values for a registry key.
type ListKeyResult struct {
	Path    string       `json:"path"`
	Subkeys []string     `json:"subkeys"`
	Values  []ValueEntry `json:"values"`
}

// ValueEntry represents a single registry value.
type ValueEntry struct {
	Name string      `json:"name"`
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// SearchResult contains search matches.
type SearchResult struct {
	Results   []SearchEntry `json:"results"`
	Truncated bool          `json:"truncated"`
}

// SearchEntry represents a single search match.
type SearchEntry struct {
	Type string `json:"type"` // "key" or "value"
	Path string `json:"path"`
	Name string `json:"name,omitempty"`
}

// Service defines the interface for Windows registry operations.
type Service interface {
	// ExportKey exports a registry key to a file.
	ExportKey(ctx context.Context, keyPath, outputPath string) error

	// IsAvailable returns true if registry operations are available on this platform.
	IsAvailable() bool

	// ListKey lists sub-keys and values under the given registry path.
	ListKey(ctx context.Context, hive, path string) (*ListKeyResult, error)

	// CreateKey creates a new registry key.
	CreateKey(ctx context.Context, hive, path string) error

	// DeleteKey deletes a registry key and all its sub-keys.
	DeleteKey(ctx context.Context, hive, path string) error

	// RenameKey renames a registry key.
	RenameKey(ctx context.Context, hive, path, newName string) error

	// SetValue creates or updates a registry value.
	SetValue(ctx context.Context, hive, path, name, valueType string, data interface{}) error

	// DeleteValue deletes a registry value.
	DeleteValue(ctx context.Context, hive, path, name string) error

	// RenameValue renames a registry value.
	RenameValue(ctx context.Context, hive, path, oldName, newName string) error

	// SearchKey searches for keys and values matching a query.
	SearchKey(ctx context.Context, hive, path, query string, maxResults int) (*SearchResult, error)
}
