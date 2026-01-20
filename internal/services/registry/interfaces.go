// Package registry provides Windows registry operations as a service layer.
package registry

import "context"

// Service defines the interface for Windows registry operations.
type Service interface {
	// ExportKey exports a registry key to a file.
	ExportKey(ctx context.Context, keyPath, outputPath string) error

	// IsAvailable returns true if registry operations are available on this platform.
	IsAvailable() bool
}
