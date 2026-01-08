//go:build !windows
// +build !windows

package actions

import "errors"

// RegistryResult contains the result of a registry query.
type RegistryResult struct {
	Path  string      `json:"path"`
	Name  string      `json:"name"`
	Value interface{} `json:"value"`
	Type  string      `json:"type"`
	Error string      `json:"error,omitempty"`
}

// ReadRegistryValue is a stub for non-Windows platforms.
func ReadRegistryValue(path string) (*RegistryResult, error) {
	return nil, errors.New("registry operations are only supported on Windows")
}

// RegistryKeyExists is a stub for non-Windows platforms.
func RegistryKeyExists(path string) bool {
	return false
}
