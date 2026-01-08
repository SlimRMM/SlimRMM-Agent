//go:build windows
// +build windows

package actions

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// RegistryResult contains the result of a registry query.
type RegistryResult struct {
	Path  string      `json:"path"`
	Name  string      `json:"name"`
	Value interface{} `json:"value"`
	Type  string      `json:"type"`
	Error string      `json:"error,omitempty"`
}

// ReadRegistryValue reads a value from the Windows registry.
// The path should be in the format: HKLM\Path\To\Key\ValueName
// or HKCU\Path\To\Key\ValueName
func ReadRegistryValue(path string) (*RegistryResult, error) {
	result := &RegistryResult{
		Path: path,
	}

	// Parse the registry path
	rootKey, subPath, valueName, err := parseRegistryPath(path)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	result.Name = valueName

	// Open the registry key
	key, err := registry.OpenKey(rootKey, subPath, registry.QUERY_VALUE)
	if err != nil {
		result.Error = fmt.Sprintf("failed to open registry key: %v", err)
		return result, err
	}
	defer key.Close()

	// Read the value - try different types
	// First try DWORD (most common for policy settings)
	if intVal, _, err := key.GetIntegerValue(valueName); err == nil {
		result.Value = intVal
		result.Type = "DWORD"
		return result, nil
	}

	// Try string value
	if strVal, _, err := key.GetStringValue(valueName); err == nil {
		result.Value = strVal
		result.Type = "SZ"
		return result, nil
	}

	// Try multi-string value
	if multiVal, _, err := key.GetStringsValue(valueName); err == nil {
		result.Value = multiVal
		result.Type = "MULTI_SZ"
		return result, nil
	}

	// Try binary value
	if binVal, _, err := key.GetBinaryValue(valueName); err == nil {
		result.Value = binVal
		result.Type = "BINARY"
		return result, nil
	}

	result.Error = "value not found or unsupported type"
	return result, fmt.Errorf("registry value not found: %s", path)
}

// parseRegistryPath parses a registry path into root key, subpath, and value name.
// Input format: HKLM\Path\To\Key\ValueName
func parseRegistryPath(path string) (registry.Key, string, string, error) {
	// Replace forward slashes with backslashes for consistency
	path = strings.ReplaceAll(path, "/", "\\")

	// Split the path
	parts := strings.SplitN(path, "\\", 2)
	if len(parts) < 2 {
		return 0, "", "", fmt.Errorf("invalid registry path: %s", path)
	}

	rootKeyStr := strings.ToUpper(parts[0])
	remainder := parts[1]

	// Map root key string to registry.Key
	var rootKey registry.Key
	switch rootKeyStr {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		rootKey = registry.LOCAL_MACHINE
	case "HKCU", "HKEY_CURRENT_USER":
		rootKey = registry.CURRENT_USER
	case "HKCR", "HKEY_CLASSES_ROOT":
		rootKey = registry.CLASSES_ROOT
	case "HKU", "HKEY_USERS":
		rootKey = registry.USERS
	case "HKCC", "HKEY_CURRENT_CONFIG":
		rootKey = registry.CURRENT_CONFIG
	default:
		return 0, "", "", fmt.Errorf("unknown registry root key: %s", rootKeyStr)
	}

	// Split the remainder into subpath and value name
	// The value name is the last component
	lastBackslash := strings.LastIndex(remainder, "\\")
	if lastBackslash == -1 {
		// Only one component - treat as value name with empty subpath
		return rootKey, "", remainder, nil
	}

	subPath := remainder[:lastBackslash]
	valueName := remainder[lastBackslash+1:]

	return rootKey, subPath, valueName, nil
}

// RegistryKeyExists checks if a registry key exists.
func RegistryKeyExists(path string) bool {
	// Parse the registry path - we only need root and subpath
	rootKey, subPath, _, err := parseRegistryPath(path + "\\dummy")
	if err != nil {
		return false
	}

	key, err := registry.OpenKey(rootKey, subPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	key.Close()
	return true
}
