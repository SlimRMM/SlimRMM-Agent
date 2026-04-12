//go:build windows
// +build windows

package registry

import (
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"golang.org/x/sys/windows/registry"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32        = windows.NewLazySystemDLL("advapi32.dll")
	procRegSetValueExW = modadvapi32.NewProc("RegSetValueExW")
)

// setRawValue writes a raw value to a registry key using the Windows API directly.
// This is needed because registry.Key only exposes typed setters, not a generic SetValue.
func setRawValue(key registry.Key, name string, valType uint32, data []byte) error {
	nameUTF16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var dataPtr uintptr
	if len(data) > 0 {
		dataPtr = uintptr(unsafe.Pointer(&data[0]))
	}
	ret, _, _ := procRegSetValueExW.Call(
		uintptr(key),
		uintptr(unsafe.Pointer(nameUTF16)),
		0,
		uintptr(valType),
		dataPtr,
		uintptr(len(data)),
	)
	if ret != 0 {
		return fmt.Errorf("RegSetValueEx failed with error code %d", ret)
	}
	return nil
}

// WindowsService implements Service for Windows registry operations.
type WindowsService struct{}

var (
	defaultService *WindowsService
	serviceOnce    sync.Once
)

// New creates a new Windows registry service.
func New() *WindowsService {
	return &WindowsService{}
}

// GetDefault returns the default singleton registry service.
func GetDefault() Service {
	serviceOnce.Do(func() {
		defaultService = New()
	})
	return defaultService
}

// ExportKey exports a registry key to a file.
func (s *WindowsService) ExportKey(ctx context.Context, keyPath, outputPath string) error {
	cmd := exec.CommandContext(ctx, "reg", "export", keyPath, outputPath, "/y")
	return cmd.Run()
}

// IsAvailable returns true as registry operations are available on Windows.
func (s *WindowsService) IsAvailable() bool {
	return true
}

// resolveHive maps a hive string to a registry.Key constant.
func resolveHive(hive string) (registry.Key, error) {
	switch strings.ToUpper(hive) {
	case "HKCR", "HKEY_CLASSES_ROOT":
		return registry.CLASSES_ROOT, nil
	case "HKCU", "HKEY_CURRENT_USER":
		return registry.CURRENT_USER, nil
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return registry.LOCAL_MACHINE, nil
	case "HKU", "HKEY_USERS":
		return registry.USERS, nil
	case "HKCC", "HKEY_CURRENT_CONFIG":
		return registry.CURRENT_CONFIG, nil
	default:
		return 0, fmt.Errorf("unknown hive: %s", hive)
	}
}

// regTypeToString converts a registry value type constant to its string name.
func regTypeToString(valType uint32) string {
	switch valType {
	case registry.SZ:
		return "REG_SZ"
	case registry.EXPAND_SZ:
		return "REG_EXPAND_SZ"
	case registry.MULTI_SZ:
		return "REG_MULTI_SZ"
	case registry.DWORD:
		return "REG_DWORD"
	case registry.QWORD:
		return "REG_QWORD"
	case registry.BINARY:
		return "REG_BINARY"
	case registry.NONE:
		return "REG_NONE"
	default:
		return fmt.Sprintf("REG_UNKNOWN(%d)", valType)
	}
}

// readValue reads a single registry value and returns its data and type string.
func readValue(key registry.Key, name string) (interface{}, string, error) {
	_, valType, err := key.GetValue(name, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to stat value %q: %w", name, err)
	}

	typeStr := regTypeToString(valType)

	switch valType {
	case registry.SZ, registry.EXPAND_SZ:
		val, _, err := key.GetStringValue(name)
		if err != nil {
			return nil, typeStr, err
		}
		return val, typeStr, nil

	case registry.MULTI_SZ:
		val, _, err := key.GetStringsValue(name)
		if err != nil {
			return nil, typeStr, err
		}
		return val, typeStr, nil

	case registry.DWORD, registry.QWORD:
		val, _, err := key.GetIntegerValue(name)
		if err != nil {
			return nil, typeStr, err
		}
		return val, typeStr, nil

	case registry.BINARY:
		val, _, err := key.GetBinaryValue(name)
		if err != nil {
			return nil, typeStr, err
		}
		return base64.StdEncoding.EncodeToString(val), typeStr, nil

	default:
		buf := make([]byte, 4096)
		n, _, err := key.GetValue(name, buf)
		if err != nil {
			return nil, typeStr, err
		}
		return base64.StdEncoding.EncodeToString(buf[:n]), typeStr, nil
	}
}

// ListKey returns subkeys and values for a registry path.
// Uses RegOpenKeyEx, RegEnumKeyEx, RegEnumValue, and RegQueryValueEx.
func (s *WindowsService) ListKey(_ context.Context, hive, path string) (*ListKeyResult, error) {
	rootKey, err := resolveHive(hive)
	if err != nil {
		return nil, err
	}

	key, err := registry.OpenKey(rootKey, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("failed to open key %s\\%s: %w", hive, path, err)
	}
	defer key.Close()

	result := &ListKeyResult{}
	if path == "" {
		result.Path = hive
	} else {
		result.Path = hive + `\` + path
	}

	// Enumerate subkeys.
	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate subkeys: %w", err)
	}
	result.Subkeys = subkeys

	// Enumerate values.
	stat, err := key.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat key: %w", err)
	}

	valueNames := make([]string, 0, stat.ValueCount)
	if stat.ValueCount > 0 {
		valueNames, err = key.ReadValueNames(int(stat.ValueCount))
		if err != nil {
			return nil, fmt.Errorf("failed to enumerate values: %w", err)
		}
	}

	result.Values = make([]ValueEntry, 0, len(valueNames))
	for _, name := range valueNames {
		data, typeStr, readErr := readValue(key, name)
		if readErr != nil {
			result.Values = append(result.Values, ValueEntry{
				Name: name,
				Type: typeStr,
				Data: fmt.Sprintf("<error: %v>", readErr),
			})
			continue
		}
		result.Values = append(result.Values, ValueEntry{
			Name: name,
			Type: typeStr,
			Data: data,
		})
	}

	return result, nil
}

// CreateKey creates a new subkey under the specified hive and path.
// Uses RegCreateKeyEx.
func (s *WindowsService) CreateKey(_ context.Context, hive, path string) error {
	rootKey, err := resolveHive(hive)
	if err != nil {
		return err
	}

	key, _, err := registry.CreateKey(rootKey, path, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("failed to create key %s\\%s: %w", hive, path, err)
	}
	key.Close()
	return nil
}

// DeleteKey deletes a key and all its subkeys recursively.
// Uses RegDeleteTree via recursive enumeration and RegDeleteKey.
func (s *WindowsService) DeleteKey(_ context.Context, hive, path string) error {
	rootKey, err := resolveHive(hive)
	if err != nil {
		return err
	}

	if err := deleteKeyRecursive(rootKey, path); err != nil {
		return fmt.Errorf("failed to delete key %s\\%s: %w", hive, path, err)
	}
	return nil
}

// deleteKeyRecursive deletes a key and all its subkeys depth-first.
func deleteKeyRecursive(root registry.Key, path string) error {
	key, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return err
	}

	subkeys, err := key.ReadSubKeyNames(-1)
	key.Close()
	if err != nil {
		return err
	}

	for _, subkey := range subkeys {
		if err := deleteKeyRecursive(root, path+`\`+subkey); err != nil {
			return err
		}
	}

	return registry.DeleteKey(root, path)
}

// RenameKey renames a key by copying it to the new name and deleting the old one.
// There is no native rename API in the Windows registry.
func (s *WindowsService) RenameKey(_ context.Context, hive, path, newName string) error {
	rootKey, err := resolveHive(hive)
	if err != nil {
		return err
	}

	// Determine parent path and build the new full path.
	lastSep := strings.LastIndex(path, `\`)
	var newPath string
	if lastSep == -1 {
		newPath = newName
	} else {
		newPath = path[:lastSep] + `\` + newName
	}

	// Verify source exists.
	srcKey, err := registry.OpenKey(rootKey, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("source key does not exist: %w", err)
	}
	srcKey.Close()

	// Check destination does not already exist.
	dstKey, err := registry.OpenKey(rootKey, newPath, registry.QUERY_VALUE)
	if err == nil {
		dstKey.Close()
		return fmt.Errorf("destination key %s\\%s already exists", hive, newPath)
	}

	// Copy the entire key tree to the new location.
	if err := copyKeyRecursive(rootKey, path, rootKey, newPath); err != nil {
		return fmt.Errorf("failed to copy key: %w", err)
	}

	// Delete the original key tree.
	if err := deleteKeyRecursive(rootKey, path); err != nil {
		_ = deleteKeyRecursive(rootKey, newPath)
		return fmt.Errorf("failed to delete old key after copy: %w", err)
	}

	return nil
}

// copyKeyRecursive copies a key, all its values, and all its subkeys.
func copyKeyRecursive(srcRoot registry.Key, srcPath string, dstRoot registry.Key, dstPath string) error {
	srcKey, err := registry.OpenKey(srcRoot, srcPath, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer srcKey.Close()

	dstKey, _, err := registry.CreateKey(dstRoot, dstPath, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer dstKey.Close()

	// Copy all values.
	stat, err := srcKey.Stat()
	if err != nil {
		return err
	}

	if stat.ValueCount > 0 {
		valueNames, err := srcKey.ReadValueNames(int(stat.ValueCount))
		if err != nil {
			return err
		}
		for _, name := range valueNames {
			buf := make([]byte, stat.MaxValueLen)
			n, valType, err := srcKey.GetValue(name, buf)
			if err != nil {
				return fmt.Errorf("failed to read value %q: %w", name, err)
			}
			if err := setRawValue(dstKey, name, valType, buf[:n]); err != nil {
				return fmt.Errorf("failed to write value %q: %w", name, err)
			}
		}
	}

	// Copy subkeys recursively.
	subkeys, err := srcKey.ReadSubKeyNames(-1)
	if err != nil {
		return err
	}
	for _, subkey := range subkeys {
		if err := copyKeyRecursive(srcRoot, srcPath+`\`+subkey, dstRoot, dstPath+`\`+subkey); err != nil {
			return err
		}
	}

	return nil
}

// SetValue creates or modifies a registry value.
// Uses RegSetValueEx.
// Supported types: REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, REG_DWORD, REG_QWORD, REG_BINARY.
func (s *WindowsService) SetValue(_ context.Context, hive, path, name, valueType string, data interface{}) error {
	rootKey, err := resolveHive(hive)
	if err != nil {
		return err
	}

	key, err := registry.OpenKey(rootKey, path, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open key %s\\%s: %w", hive, path, err)
	}
	defer key.Close()

	switch strings.ToUpper(valueType) {
	case "REG_SZ":
		str, ok := data.(string)
		if !ok {
			return fmt.Errorf("REG_SZ requires string data, got %T", data)
		}
		return key.SetStringValue(name, str)

	case "REG_EXPAND_SZ":
		str, ok := data.(string)
		if !ok {
			return fmt.Errorf("REG_EXPAND_SZ requires string data, got %T", data)
		}
		return key.SetExpandStringValue(name, str)

	case "REG_MULTI_SZ":
		switch v := data.(type) {
		case []string:
			return key.SetStringsValue(name, v)
		case []interface{}:
			strs := make([]string, len(v))
			for i, item := range v {
				s, ok := item.(string)
				if !ok {
					return fmt.Errorf("REG_MULTI_SZ element %d is %T, expected string", i, item)
				}
				strs[i] = s
			}
			return key.SetStringsValue(name, strs)
		default:
			return fmt.Errorf("REG_MULTI_SZ requires []string data, got %T", data)
		}

	case "REG_DWORD":
		num, err := toUint32(data)
		if err != nil {
			return fmt.Errorf("REG_DWORD: %w", err)
		}
		return key.SetDWordValue(name, num)

	case "REG_QWORD":
		num, err := toUint64(data)
		if err != nil {
			return fmt.Errorf("REG_QWORD: %w", err)
		}
		return key.SetQWordValue(name, num)

	case "REG_BINARY":
		str, ok := data.(string)
		if !ok {
			return fmt.Errorf("REG_BINARY requires base64-encoded string data, got %T", data)
		}
		decoded, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			return fmt.Errorf("REG_BINARY: invalid base64: %w", err)
		}
		return key.SetBinaryValue(name, decoded)

	default:
		return fmt.Errorf("unsupported value type: %s", valueType)
	}
}

// toUint32 converts a numeric interface{} to uint32.
func toUint32(data interface{}) (uint32, error) {
	switch v := data.(type) {
	case float64:
		return uint32(v), nil
	case float32:
		return uint32(v), nil
	case int:
		return uint32(v), nil
	case int32:
		return uint32(v), nil
	case int64:
		return uint32(v), nil
	case uint32:
		return v, nil
	case uint64:
		return uint32(v), nil
	default:
		return 0, fmt.Errorf("requires numeric data, got %T", data)
	}
}

// toUint64 converts a numeric interface{} to uint64.
func toUint64(data interface{}) (uint64, error) {
	switch v := data.(type) {
	case float64:
		return uint64(v), nil
	case float32:
		return uint64(v), nil
	case int:
		return uint64(v), nil
	case int32:
		return uint64(v), nil
	case int64:
		return uint64(v), nil
	case uint32:
		return uint64(v), nil
	case uint64:
		return v, nil
	default:
		return 0, fmt.Errorf("requires numeric data, got %T", data)
	}
}

// DeleteValue deletes a registry value.
// Uses RegDeleteValue.
func (s *WindowsService) DeleteValue(_ context.Context, hive, path, name string) error {
	rootKey, err := resolveHive(hive)
	if err != nil {
		return err
	}

	key, err := registry.OpenKey(rootKey, path, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open key %s\\%s: %w", hive, path, err)
	}
	defer key.Close()

	if err := key.DeleteValue(name); err != nil {
		return fmt.Errorf("failed to delete value %q: %w", name, err)
	}
	return nil
}

// RenameValue renames a registry value by reading the old value, writing it
// with the new name, and deleting the old one.
func (s *WindowsService) RenameValue(_ context.Context, hive, path, oldName, newName string) error {
	rootKey, err := resolveHive(hive)
	if err != nil {
		return err
	}

	key, err := registry.OpenKey(rootKey, path, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open key %s\\%s: %w", hive, path, err)
	}
	defer key.Close()

	// Read the old value's raw bytes and type.
	buf := make([]byte, 4096)
	n, valType, err := key.GetValue(oldName, buf)
	if err != nil {
		return fmt.Errorf("failed to read value %q: %w", oldName, err)
	}

	// Write the value with the new name.
	if err := setRawValue(key, newName, valType, buf[:n]); err != nil {
		return fmt.Errorf("failed to write value %q: %w", newName, err)
	}

	// Delete the old value.
	if err := key.DeleteValue(oldName); err != nil {
		_ = key.DeleteValue(newName)
		return fmt.Errorf("failed to delete old value %q: %w", oldName, err)
	}

	return nil
}

// SearchKey searches recursively for keys and values matching a query string.
// Max depth is 10 levels. maxResults limits the number of results returned.
func (s *WindowsService) SearchKey(_ context.Context, hive, path, query string, maxResults int) (*SearchResult, error) {
	rootKey, err := resolveHive(hive)
	if err != nil {
		return nil, err
	}

	if maxResults <= 0 {
		maxResults = 100
	}

	queryLower := strings.ToLower(query)
	results := &SearchResult{}

	searchRecursive(rootKey, hive, path, queryLower, 0, 10, maxResults, results)

	return results, nil
}

// searchRecursive performs the depth-limited recursive search.
func searchRecursive(root registry.Key, hive, path, queryLower string, depth, maxDepth, maxResults int, results *SearchResult) {
	if depth > maxDepth || len(results.Results) >= maxResults {
		if len(results.Results) >= maxResults {
			results.Truncated = true
		}
		return
	}

	key, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer key.Close()

	// Check value names for matches.
	stat, err := key.Stat()
	if err == nil && stat.ValueCount > 0 {
		valueNames, err := key.ReadValueNames(int(stat.ValueCount))
		if err == nil {
			for _, name := range valueNames {
				if len(results.Results) >= maxResults {
					results.Truncated = true
					return
				}
				if strings.Contains(strings.ToLower(name), queryLower) {
					results.Results = append(results.Results, SearchEntry{
						Path: hive + `\` + path,
						Name: name,
						Type: "value",
					})
				}
			}
		}
	}

	// Enumerate and recurse into subkeys.
	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return
	}

	for _, subkey := range subkeys {
		if len(results.Results) >= maxResults {
			results.Truncated = true
			return
		}

		subPath := path + `\` + subkey
		if path == "" {
			subPath = subkey
		}

		// Check if the subkey name itself matches.
		if strings.Contains(strings.ToLower(subkey), queryLower) {
			results.Results = append(results.Results, SearchEntry{
				Path: hive + `\` + subPath,
				Type: "key",
			})
		}

		searchRecursive(root, hive, subPath, queryLower, depth+1, maxDepth, maxResults, results)
	}
}
