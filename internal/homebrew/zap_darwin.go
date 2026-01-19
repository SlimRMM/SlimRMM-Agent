//go:build darwin
// +build darwin

// Package homebrew provides Homebrew cask zap stanza execution for macOS.
package homebrew

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ZapStanza represents the parsed zap stanza from a Homebrew cask.
type ZapStanza struct {
	Trash     []string `json:"trash,omitempty"`
	Delete    []string `json:"delete,omitempty"`
	Launchctl []string `json:"launchctl,omitempty"`
	Pkgutil   []string `json:"pkgutil,omitempty"`
	Quit      []string `json:"quit,omitempty"`
	Signal    []interface{} `json:"signal,omitempty"` // Can be string or [signal, bundleID]
	Rmdir     []string `json:"rmdir,omitempty"`
	Kext      []string `json:"kext,omitempty"`
}

// FetchCaskInfoFull fetches complete cask information including zap stanza.
func FetchCaskInfoFull(caskName string) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://formulae.brew.sh/api/cask/%s.json", caskName)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("cask not found: %s", caskName)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// ParseZapStanza parses zap stanza from cask info.
func ParseZapStanza(cleanupInfo map[string]interface{}) ([]ZapStanza, error) {
	zapData, ok := cleanupInfo["zap"]
	if !ok {
		return nil, nil
	}

	var zapItems []ZapStanza

	// Zap can be a single item or array
	switch zap := zapData.(type) {
	case []interface{}:
		for _, item := range zap {
			if itemMap, ok := item.(map[string]interface{}); ok {
				zapItem := parseZapItem(itemMap)
				zapItems = append(zapItems, zapItem)
			}
		}
	case map[string]interface{}:
		zapItem := parseZapItem(zap)
		zapItems = append(zapItems, zapItem)
	}

	return zapItems, nil
}

func parseZapItem(item map[string]interface{}) ZapStanza {
	zap := ZapStanza{}

	if trash, ok := item["trash"]; ok {
		zap.Trash = toStringSlice(trash)
	}
	if del, ok := item["delete"]; ok {
		zap.Delete = toStringSlice(del)
	}
	if launchctl, ok := item["launchctl"]; ok {
		zap.Launchctl = toStringSlice(launchctl)
	}
	if pkgutil, ok := item["pkgutil"]; ok {
		zap.Pkgutil = toStringSlice(pkgutil)
	}
	if quit, ok := item["quit"]; ok {
		zap.Quit = toStringSlice(quit)
	}
	if signal, ok := item["signal"]; ok {
		if signalSlice, ok := signal.([]interface{}); ok {
			zap.Signal = signalSlice
		}
	}
	if rmdir, ok := item["rmdir"]; ok {
		zap.Rmdir = toStringSlice(rmdir)
	}
	if kext, ok := item["kext"]; ok {
		zap.Kext = toStringSlice(kext)
	}

	return zap
}

func toStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case []string:
		return val
	}
	return nil
}

// ExecuteZapStanza executes all zap stanza operations.
// Returns paths removed, services unloaded, and any errors.
func ExecuteZapStanza(ctx context.Context, cleanupInfo map[string]interface{}) (*ZapResult, error) {
	result := &ZapResult{
		PathsRemoved:      make([]string, 0),
		ServicesUnloaded:  make([]string, 0),
		ReceiptsForgotten: make([]string, 0),
		Operations:        make([]ZapOperation, 0),
	}

	zapItems, err := ParseZapStanza(cleanupInfo)
	if err != nil {
		return result, err
	}

	if len(zapItems) == 0 {
		return result, nil
	}

	// Get current user's UID for launchctl
	currentUser, _ := user.Current()
	uid := "501" // Default
	if currentUser != nil {
		uid = currentUser.Uid
	}

	for _, zap := range zapItems {
		// Step 1: Quit applications
		for _, bundleID := range zap.Quit {
			op := quitApp(ctx, bundleID)
			result.Operations = append(result.Operations, op)
		}

		// Step 2: Send signals
		for _, sig := range zap.Signal {
			op := sendSignal(ctx, sig)
			result.Operations = append(result.Operations, op)
		}

		// Step 3: Unload LaunchAgents/Daemons
		for _, service := range zap.Launchctl {
			op := unloadLaunchctl(ctx, service, uid)
			result.Operations = append(result.Operations, op)
			if op.Success {
				result.ServicesUnloaded = append(result.ServicesUnloaded, service)
			}
		}

		// Step 4: Forget pkgutil receipts
		for _, receipt := range zap.Pkgutil {
			op := forgetPkgutil(ctx, receipt)
			result.Operations = append(result.Operations, op)
			if op.Success {
				result.ReceiptsForgotten = append(result.ReceiptsForgotten, receipt)
			}
		}

		// Step 5: Unload kexts
		for _, kext := range zap.Kext {
			op := unloadKext(ctx, kext)
			result.Operations = append(result.Operations, op)
		}

		// Step 6: Delete paths
		for _, path := range zap.Delete {
			expandedPath := expandPath(path)
			if !isProtectedPath(expandedPath) {
				op := deletePath(ctx, expandedPath)
				result.Operations = append(result.Operations, op)
				if op.Success {
					result.PathsRemoved = append(result.PathsRemoved, expandedPath)
				}
			}
		}

		// Step 7: Trash paths (same as delete for our purposes)
		for _, path := range zap.Trash {
			expandedPath := expandPath(path)
			if !isProtectedPath(expandedPath) {
				op := deletePath(ctx, expandedPath)
				result.Operations = append(result.Operations, op)
				if op.Success {
					result.PathsRemoved = append(result.PathsRemoved, expandedPath)
				}
			}
		}

		// Step 8: Remove directories if empty
		for _, path := range zap.Rmdir {
			expandedPath := expandPath(path)
			if !isProtectedPath(expandedPath) {
				op := rmdirIfEmpty(ctx, expandedPath)
				result.Operations = append(result.Operations, op)
			}
		}
	}

	return result, nil
}

// ZapOperation represents a single zap operation result.
type ZapOperation struct {
	Operation  string    `json:"operation"`
	Target     string    `json:"target"`
	Command    string    `json:"command,omitempty"`
	Args       []string  `json:"args,omitempty"`
	Stdout     string    `json:"stdout,omitempty"`
	Stderr     string    `json:"stderr,omitempty"`
	ExitCode   int       `json:"exit_code"`
	Success    bool      `json:"success"`
	Error      string    `json:"error,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
	DurationMs int64     `json:"duration_ms"`
}

// ZapResult contains the results of executing a zap stanza.
type ZapResult struct {
	PathsRemoved      []string       `json:"paths_removed"`
	ServicesUnloaded  []string       `json:"services_unloaded"`
	ReceiptsForgotten []string       `json:"receipts_forgotten"`
	Operations        []ZapOperation `json:"operations"`
}

func quitApp(ctx context.Context, bundleID string) ZapOperation {
	start := time.Now()
	op := ZapOperation{
		Operation: "quit_app",
		Target:    bundleID,
		Timestamp: start,
	}

	// Use osascript to quit the app
	script := fmt.Sprintf(`quit app id "%s"`, bundleID)
	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	op.Command = "osascript"
	op.Args = []string{"-e", script}

	output, err := cmd.CombinedOutput()
	op.DurationMs = time.Since(start).Milliseconds()
	op.Stdout = string(output)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			op.ExitCode = exitErr.ExitCode()
		} else {
			op.ExitCode = -1
		}
		op.Error = err.Error()
		op.Success = false
	} else {
		op.ExitCode = 0
		op.Success = true
	}

	return op
}

func sendSignal(ctx context.Context, sig interface{}) ZapOperation {
	start := time.Now()
	op := ZapOperation{
		Operation: "send_signal",
		Timestamp: start,
	}

	var signal, bundleID string
	switch s := sig.(type) {
	case string:
		signal = "TERM"
		bundleID = s
	case []interface{}:
		if len(s) >= 2 {
			signal = fmt.Sprintf("%v", s[0])
			bundleID = fmt.Sprintf("%v", s[1])
		}
	}

	op.Target = fmt.Sprintf("%s -> %s", signal, bundleID)

	// Get PID from bundle ID
	script := fmt.Sprintf(`tell application "System Events" to get unix id of process "%s"`, bundleID)
	pidCmd := exec.CommandContext(ctx, "osascript", "-e", script)
	pidOutput, err := pidCmd.Output()

	if err != nil {
		op.DurationMs = time.Since(start).Milliseconds()
		op.Error = fmt.Sprintf("could not find process: %v", err)
		op.Success = false
		return op
	}

	pid := strings.TrimSpace(string(pidOutput))
	if pid == "" {
		op.DurationMs = time.Since(start).Milliseconds()
		op.Error = "process not running"
		op.Success = true // Not an error if process isn't running
		return op
	}

	// Send signal
	cmd := exec.CommandContext(ctx, "kill", fmt.Sprintf("-%s", signal), pid)
	op.Command = "kill"
	op.Args = []string{fmt.Sprintf("-%s", signal), pid}

	output, err := cmd.CombinedOutput()
	op.DurationMs = time.Since(start).Milliseconds()
	op.Stdout = string(output)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			op.ExitCode = exitErr.ExitCode()
		} else {
			op.ExitCode = -1
		}
		op.Error = err.Error()
		op.Success = false
	} else {
		op.ExitCode = 0
		op.Success = true
	}

	return op
}

func unloadLaunchctl(ctx context.Context, service, uid string) ZapOperation {
	start := time.Now()
	op := ZapOperation{
		Operation: "launchctl_bootout",
		Target:    service,
		Timestamp: start,
	}

	// Try both user and system domains
	domains := []string{
		fmt.Sprintf("gui/%s/%s", uid, service),
		fmt.Sprintf("system/%s", service),
	}

	for _, domain := range domains {
		cmd := exec.CommandContext(ctx, "launchctl", "bootout", domain)
		op.Command = "launchctl"
		op.Args = []string{"bootout", domain}

		var stdout, stderr strings.Builder
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		op.Stdout = stdout.String()
		op.Stderr = stderr.String()

		if err == nil {
			op.DurationMs = time.Since(start).Milliseconds()
			op.ExitCode = 0
			op.Success = true
			return op
		}
	}

	// Also try to remove the plist file
	plistPaths := []string{
		filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents", service+".plist"),
		filepath.Join("/Library/LaunchAgents", service+".plist"),
		filepath.Join("/Library/LaunchDaemons", service+".plist"),
	}

	for _, plistPath := range plistPaths {
		if _, err := os.Stat(plistPath); err == nil {
			os.Remove(plistPath)
		}
	}

	op.DurationMs = time.Since(start).Milliseconds()
	op.Success = true // Consider success even if service wasn't loaded
	op.ExitCode = 0
	return op
}

func forgetPkgutil(ctx context.Context, receipt string) ZapOperation {
	start := time.Now()
	op := ZapOperation{
		Operation: "pkgutil_forget",
		Target:    receipt,
		Command:   "pkgutil",
		Args:      []string{"--forget", receipt},
		Timestamp: start,
	}

	cmd := exec.CommandContext(ctx, "pkgutil", "--forget", receipt)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	op.DurationMs = time.Since(start).Milliseconds()
	op.Stdout = stdout.String()
	op.Stderr = stderr.String()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			op.ExitCode = exitErr.ExitCode()
		} else {
			op.ExitCode = -1
		}
		op.Error = err.Error()
		op.Success = false
	} else {
		op.ExitCode = 0
		op.Success = true
	}

	return op
}

func unloadKext(ctx context.Context, kext string) ZapOperation {
	start := time.Now()
	op := ZapOperation{
		Operation: "kextunload",
		Target:    kext,
		Command:   "kextunload",
		Args:      []string{"-b", kext},
		Timestamp: start,
	}

	cmd := exec.CommandContext(ctx, "kextunload", "-b", kext)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	op.DurationMs = time.Since(start).Milliseconds()
	op.Stdout = stdout.String()
	op.Stderr = stderr.String()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			op.ExitCode = exitErr.ExitCode()
		} else {
			op.ExitCode = -1
		}
		op.Error = err.Error()
		op.Success = false
	} else {
		op.ExitCode = 0
		op.Success = true
	}

	return op
}

func deletePath(ctx context.Context, path string) ZapOperation {
	start := time.Now()
	op := ZapOperation{
		Operation: "delete_path",
		Target:    path,
		Command:   "rm",
		Args:      []string{"-rf", path},
		Timestamp: start,
	}

	// Check if path exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		op.DurationMs = time.Since(start).Milliseconds()
		op.Success = true
		op.ExitCode = 0
		op.Stdout = "path does not exist, skipped"
		return op
	}

	cmd := exec.CommandContext(ctx, "rm", "-rf", path)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	op.DurationMs = time.Since(start).Milliseconds()
	op.Stdout = stdout.String()
	op.Stderr = stderr.String()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			op.ExitCode = exitErr.ExitCode()
		} else {
			op.ExitCode = -1
		}
		op.Error = err.Error()
		op.Success = false
	} else {
		op.ExitCode = 0
		op.Success = true
	}

	return op
}

func rmdirIfEmpty(ctx context.Context, path string) ZapOperation {
	start := time.Now()
	op := ZapOperation{
		Operation: "rmdir_if_empty",
		Target:    path,
		Timestamp: start,
	}

	// Check if path exists and is directory
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		op.DurationMs = time.Since(start).Milliseconds()
		op.Success = true
		op.ExitCode = 0
		op.Stdout = "path does not exist, skipped"
		return op
	}

	if !info.IsDir() {
		op.DurationMs = time.Since(start).Milliseconds()
		op.Success = true
		op.ExitCode = 0
		op.Stdout = "not a directory, skipped"
		return op
	}

	// Try to remove (will fail if not empty)
	err = os.Remove(path)
	op.DurationMs = time.Since(start).Milliseconds()

	if err != nil {
		op.Error = err.Error()
		op.Success = true // Not an error if directory isn't empty
		op.ExitCode = 0
	} else {
		op.ExitCode = 0
		op.Success = true
	}

	return op
}

// expandPath expands ~ and environment variables.
func expandPath(path string) string {
	// Expand home directory
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, path[2:])
		}
	}

	// Expand environment variables
	path = os.ExpandEnv(path)

	return path
}

// isProtectedPath checks if a path should never be deleted.
func isProtectedPath(path string) bool {
	protectedPaths := []string{
		"/System",
		"/Library",
		"/usr",
		"/bin",
		"/sbin",
		"/private/var",
		"/cores",
	}

	path = filepath.Clean(path)

	for _, protected := range protectedPaths {
		protected = filepath.Clean(protected)
		if path == protected || strings.HasPrefix(path, protected+"/") {
			// Allow ~/Library paths (user preferences)
			home, _ := os.UserHomeDir()
			if strings.HasPrefix(path, home) && strings.Contains(path, "/Library/") {
				return false
			}
			return true
		}
	}

	return false
}

// GetCurrentUID returns the current user's UID as a string.
func GetCurrentUID() string {
	u, err := user.Current()
	if err != nil {
		return "501" // Default macOS UID
	}
	return u.Uid
}

// GetCurrentUIDInt returns the current user's UID as an int.
func GetCurrentUIDInt() int {
	u, err := user.Current()
	if err != nil {
		return 501
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 501
	}
	return uid
}

// =============================================================================
// Extended Cleanup Operations
// =============================================================================

// ExtendedZapStanza extends the standard zap stanza with additional cleanup options.
type ExtendedZapStanza struct {
	ZapStanza
	LoginItems       []string `json:"login_items,omitempty"`
	SystemExtensions []string `json:"system_extensions,omitempty"`
	Spotlight        bool     `json:"spotlight,omitempty"`
	Containers       []string `json:"containers,omitempty"`
	GroupContainers  []string `json:"group_containers,omitempty"`
}

// ExtendedZapResult contains results from extended zap operations.
type ExtendedZapResult struct {
	ZapResult
	LoginItemsRemoved       []string `json:"login_items_removed,omitempty"`
	SystemExtensionsRemoved []string `json:"system_extensions_removed,omitempty"`
	SpotlightIndexCleared   bool     `json:"spotlight_index_cleared,omitempty"`
	ContainersRemoved       []string `json:"containers_removed,omitempty"`
}

// ExecuteExtendedZapStanza executes all zap stanza operations including extended ones.
func ExecuteExtendedZapStanza(ctx context.Context, cleanupInfo map[string]interface{}) (*ExtendedZapResult, error) {
	// First execute standard zap stanza
	standardResult, err := ExecuteZapStanza(ctx, cleanupInfo)

	extResult := &ExtendedZapResult{
		LoginItemsRemoved:       make([]string, 0),
		SystemExtensionsRemoved: make([]string, 0),
		ContainersRemoved:       make([]string, 0),
	}

	if standardResult != nil {
		extResult.ZapResult = *standardResult
	}

	// Parse extended zap options
	extZap, extErr := ParseExtendedZapStanza(cleanupInfo)
	if extErr != nil || len(extZap) == 0 {
		return extResult, err
	}

	uid := GetCurrentUID()

	for _, zap := range extZap {
		// Handle login items
		for _, loginItem := range zap.LoginItems {
			op := removeLoginItem(ctx, loginItem)
			extResult.Operations = append(extResult.Operations, op)
			if op.Success {
				extResult.LoginItemsRemoved = append(extResult.LoginItemsRemoved, loginItem)
			}
		}

		// Handle system extensions
		for _, sysext := range zap.SystemExtensions {
			op := uninstallSystemExtension(ctx, sysext)
			extResult.Operations = append(extResult.Operations, op)
			if op.Success {
				extResult.SystemExtensionsRemoved = append(extResult.SystemExtensionsRemoved, sysext)
			}
		}

		// Handle app containers
		home, _ := os.UserHomeDir()
		for _, container := range zap.Containers {
			containerPath := filepath.Join(home, "Library", "Containers", container)
			op := deletePath(ctx, containerPath)
			extResult.Operations = append(extResult.Operations, op)
			if op.Success {
				extResult.ContainersRemoved = append(extResult.ContainersRemoved, container)
			}
		}

		// Handle group containers
		for _, groupContainer := range zap.GroupContainers {
			groupPath := filepath.Join(home, "Library", "Group Containers", groupContainer)
			op := deletePath(ctx, groupPath)
			extResult.Operations = append(extResult.Operations, op)
			if op.Success {
				extResult.ContainersRemoved = append(extResult.ContainersRemoved, groupContainer)
			}
		}

		// Clear spotlight index if requested
		if zap.Spotlight {
			op := clearSpotlightIndex(ctx)
			extResult.Operations = append(extResult.Operations, op)
			extResult.SpotlightIndexCleared = op.Success
		}

		_ = uid
	}

	return extResult, err
}

// ParseExtendedZapStanza parses extended zap options from cask info.
func ParseExtendedZapStanza(cleanupInfo map[string]interface{}) ([]ExtendedZapStanza, error) {
	zapData, ok := cleanupInfo["zap"]
	if !ok {
		return nil, nil
	}

	var extZapItems []ExtendedZapStanza

	switch zap := zapData.(type) {
	case []interface{}:
		for _, item := range zap {
			if itemMap, ok := item.(map[string]interface{}); ok {
				extZapItem := parseExtendedZapItem(itemMap)
				extZapItems = append(extZapItems, extZapItem)
			}
		}
	case map[string]interface{}:
		extZapItem := parseExtendedZapItem(zap)
		extZapItems = append(extZapItems, extZapItem)
	}

	return extZapItems, nil
}

func parseExtendedZapItem(item map[string]interface{}) ExtendedZapStanza {
	extZap := ExtendedZapStanza{
		ZapStanza: parseZapItem(item),
	}

	if loginItems, ok := item["login_item"]; ok {
		extZap.LoginItems = toStringSlice(loginItems)
	}
	if sysext, ok := item["system_extension"]; ok {
		extZap.SystemExtensions = toStringSlice(sysext)
	}
	if spotlight, ok := item["spotlight"].(bool); ok {
		extZap.Spotlight = spotlight
	}
	if containers, ok := item["container"]; ok {
		extZap.Containers = toStringSlice(containers)
	}
	if groupContainers, ok := item["group_container"]; ok {
		extZap.GroupContainers = toStringSlice(groupContainers)
	}

	return extZap
}

// removeLoginItem removes a login item using AppleScript.
func removeLoginItem(ctx context.Context, itemName string) ZapOperation {
	start := time.Now()
	op := ZapOperation{
		Operation: "remove_login_item",
		Target:    itemName,
		Timestamp: start,
	}

	// Use osascript to remove login item
	script := fmt.Sprintf(`tell application "System Events" to delete login item "%s"`, itemName)
	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	op.Command = "osascript"
	op.Args = []string{"-e", script}

	output, err := cmd.CombinedOutput()
	op.DurationMs = time.Since(start).Milliseconds()
	op.Stdout = string(output)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			op.ExitCode = exitErr.ExitCode()
		} else {
			op.ExitCode = -1
		}
		op.Error = err.Error()
		// Not finding the login item is not an error
		op.Success = strings.Contains(op.Error, "Can't get login item") || strings.Contains(string(output), "Can't get")
		if !op.Success {
			op.Success = false
		}
	} else {
		op.ExitCode = 0
		op.Success = true
	}

	return op
}

// uninstallSystemExtension uninstalls a system extension.
func uninstallSystemExtension(ctx context.Context, teamID string) ZapOperation {
	start := time.Now()
	op := ZapOperation{
		Operation: "uninstall_system_extension",
		Target:    teamID,
		Command:   "systemextensionsctl",
		Args:      []string{"uninstall", teamID},
		Timestamp: start,
	}

	cmd := exec.CommandContext(ctx, "systemextensionsctl", "uninstall", teamID)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	op.DurationMs = time.Since(start).Milliseconds()
	op.Stdout = stdout.String()
	op.Stderr = stderr.String()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			op.ExitCode = exitErr.ExitCode()
		} else {
			op.ExitCode = -1
		}
		op.Error = err.Error()
		// Extension not found is not an error
		op.Success = strings.Contains(op.Stderr, "no extensions")
	} else {
		op.ExitCode = 0
		op.Success = true
	}

	return op
}

// clearSpotlightIndex triggers a Spotlight reindex.
func clearSpotlightIndex(ctx context.Context) ZapOperation {
	start := time.Now()
	op := ZapOperation{
		Operation: "clear_spotlight_index",
		Target:    "/",
		Timestamp: start,
	}

	// Turn off indexing
	cmd := exec.CommandContext(ctx, "mdutil", "-i", "off", "/")
	op.Command = "mdutil"
	op.Args = []string{"-i", "off", "/"}

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_ = cmd.Run()

	// Turn indexing back on (will trigger reindex)
	cmd = exec.CommandContext(ctx, "mdutil", "-i", "on", "/")
	err := cmd.Run()

	op.DurationMs = time.Since(start).Milliseconds()
	op.Stdout = stdout.String()
	op.Stderr = stderr.String()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			op.ExitCode = exitErr.ExitCode()
		} else {
			op.ExitCode = -1
		}
		op.Error = err.Error()
		op.Success = false
	} else {
		op.ExitCode = 0
		op.Success = true
	}

	return op
}

// =============================================================================
// Service Management Utilities
// =============================================================================

// StopAllServicesForBundle stops all launchctl services for a bundle ID pattern.
func StopAllServicesForBundle(ctx context.Context, bundleIDPattern string) []ZapOperation {
	var operations []ZapOperation
	uid := GetCurrentUID()

	// List all services
	cmd := exec.CommandContext(ctx, "launchctl", "list")
	output, err := cmd.Output()
	if err != nil {
		return operations
	}

	lines := strings.Split(string(output), "\n")
	bundleIDLower := strings.ToLower(bundleIDPattern)

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			serviceName := fields[2]
			if strings.Contains(strings.ToLower(serviceName), bundleIDLower) {
				op := unloadLaunchctl(ctx, serviceName, uid)
				operations = append(operations, op)
			}
		}
	}

	return operations
}

// GetInstalledServices returns a list of services matching a pattern.
func GetInstalledServices(ctx context.Context, pattern string) []string {
	var services []string

	cmd := exec.CommandContext(ctx, "launchctl", "list")
	output, err := cmd.Output()
	if err != nil {
		return services
	}

	patternLower := strings.ToLower(pattern)
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			serviceName := fields[2]
			if strings.Contains(strings.ToLower(serviceName), patternLower) {
				services = append(services, serviceName)
			}
		}
	}

	return services
}

// =============================================================================
// Application Utilities
// =============================================================================

// QuitAllInstances quits all running instances of an application.
func QuitAllInstances(ctx context.Context, appName string) []ZapOperation {
	var operations []ZapOperation

	// Try to quit via AppleScript first (graceful)
	script := fmt.Sprintf(`
		tell application "System Events"
			set appList to every process whose name contains "%s"
			repeat with proc in appList
				tell proc to quit
			end repeat
		end tell
	`, appName)

	start := time.Now()
	op := ZapOperation{
		Operation: "quit_all_instances",
		Target:    appName,
		Command:   "osascript",
		Args:      []string{"-e", script},
		Timestamp: start,
	}

	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	output, err := cmd.CombinedOutput()
	op.DurationMs = time.Since(start).Milliseconds()
	op.Stdout = string(output)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			op.ExitCode = exitErr.ExitCode()
		} else {
			op.ExitCode = -1
		}
		op.Error = err.Error()
	} else {
		op.ExitCode = 0
		op.Success = true
	}

	operations = append(operations, op)

	// Also try to kill any remaining processes via pkill
	time.Sleep(500 * time.Millisecond) // Give apps time to quit gracefully

	killOp := ZapOperation{
		Operation: "pkill_remaining",
		Target:    appName,
		Command:   "pkill",
		Args:      []string{"-f", appName},
		Timestamp: time.Now(),
	}

	cmd = exec.CommandContext(ctx, "pkill", "-f", appName)
	cmd.Run() // Ignore error - process may already be gone

	killOp.DurationMs = time.Since(killOp.Timestamp).Milliseconds()
	killOp.Success = true
	operations = append(operations, killOp)

	return operations
}

// IsAppRunning checks if an application is currently running.
func IsAppRunning(ctx context.Context, appName string) bool {
	cmd := exec.CommandContext(ctx, "pgrep", "-x", appName)
	err := cmd.Run()
	return err == nil
}

// GetAppBundleID gets the bundle ID of an application.
func GetAppBundleID(appPath string) (string, error) {
	plistPath := filepath.Join(appPath, "Contents", "Info.plist")

	cmd := exec.Command("defaults", "read", plistPath, "CFBundleIdentifier")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(output)), nil
}

// =============================================================================
// Cleanup Path Utilities
// =============================================================================

// GetAllCleanupPaths returns all paths that would be cleaned up for an app.
func GetAllCleanupPaths(appName, bundleID string) []string {
	var paths []string
	home, _ := os.UserHomeDir()

	// Library subdirectories
	libraryDirs := []string{
		"Application Support",
		"Caches",
		"Preferences",
		"Saved Application State",
		"HTTPStorages",
		"Logs",
		"Containers",
		"Group Containers",
		"Cookies",
		"WebKit",
	}

	for _, dir := range libraryDirs {
		if appName != "" {
			paths = append(paths, filepath.Join(home, "Library", dir, appName))
		}
		if bundleID != "" {
			paths = append(paths, filepath.Join(home, "Library", dir, bundleID))
		}
	}

	// Preferences plist files
	if bundleID != "" {
		paths = append(paths, filepath.Join(home, "Library", "Preferences", bundleID+".plist"))
		paths = append(paths, filepath.Join(home, "Library", "Preferences", bundleID+".plist.lockfile"))
	}

	// LaunchAgents
	if bundleID != "" {
		paths = append(paths, filepath.Join(home, "Library", "LaunchAgents", bundleID+".plist"))
		paths = append(paths, filepath.Join("/Library", "LaunchAgents", bundleID+".plist"))
		paths = append(paths, filepath.Join("/Library", "LaunchDaemons", bundleID+".plist"))
	}

	return paths
}

// EstimateCleanupSize estimates the total size of cleanup paths.
func EstimateCleanupSize(paths []string) int64 {
	var totalSize int64

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		if info.IsDir() {
			filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				if !info.IsDir() {
					totalSize += info.Size()
				}
				return nil
			})
		} else {
			totalSize += info.Size()
		}
	}

	return totalSize
}
