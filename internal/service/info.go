// Package service provides agent service utilities.
package service

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/slimrmm/slimrmm-agent/internal/config"
	"github.com/slimrmm/slimrmm-agent/pkg/version"
)

// AgentInfo holds agent status information.
type AgentInfo struct {
	Version        string `json:"version"`
	GitCommit      string `json:"git_commit"`
	BuildDate      string `json:"build_date"`
	Server         string `json:"server"`
	UUID           string `json:"uuid"`
	InstallDate    string `json:"install_date"`
	LastConnection string `json:"last_connection"`
	LastHeartbeat  string `json:"last_heartbeat"`
	MTLSEnabled    bool   `json:"mtls_enabled"`

	// macOS specific
	FullDiskAccess bool `json:"full_disk_access,omitempty"`
	ScreenSharing  bool `json:"screen_sharing,omitempty"`
}

// GetAgentInfo returns the current agent information.
func GetAgentInfo(cfg *config.Config) *AgentInfo {
	v := version.Get()
	info := &AgentInfo{
		Version:        v.Version,
		GitCommit:      v.GitCommit,
		BuildDate:      v.BuildDate,
		Server:         cfg.GetServer(),
		UUID:           cfg.GetUUID(),
		InstallDate:    cfg.GetInstallDate(),
		LastConnection: cfg.GetLastConnection(),
		LastHeartbeat:  cfg.GetLastHeartbeat(),
		MTLSEnabled:    cfg.IsMTLSEnabled(),
	}

	// Check macOS-specific permissions
	if runtime.GOOS == "darwin" {
		info.FullDiskAccess = checkFullDiskAccess()
		info.ScreenSharing = checkScreenSharingEnabled()
	}

	return info
}

// PrintInfo prints the agent info to stdout.
func (i *AgentInfo) PrintInfo() {
	fmt.Println("SlimRMM Agent Information")
	fmt.Println("=========================")
	fmt.Printf("Version:         %s\n", i.Version)
	fmt.Printf("Git Commit:      %s\n", i.GitCommit)
	fmt.Printf("Build Date:      %s\n", i.BuildDate)
	fmt.Println()
	fmt.Printf("Server:          %s\n", valueOrNA(i.Server))
	fmt.Printf("Agent UUID:      %s\n", valueOrNA(i.UUID))
	fmt.Printf("mTLS Enabled:    %v\n", i.MTLSEnabled)
	fmt.Println()
	fmt.Printf("Install Date:    %s\n", valueOrNA(i.InstallDate))
	fmt.Printf("Last Connection: %s\n", valueOrNA(i.LastConnection))
	fmt.Printf("Last Heartbeat:  %s\n", valueOrNA(i.LastHeartbeat))

	if runtime.GOOS == "darwin" {
		fmt.Println()
		fmt.Println("macOS Permissions")
		fmt.Println("-----------------")
		fmt.Printf("Full Disk Access:  %s\n", permissionStatus(i.FullDiskAccess))
		fmt.Printf("Screen Recording:  %s\n", permissionStatus(i.ScreenSharing))
	}
}

func valueOrNA(s string) string {
	if s == "" {
		return "N/A"
	}
	return s
}

func permissionStatus(granted bool) string {
	if granted {
		return "Granted"
	}
	return "Not Granted"
}

// checkFullDiskAccess checks if the agent has Full Disk Access on macOS.
func checkFullDiskAccess() bool {
	if runtime.GOOS != "darwin" {
		return false
	}

	// Try to read a file that requires FDA
	// ~/Library/Mail is protected by FDA
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}

	// Try to access a protected directory
	protectedPaths := []string{
		home + "/Library/Mail",
		home + "/Library/Safari",
		"/Library/Application Support/com.apple.TCC",
	}

	for _, path := range protectedPaths {
		if _, err := os.ReadDir(path); err == nil {
			return true
		}
	}

	return false
}

// checkScreenSharingEnabled checks if Screen Recording permission is granted on macOS.
func checkScreenSharingEnabled() bool {
	if runtime.GOOS != "darwin" {
		return false
	}

	// Use CGPreflightScreenCaptureAccess via a simple test
	// This checks if the current app has screen recording permission
	cmd := exec.Command("osascript", "-e", `
		use framework "CoreGraphics"
		set hasAccess to current application's CGPreflightScreenCaptureAccess()
		if hasAccess then
			return "granted"
		else
			return "denied"
		end if
	`)

	output, err := cmd.Output()
	if err != nil {
		// Fallback: check TCC database (may not work without FDA)
		return checkTCCScreenCapture()
	}

	return strings.TrimSpace(string(output)) == "granted"
}

// checkTCCScreenCapture checks the TCC database for screen capture permission.
func checkTCCScreenCapture() bool {
	// Try to query the TCC database
	cmd := exec.Command("sqlite3",
		"/Library/Application Support/com.apple.TCC/TCC.db",
		"SELECT auth_value FROM access WHERE service='kTCCServiceScreenCapture' AND client LIKE '%slimrmm%' LIMIT 1")

	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// auth_value 2 means authorized
	return strings.TrimSpace(string(output)) == "2"
}
