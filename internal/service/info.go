// Package service provides agent service utilities.
package service

import (
	"fmt"
	"os"
	"runtime"

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

