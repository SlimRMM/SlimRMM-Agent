// Package hyperv provides Hyper-V detection and management capabilities.
package hyperv

import (
	"context"
	"encoding/json"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Info contains Hyper-V host information.
type Info struct {
	IsHyperV       bool   `json:"is_hyperv"`
	Version        string `json:"version,omitempty"`
	HostName       string `json:"host_name,omitempty"`
	VMCount        int    `json:"vm_count,omitempty"`
	ClusterEnabled bool   `json:"cluster_enabled,omitempty"`
}

const detectionTimeout = 5 * time.Second

// vmHostInfo is the JSON structure returned by Get-VMHost PowerShell command.
type vmHostInfo struct {
	Name                           string `json:"Name"`
	FullyQualifiedDomainName       string `json:"FullyQualifiedDomainName"`
	VirtualHardDiskPath            string `json:"VirtualHardDiskPath"`
	VirtualMachinePath             string `json:"VirtualMachinePath"`
	MacAddressMaximum              string `json:"MacAddressMaximum"`
	MacAddressMinimum              string `json:"MacAddressMinimum"`
	EnableEnhancedSessionMode      bool   `json:"EnableEnhancedSessionMode"`
	NumaSpanningEnabled            bool   `json:"NumaSpanningEnabled"`
	IoVSupport                     bool   `json:"IoVSupport"`
	VirtualMachineMigrationEnabled bool   `json:"VirtualMachineMigrationEnabled"`
}

// Detect checks if the current system is a Hyper-V host.
// This function uses PowerShell and does not require API authentication.
func Detect(ctx context.Context) *Info {
	info := &Info{IsHyperV: false}

	// Hyper-V only runs on Windows
	if runtime.GOOS != "windows" {
		return info
	}

	ctx, cancel := context.WithTimeout(ctx, detectionTimeout)
	defer cancel()

	// Check if Hyper-V is available using Get-VMHost
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-VMHost | Select-Object Name, FullyQualifiedDomainName, VirtualMachineMigrationEnabled | ConvertTo-Json")
	output, err := cmd.Output()
	if err != nil {
		// Hyper-V not available or not installed
		return info
	}

	// Parse the JSON output
	var hostInfo vmHostInfo
	if err := json.Unmarshal(output, &hostInfo); err != nil {
		// Failed to parse, but command succeeded - might be Hyper-V
		info.IsHyperV = true
		return info
	}

	info.IsHyperV = true
	info.HostName = hostInfo.Name
	if hostInfo.FullyQualifiedDomainName != "" && hostInfo.FullyQualifiedDomainName != hostInfo.Name {
		info.HostName = hostInfo.FullyQualifiedDomainName
	}

	// Get Hyper-V version
	info.Version = getHyperVVersion(ctx)

	// Get VM count
	info.VMCount = getVMCount(ctx)

	// Check cluster status
	info.ClusterEnabled = isClusterEnabled(ctx)

	return info
}

// getHyperVVersion retrieves the Hyper-V version from registry.
func getHyperVVersion(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		`(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization' -ErrorAction SilentlyContinue).Version`)
	output, err := cmd.Output()
	if err != nil {
		// Try alternative method - get Windows build
		cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
			`[System.Environment]::OSVersion.Version.ToString()`)
		output, err = cmd.Output()
		if err != nil {
			return ""
		}
	}
	return strings.TrimSpace(string(output))
}

// getVMCount returns the number of VMs on the host.
func getVMCount(ctx context.Context) int {
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		`(Get-VM).Count`)
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	var count int
	if _, err := parseIntFromString(strings.TrimSpace(string(output)), &count); err != nil {
		return 0
	}
	return count
}

// parseIntFromString parses an integer from a string.
func parseIntFromString(s string, v *int) (string, error) {
	var i int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			i = i*10 + int(c-'0')
		}
	}
	*v = i
	return s, nil
}

// isClusterEnabled checks if Failover Clustering is enabled.
func isClusterEnabled(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		`(Get-Service -Name 'ClusSvc' -ErrorAction SilentlyContinue).Status -eq 'Running'`)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "True"
}

// IsHyperVHost is a quick check if the system is a Hyper-V host.
func IsHyperVHost() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		`(Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue).State -eq 'Enabled'`)
	output, err := cmd.Output()
	if err != nil {
		// Try alternative check via service
		cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
			`(Get-Service -Name 'vmms' -ErrorAction SilentlyContinue).Status -eq 'Running'`)
		output, err = cmd.Output()
		if err != nil {
			return false
		}
	}
	return strings.TrimSpace(string(output)) == "True"
}
