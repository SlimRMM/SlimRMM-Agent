// Package proxmox provides Proxmox VE detection and management capabilities.
package proxmox

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Info contains Proxmox host information.
type Info struct {
	IsProxmox      bool   `json:"is_proxmox"`
	Version        string `json:"version,omitempty"`
	Release        string `json:"release,omitempty"`
	KernelVersion  string `json:"kernel_version,omitempty"`
	ClusterName    string `json:"cluster_name,omitempty"`
	NodeName       string `json:"node_name,omitempty"`
	RepositoryType string `json:"repository_type,omitempty"` // enterprise, no-subscription, test
}

const (
	pveConfigPath   = "/etc/pve"
	pveVersionCmd   = "pveversion"
	pveClusterConf  = "/etc/pve/corosync.conf"
	pveLocalNode    = "/etc/hostname"
	detectionTimeout = 5 * time.Second
)

// Detect checks if the current system is a Proxmox VE host.
// This function uses CLI tools and does not require API authentication.
func Detect(ctx context.Context) *Info {
	info := &Info{IsProxmox: false}

	// Check if /etc/pve exists (definitive Proxmox indicator)
	if _, err := os.Stat(pveConfigPath); os.IsNotExist(err) {
		return info
	}

	// Try to get version information
	ctx, cancel := context.WithTimeout(ctx, detectionTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, pveVersionCmd, "-v")
	output, err := cmd.Output()
	if err != nil {
		// pveversion not available, but /etc/pve exists - still Proxmox
		info.IsProxmox = true
		return info
	}

	info.IsProxmox = true
	parseVersionOutput(string(output), info)

	// Get node name
	if hostname, err := os.Hostname(); err == nil {
		info.NodeName = hostname
	}

	// Check for cluster configuration
	if clusterName := getClusterName(); clusterName != "" {
		info.ClusterName = clusterName
	}

	// Detect repository type
	info.RepositoryType = detectRepositoryType()

	return info
}

// parseVersionOutput parses the output of pveversion -v.
func parseVersionOutput(output string, info *Info) {
	scanner := bufio.NewScanner(strings.NewReader(output))

	// Regex patterns for version parsing
	pveVersionRe := regexp.MustCompile(`^pve-manager/(\d+\.\d+[.\d-]*)\s+\(running kernel:\s*([^)]+)\)`)
	releaseRe := regexp.MustCompile(`^proxmox-ve:\s*(\S+)`)

	for scanner.Scan() {
		line := scanner.Text()

		if matches := pveVersionRe.FindStringSubmatch(line); len(matches) >= 3 {
			info.Version = matches[1]
			info.KernelVersion = matches[2]
			continue
		}

		if matches := releaseRe.FindStringSubmatch(line); len(matches) >= 2 {
			info.Release = matches[1]
		}
	}
}

// getClusterName reads the cluster name from corosync configuration.
func getClusterName() string {
	data, err := os.ReadFile(pveClusterConf)
	if err != nil {
		return ""
	}

	// Parse cluster_name from corosync.conf
	re := regexp.MustCompile(`cluster_name:\s*(\S+)`)
	if matches := re.FindStringSubmatch(string(data)); len(matches) >= 2 {
		return matches[1]
	}

	return ""
}

// detectRepositoryType checks which Proxmox repository is configured.
func detectRepositoryType() string {
	// Check for enterprise repository
	if fileContains("/etc/apt/sources.list.d/pve-enterprise.list", "enterprise.proxmox.com") {
		return "enterprise"
	}

	// Check for no-subscription repository
	if fileContains("/etc/apt/sources.list.d/pve-no-subscription.list", "download.proxmox.com") ||
		fileContains("/etc/apt/sources.list", "download.proxmox.com") {
		return "no-subscription"
	}

	// Check for test repository
	if fileContains("/etc/apt/sources.list.d/pvetest-for-beta.list", "download.proxmox.com") {
		return "test"
	}

	return "unknown"
}

// fileContains checks if a file exists and contains a specific string.
func fileContains(path, search string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), search)
}

// IsProxmoxHost is a quick check if the system is a Proxmox host.
func IsProxmoxHost() bool {
	_, err := os.Stat(pveConfigPath)
	return err == nil
}
