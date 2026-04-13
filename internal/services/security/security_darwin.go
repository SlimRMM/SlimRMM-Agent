//go:build darwin

package security

import (
	"os/exec"
	"strings"
)

// CollectSecurityInfo gathers security posture on macOS systems.
// macOS has limited overlap with Windows/Linux checks, so this provides
// best-effort detection using built-in tools.
func CollectSecurityInfo() *Info {
	info := &Info{}

	collectFirewallInfo(info)
	collectDiskEncryptionInfo(info)
	collectRDPInfo(info)

	return info
}

// collectFirewallInfo checks if macOS application firewall is enabled.
func collectFirewallInfo(info *Info) {
	out, err := exec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate").Output()
	if err != nil {
		return
	}
	if strings.Contains(strings.ToLower(string(out)), "enabled") {
		info.FirewallActive = true
	}
}

// collectDiskEncryptionInfo checks FileVault status.
func collectDiskEncryptionInfo(info *Info) {
	out, err := exec.Command("fdesetup", "status").Output()
	if err != nil {
		return
	}
	if strings.Contains(string(out), "On") {
		info.DiskEncrypted = true
		info.EncryptionMethod = "FileVault"
	}
}

// collectRDPInfo checks if screen sharing / remote management is enabled.
func collectRDPInfo(info *Info) {
	out, err := exec.Command("launchctl", "list").Output()
	if err != nil {
		return
	}
	output := string(out)
	if strings.Contains(output, "com.apple.screensharing") {
		info.RDPEnabled = true
	}
}
