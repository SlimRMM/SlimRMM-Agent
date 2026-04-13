//go:build windows

package security

import (
	"os/exec"
	"strconv"
	"strings"
)

// CollectSecurityInfo gathers security posture on Windows systems.
func CollectSecurityInfo() *Info {
	info := &Info{}

	collectAntivirusInfo(info)
	collectFirewallInfo(info)
	collectDiskEncryptionInfo(info)
	collectRDPInfo(info)
	collectPasswordPolicyInfo(info)

	return info
}

// collectAntivirusInfo queries WMI SecurityCenter2 for antivirus products.
// The productState is a bitmask: bits 12-8 indicate signature status,
// bits 15-12 indicate enabled/disabled status.
func collectAntivirusInfo(info *Info) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | `+
			`Select-Object -First 1 displayName, productState | `+
			`ForEach-Object { "$($_.displayName)|$($_.productState)" }`).
		Output()
	if err != nil {
		return
	}

	line := strings.TrimSpace(string(out))
	if line == "" {
		return
	}

	parts := strings.SplitN(line, "|", 2)
	if len(parts) != 2 {
		return
	}

	info.AntivirusName = strings.TrimSpace(parts[0])

	productState, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
	if err != nil {
		return
	}

	// Bit 12 (0x1000): product enabled
	info.AntivirusActive = (productState & 0x1000) != 0
	// Bit 4 (0x10): signatures up to date (when 0, signatures are current)
	info.AntivirusSignaturesCurrent = (productState & 0x10) == 0
}

// collectFirewallInfo checks Windows Firewall status using netsh.
func collectFirewallInfo(info *Info) {
	out, err := exec.Command("netsh", "advfirewall", "show", "allprofiles", "state").Output()
	if err != nil {
		return
	}

	// If any profile shows "ON", firewall is considered active.
	output := strings.ToUpper(string(out))
	info.FirewallActive = strings.Contains(output, "ON")
}

// collectDiskEncryptionInfo checks BitLocker status on the system drive.
func collectDiskEncryptionInfo(info *Info) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`$vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue; `+
			`if ($vol) { "$($vol.ProtectionStatus)" } else { "NotAvailable" }`).
		Output()
	if err != nil {
		return
	}

	status := strings.TrimSpace(string(out))
	if status == "On" || status == "1" {
		info.DiskEncrypted = true
		info.EncryptionMethod = "BitLocker"
	}
}

// collectRDPInfo checks if Remote Desktop is enabled via registry.
func collectRDPInfo(info *Info) {
	out, err := exec.Command("reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`,
		"/v", "fDenyTSConnections").Output()
	if err != nil {
		return
	}

	output := strings.TrimSpace(string(out))
	// fDenyTSConnections = 0 means RDP is enabled
	// fDenyTSConnections = 1 means RDP is disabled
	if strings.Contains(output, "0x0") {
		info.RDPEnabled = true
	}
}

// collectPasswordPolicyInfo checks if a password lockout policy is configured.
func collectPasswordPolicyInfo(info *Info) {
	out, err := exec.Command("net", "accounts").Output()
	if err != nil {
		return
	}

	output := string(out)
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(line)
		// Check for lockout threshold > 0
		if strings.Contains(lower, "lockout threshold") || strings.Contains(lower, "sperrschwelle") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				if val != "" && val != "0" && !strings.EqualFold(val, "never") && !strings.EqualFold(val, "nie") {
					info.PasswordPolicyConfigured = true
					return
				}
			}
		}
	}
}
