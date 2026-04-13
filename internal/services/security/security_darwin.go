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
	collectSecureBootInfo(info)
	collectOpenPortsInfo(info)
	collectAuditLoggingInfo(info)
	collectExpiredCertsInfo(info)
	collectRootkitScanInfo(info)

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

// collectSecureBootInfo checks Secure Boot status via nvram.
func collectSecureBootInfo(info *Info) {
	out, err := exec.Command("nvram", "94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy").Output()
	if err != nil {
		return
	}
	// Value of 0x02 means full security, 0x01 means medium, 0x00 means no security
	output := string(out)
	if strings.Contains(output, "%02") || strings.Contains(output, "%01") {
		info.SecureBootEnabled = true
	}
}

// collectOpenPortsInfo counts unexpected listening TCP ports.
func collectOpenPortsInfo(info *Info) {
	out, err := exec.Command("lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n").Output()
	if err != nil {
		return
	}

	commonPorts := map[string]bool{
		"22": true, "80": true, "443": true,
	}

	seen := make(map[string]bool)
	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "COMMAND") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		// Name field (index 8) contains addr:port
		name := fields[8]
		port := name
		if idx := strings.LastIndex(name, ":"); idx >= 0 {
			port = name[idx+1:]
		}
		if !commonPorts[port] && !seen[port] {
			seen[port] = true
			count++
		}
	}
	info.OpenPortsCount = count
}

// collectAuditLoggingInfo checks if the audit daemon is running on macOS.
func collectAuditLoggingInfo(info *Info) {
	out, err := exec.Command("launchctl", "list").Output()
	if err != nil {
		return
	}
	if strings.Contains(string(out), "com.apple.auditd") {
		info.AuditLoggingActive = true
	}
}

// collectExpiredCertsInfo checks the system keychain for expired certificates.
func collectExpiredCertsInfo(info *Info) {
	// Export all certs from System keychain as PEM
	out, err := exec.Command("security", "find-certificate", "-a", "-p", "/Library/Keychains/System.keychain").Output()
	if err != nil {
		return
	}

	// Split into individual PEM blocks and check each
	expired := 0
	certs := strings.Split(string(out), "-----BEGIN CERTIFICATE-----")
	for _, cert := range certs[1:] { // skip first empty element
		pem := "-----BEGIN CERTIFICATE-----" + cert
		cmd := exec.Command("openssl", "x509", "-checkend", "0", "-noout")
		cmd.Stdin = strings.NewReader(pem)
		if err := cmd.Run(); err != nil {
			expired++
		}
	}
	info.ExpiredCertificates = expired
}

// collectRootkitScanInfo is not applicable on macOS; returns defaults.
func collectRootkitScanInfo(info *Info) {
	// Rootkit scanning is not standard on macOS.
	// Leave LastRootkitScan empty and RootkitScanClean as false (default).
}
