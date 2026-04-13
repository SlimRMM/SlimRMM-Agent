//go:build linux

package security

import (
	"os"
	"os/exec"
	"strings"
)

// CollectSecurityInfo gathers security posture on Linux systems.
func CollectSecurityInfo() *Info {
	info := &Info{}

	collectAntivirusInfo(info)
	collectFirewallInfo(info)
	collectDiskEncryptionInfo(info)
	collectRDPInfo(info)
	collectPasswordPolicyInfo(info)

	return info
}

// collectAntivirusInfo checks if ClamAV or similar antivirus is running.
func collectAntivirusInfo(info *Info) {
	// Check ClamAV daemon
	out, err := exec.Command("systemctl", "is-active", "clamav-daemon").Output()
	if err == nil && strings.TrimSpace(string(out)) == "active" {
		info.AntivirusActive = true
		info.AntivirusName = "ClamAV"
		// Check if freshclam (signature updater) ran recently
		if _, err := exec.Command("systemctl", "is-active", "clamav-freshclam").Output(); err == nil {
			info.AntivirusSignaturesCurrent = true
		}
		return
	}

	// Check clamd alternative service name
	out, err = exec.Command("systemctl", "is-active", "clamd").Output()
	if err == nil && strings.TrimSpace(string(out)) == "active" {
		info.AntivirusActive = true
		info.AntivirusName = "ClamAV"
		return
	}

	// Check Sophos
	out, err = exec.Command("systemctl", "is-active", "savd").Output()
	if err == nil && strings.TrimSpace(string(out)) == "active" {
		info.AntivirusActive = true
		info.AntivirusName = "Sophos"
		return
	}
}

// collectFirewallInfo checks if a firewall is active (ufw, firewalld, or iptables).
func collectFirewallInfo(info *Info) {
	// Check ufw
	out, err := exec.Command("ufw", "status").Output()
	if err == nil {
		output := strings.ToLower(string(out))
		if strings.Contains(output, "active") && !strings.Contains(output, "inactive") {
			info.FirewallActive = true
			return
		}
	}

	// Check firewalld
	out, err = exec.Command("systemctl", "is-active", "firewalld").Output()
	if err == nil && strings.TrimSpace(string(out)) == "active" {
		info.FirewallActive = true
		return
	}

	// Check nftables
	out, err = exec.Command("systemctl", "is-active", "nftables").Output()
	if err == nil && strings.TrimSpace(string(out)) == "active" {
		info.FirewallActive = true
		return
	}

	// Fallback: check iptables for any non-default rules
	out, err = exec.Command("iptables", "-L", "-n", "--line-numbers").Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		ruleCount := 0
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "Chain") && !strings.HasPrefix(trimmed, "num") {
				ruleCount++
			}
		}
		if ruleCount > 0 {
			info.FirewallActive = true
			return
		}
	}
}

// collectDiskEncryptionInfo checks for LUKS-encrypted partitions.
func collectDiskEncryptionInfo(info *Info) {
	out, err := exec.Command("lsblk", "-o", "NAME,TYPE,FSTYPE", "--noheadings").Output()
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(out), "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "crypt") || strings.Contains(lower, "luks") {
			info.DiskEncrypted = true
			info.EncryptionMethod = "LUKS"
			return
		}
	}

	// Also check /etc/crypttab
	if data, err := os.ReadFile("/etc/crypttab"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				info.DiskEncrypted = true
				info.EncryptionMethod = "LUKS"
				return
			}
		}
	}
}

// collectRDPInfo checks if xrdp service is running.
func collectRDPInfo(info *Info) {
	out, err := exec.Command("systemctl", "is-active", "xrdp").Output()
	if err == nil && strings.TrimSpace(string(out)) == "active" {
		info.RDPEnabled = true
	}
}

// collectPasswordPolicyInfo checks PAM configuration for account lockout.
func collectPasswordPolicyInfo(info *Info) {
	// Check common PAM config files for pam_faillock or pam_tally2
	pamFiles := []string{
		"/etc/pam.d/common-auth",
		"/etc/pam.d/system-auth",
		"/etc/pam.d/password-auth",
		"/etc/security/faillock.conf",
	}

	for _, path := range pamFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		content := strings.ToLower(string(data))
		if strings.Contains(content, "pam_faillock") ||
			strings.Contains(content, "pam_tally2") ||
			strings.Contains(content, "deny=") {
			info.PasswordPolicyConfigured = true
			return
		}
	}

	// Check /etc/login.defs for PASS_MAX_DAYS etc.
	if data, err := os.ReadFile("/etc/login.defs"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") || trimmed == "" {
				continue
			}
			if strings.HasPrefix(trimmed, "PASS_MAX_DAYS") {
				fields := strings.Fields(trimmed)
				if len(fields) >= 2 && fields[1] != "99999" {
					info.PasswordPolicyConfigured = true
					return
				}
			}
		}
	}
}
