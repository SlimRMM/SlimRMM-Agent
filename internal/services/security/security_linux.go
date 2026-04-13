//go:build linux

package security

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
	"time"
)

// CollectSecurityInfo gathers security posture on Linux systems.
func CollectSecurityInfo() *Info {
	info := &Info{}

	collectAntivirusInfo(info)
	collectFirewallInfo(info)
	collectDiskEncryptionInfo(info)
	collectRDPInfo(info)
	collectPasswordPolicyInfo(info)
	collectSecureBootInfo(info)
	collectOpenPortsInfo(info)
	collectAuditLoggingInfo(info)
	collectExpiredCertsInfo(info)
	collectRootkitScanInfo(info)

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

// collectSecureBootInfo checks if Secure Boot is enabled.
func collectSecureBootInfo(info *Info) {
	// Try mokutil first
	out, err := exec.Command("mokutil", "--sb-state").Output()
	if err == nil {
		if strings.Contains(strings.ToLower(string(out)), "secureboot enabled") {
			info.SecureBootEnabled = true
			return
		}
	}

	// Fallback: check if EFI firmware directory exists (indicates UEFI boot)
	if _, err := os.Stat("/sys/firmware/efi"); err == nil {
		// EFI exists; check secure boot variable
		data, err := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
		if err == nil && len(data) >= 5 && data[4] == 1 {
			info.SecureBootEnabled = true
		}
	}
}

// collectOpenPortsInfo counts unexpected listening ports.
func collectOpenPortsInfo(info *Info) {
	out, err := exec.Command("ss", "-tlnH").Output()
	if err != nil {
		return
	}

	commonPorts := map[string]bool{
		"22": true, "80": true, "443": true,
	}

	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// Local address is field 3 (0-indexed), format addr:port or [addr]:port
		local := fields[3]
		port := local
		if idx := strings.LastIndex(local, ":"); idx >= 0 {
			port = local[idx+1:]
		}
		if !commonPorts[port] {
			count++
		}
	}
	info.OpenPortsCount = count
}

// collectAuditLoggingInfo checks if auditd or rsyslog is active.
func collectAuditLoggingInfo(info *Info) {
	for _, svc := range []string{"auditd", "rsyslog", "syslog"} {
		out, err := exec.Command("systemctl", "is-active", svc).Output()
		if err == nil && strings.TrimSpace(string(out)) == "active" {
			info.AuditLoggingActive = true
			return
		}
	}
}

// collectExpiredCertsInfo counts expired certificates in /etc/ssl/certs/.
func collectExpiredCertsInfo(info *Info) {
	entries, err := os.ReadDir("/etc/ssl/certs")
	if err != nil {
		return
	}

	expired := 0
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".pem") && !strings.HasSuffix(entry.Name(), ".crt")) {
			continue
		}
		path := "/etc/ssl/certs/" + entry.Name()
		// openssl x509 -checkend 0 exits non-zero if cert has expired
		err := exec.Command("openssl", "x509", "-in", path, "-checkend", "0", "-noout").Run()
		if err != nil {
			expired++
		}
	}
	info.ExpiredCertificates = expired
}

// collectRootkitScanInfo checks for rkhunter or chkrootkit and their last scan.
func collectRootkitScanInfo(info *Info) {
	// Check rkhunter log
	if fi, err := os.Stat("/var/log/rkhunter.log"); err == nil {
		info.LastRootkitScan = fi.ModTime().UTC().Format(time.RFC3339)
		// Check if last run was clean
		if f, err := os.Open("/var/log/rkhunter.log"); err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			lastResult := ""
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, "System checks summary") || strings.Contains(line, "No warnings found") || strings.Contains(line, "Warning") {
					lastResult = line
				}
			}
			info.RootkitScanClean = strings.Contains(lastResult, "No warnings found") || !strings.Contains(lastResult, "Warning")
		}
		return
	}

	// Check chkrootkit log
	if fi, err := os.Stat("/var/log/chkrootkit.log"); err == nil {
		info.LastRootkitScan = fi.ModTime().UTC().Format(time.RFC3339)
		data, err := os.ReadFile("/var/log/chkrootkit.log")
		if err == nil {
			info.RootkitScanClean = !strings.Contains(string(data), "INFECTED")
		}
	}
}
