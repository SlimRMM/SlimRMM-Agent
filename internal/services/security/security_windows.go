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
	collectSecureBootInfo(info)
	collectOpenPortsInfo(info)
	collectAuditLoggingInfo(info)
	collectExpiredCertsInfo(info)
	collectRootkitScanInfo(info)

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

// collectSecureBootInfo checks if Secure Boot is enabled via PowerShell.
func collectSecureBootInfo(info *Info) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`try { Confirm-SecureBootUEFI } catch { "False" }`).Output()
	if err != nil {
		return
	}
	if strings.TrimSpace(string(out)) == "True" {
		info.SecureBootEnabled = true
	}
}

// collectOpenPortsInfo counts listening ports not in the standard allowlist.
func collectOpenPortsInfo(info *Info) {
	out, err := exec.Command("netstat", "-an").Output()
	if err != nil {
		return
	}

	allowlist := map[string]bool{
		"80": true, "443": true, "445": true, "135": true,
	}
	// If RDP is enabled, allow port 3389
	// We check the already-collected RDP field via a separate reg query here
	// to keep this function self-contained.
	rdpOut, err := exec.Command("reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`,
		"/v", "fDenyTSConnections").Output()
	if err == nil && strings.Contains(string(rdpOut), "0x0") {
		allowlist["3389"] = true
	}

	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "LISTENING") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		local := fields[1]
		port := local
		if idx := strings.LastIndex(local, ":"); idx >= 0 {
			port = local[idx+1:]
		}
		if !allowlist[port] {
			count++
		}
	}
	info.OpenPortsCount = count
}

// collectAuditLoggingInfo checks if the Windows Event Log service is running
// and the Security log has events.
func collectAuditLoggingInfo(info *Info) {
	// Check if EventLog service is running
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`(Get-Service -Name EventLog -ErrorAction SilentlyContinue).Status`).Output()
	if err != nil {
		return
	}
	if strings.TrimSpace(string(out)) != "Running" {
		return
	}

	// Check if Security log has any entries
	out, err = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`(Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue) -ne $null`).Output()
	if err != nil {
		return
	}
	if strings.TrimSpace(string(out)) == "True" {
		info.AuditLoggingActive = true
	}
}

// collectExpiredCertsInfo counts expired certificates in the local machine store.
func collectExpiredCertsInfo(info *Info) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`@(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object { $_.NotAfter -lt (Get-Date) }).Count`).
		Output()
	if err != nil {
		return
	}
	count, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return
	}
	info.ExpiredCertificates = count
}

// collectRootkitScanInfo checks Windows Defender's last scan date.
func collectRootkitScanInfo(info *Info) {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`$status = Get-MpComputerStatus -ErrorAction SilentlyContinue; `+
			`if ($status) { "$($status.FullScanEndTime)|$($status.FullScanAge)" }`).Output()
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

	scanTime := strings.TrimSpace(parts[0])
	if scanTime != "" && scanTime != "01/01/0001 00:00:00" {
		info.LastRootkitScan = scanTime
		info.RootkitScanClean = true // If Defender completed a scan, assume clean unless threats found
	}

	// Check if there are active threats
	threatOut, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`(Get-MpThreatDetection -ErrorAction SilentlyContinue | Measure-Object).Count`).Output()
	if err == nil {
		count, err := strconv.Atoi(strings.TrimSpace(string(threatOut)))
		if err == nil && count > 0 {
			info.RootkitScanClean = false
		}
	}
}
