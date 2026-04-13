// Package security provides system security information collection
// for heartbeat reporting across different operating systems.
package security

// Info contains the security posture of the system.
type Info struct {
	AntivirusActive           bool   `json:"antivirus_active"`
	AntivirusName             string `json:"antivirus_name,omitempty"`
	AntivirusSignaturesCurrent bool  `json:"antivirus_signatures_current"`
	FirewallActive            bool   `json:"firewall_active"`
	DiskEncrypted             bool   `json:"disk_encrypted"`
	EncryptionMethod          string `json:"encryption_method,omitempty"`
	RDPEnabled                bool   `json:"rdp_enabled"`
	PasswordPolicyConfigured  bool   `json:"password_policy_configured"`
}

// CollectSecurityInfo gathers security information for the current platform.
// This is declared per-platform via build tags.
// If any check fails, the corresponding field is set to false with empty details
// rather than returning an error.
