package urlval

import (
	"net"
	"testing"
)

func TestValidator(t *testing.T) {
	v := NewDefault()

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		// Valid URLs
		{"valid https", "https://example.com/file.zip", false},
		{"valid http", "http://example.com/file.zip", false},
		{"valid with port", "https://example.com:8080/file.zip", false},
		{"valid with path", "https://cdn.example.com/downloads/v1/file.zip", false},

		// Invalid schemes
		{"file scheme", "file:///etc/passwd", true},
		{"ftp scheme", "ftp://example.com/file.zip", true},
		{"javascript", "javascript:alert(1)", true},
		{"data scheme", "data:text/html,<script>alert(1)</script>", true},

		// Blocked hosts
		{"localhost", "http://localhost/file", true},
		{"127.0.0.1", "http://127.0.0.1/file", true},
		{"loopback ipv6", "http://[::1]/file", true},
		{"metadata gcp", "http://metadata.google.internal/computeMetadata/v1/", true},
		{"metadata aws", "http://169.254.169.254/latest/meta-data/", true},

		// Private IPs
		{"private 10.x", "http://10.0.0.1/file", true},
		{"private 172.16.x", "http://172.16.0.1/file", true},
		{"private 192.168.x", "http://192.168.1.1/file", true},

		// Invalid URLs
		{"empty", "", true},
		{"no scheme", "example.com/file", true},
		{"malformed", "http://", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip        string
		isPrivate bool
	}{
		// Private IPv4
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		{"127.0.0.1", true},
		{"169.254.1.1", true},

		// Public IPv4
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"203.0.113.1", false},
		{"198.51.100.1", false},

		// Edge cases
		{"172.15.255.255", false}, // Just below private range
		{"172.32.0.0", false},     // Just above private range
		{"11.0.0.0", false},       // Just above 10.x range
		{"9.255.255.255", false},  // Just below 10.x range
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := parseIPHelper(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}
			got := isPrivateIP(ip)
			if got != tt.isPrivate {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.isPrivate)
			}
		})
	}
}

func TestIsLocalhost(t *testing.T) {
	tests := []struct {
		host        string
		isLocalhost bool
	}{
		{"localhost", true},
		{"localhost.", true},
		{"sub.localhost", true},
		{"LOCALHOST", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"example.com", false},
		{"localhostfake.com", false},
		{"notlocalhost", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := isLocalhost(tt.host)
			if got != tt.isLocalhost {
				t.Errorf("isLocalhost(%s) = %v, want %v", tt.host, got, tt.isLocalhost)
			}
		})
	}
}

func TestCustomConfig(t *testing.T) {
	// Test with custom configuration that allows more
	cfg := Config{
		AllowedSchemes:  map[string]bool{"https": true, "ftp": true},
		BlockedHosts:    map[string]bool{},
		BlockPrivateIPs: false,
		BlockLocalhost:  false,
	}

	v := New(cfg)

	// FTP should now be allowed
	if err := v.Validate("ftp://example.com/file.zip"); err != nil {
		t.Errorf("ftp should be allowed with custom config: %v", err)
	}

	// Private IPs should be allowed
	if err := v.Validate("https://192.168.1.1/file"); err != nil {
		t.Errorf("private IP should be allowed with custom config: %v", err)
	}

	// Localhost should be allowed
	if err := v.Validate("https://localhost/file"); err != nil {
		t.Errorf("localhost should be allowed with custom config: %v", err)
	}
}

// Helper to parse IP for testing
func parseIPHelper(s string) net.IP {
	return net.ParseIP(s)
}

func TestValidateWithDNS(t *testing.T) {
	v := NewDefault()

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		// Valid external URLs
		{"valid https", "https://example.com/file.zip", false},
		{"valid with subdomain", "https://cdn.example.com/file", false},

		// Direct IP addresses (already checked in Validate)
		{"direct public IP", "https://8.8.8.8/dns", false},
		{"direct private IP", "https://192.168.1.1/file", true},

		// Invalid schemes still caught
		{"file scheme", "file:///etc/passwd", true},

		// Blocked hosts still caught
		{"localhost", "http://localhost/file", true},
		{"metadata endpoint", "http://169.254.169.254/", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateWithDNS(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateWithDNS(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestValidateWithDNS_NoPrivateIPCheck(t *testing.T) {
	cfg := Config{
		AllowedSchemes:  AllowedSchemes,
		BlockedHosts:    BlockedHosts,
		BlockPrivateIPs: false,
		BlockLocalhost:  true,
	}
	v := New(cfg)

	// With BlockPrivateIPs=false, private IPs should be allowed
	err := v.ValidateWithDNS("https://192.168.1.1/file")
	if err != nil {
		t.Errorf("private IP should be allowed when BlockPrivateIPs=false: %v", err)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.BlockPrivateIPs {
		t.Error("DefaultConfig should block private IPs")
	}
	if !cfg.BlockLocalhost {
		t.Error("DefaultConfig should block localhost")
	}
	if !cfg.AllowedSchemes["http"] || !cfg.AllowedSchemes["https"] {
		t.Error("DefaultConfig should allow http and https")
	}
	if len(cfg.BlockedHosts) == 0 {
		t.Error("DefaultConfig should have blocked hosts")
	}
}

func TestIsPrivateIP_IPv6(t *testing.T) {
	tests := []struct {
		ip        string
		isPrivate bool
	}{
		// IPv6 loopback
		{"::1", true},

		// IPv6 link-local
		{"fe80::1", true},

		// IPv6 unique local (fc00::/7)
		{"fc00::1", true},
		{"fd00::1", true},

		// IPv6 public addresses
		{"2001:4860:4860::8888", false}, // Google DNS
		{"2606:4700:4700::1111", false}, // Cloudflare DNS

		// IPv4-mapped IPv6 addresses
		{"::ffff:192.168.1.1", true},  // Private
		{"::ffff:10.0.0.1", true},     // Private
		{"::ffff:8.8.8.8", false},     // Public
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := parseIPHelper(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}
			got := isPrivateIP(ip)
			if got != tt.isPrivate {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.isPrivate)
			}
		})
	}
}

func TestIsPrivateIP_NilIP(t *testing.T) {
	if isPrivateIP(nil) {
		t.Error("isPrivateIP(nil) should return false")
	}
}

func TestBytesInRange(t *testing.T) {
	tests := []struct {
		name     string
		ip       []byte
		start    []byte
		end      []byte
		expected bool
	}{
		{"in range middle", []byte{10, 0, 0, 50}, []byte{10, 0, 0, 0}, []byte{10, 0, 0, 255}, true},
		{"at start", []byte{10, 0, 0, 0}, []byte{10, 0, 0, 0}, []byte{10, 0, 0, 255}, true},
		{"at end", []byte{10, 0, 0, 255}, []byte{10, 0, 0, 0}, []byte{10, 0, 0, 255}, true},
		{"before range", []byte{9, 255, 255, 255}, []byte{10, 0, 0, 0}, []byte{10, 255, 255, 255}, false},
		{"after range", []byte{11, 0, 0, 0}, []byte{10, 0, 0, 0}, []byte{10, 255, 255, 255}, false},
		{"different lengths", []byte{10, 0, 0}, []byte{10, 0, 0, 0}, []byte{10, 0, 0, 255}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bytesInRange(tt.ip, tt.start, tt.end)
			if got != tt.expected {
				t.Errorf("bytesInRange(%v, %v, %v) = %v, want %v",
					tt.ip, tt.start, tt.end, got, tt.expected)
			}
		})
	}
}

func TestErrorTypes(t *testing.T) {
	// Verify error types are defined and have messages
	errors := []error{
		ErrInvalidScheme,
		ErrInvalidHost,
		ErrPrivateIP,
		ErrLocalhost,
		ErrInvalidURL,
	}

	for _, err := range errors {
		if err == nil {
			t.Error("error should not be nil")
		}
		if err.Error() == "" {
			t.Errorf("error %v should have a message", err)
		}
	}
}

func TestAllowedSchemes(t *testing.T) {
	if !AllowedSchemes["http"] {
		t.Error("http should be in AllowedSchemes")
	}
	if !AllowedSchemes["https"] {
		t.Error("https should be in AllowedSchemes")
	}
	if AllowedSchemes["ftp"] {
		t.Error("ftp should not be in AllowedSchemes")
	}
}

func TestBlockedHosts(t *testing.T) {
	expectedBlocked := []string{
		"localhost",
		"127.0.0.1",
		"::1",
		"0.0.0.0",
		"metadata.google.internal",
		"169.254.169.254",
	}

	for _, host := range expectedBlocked {
		if !BlockedHosts[host] {
			t.Errorf("%s should be in BlockedHosts", host)
		}
	}
}

func TestNewDefault(t *testing.T) {
	v := NewDefault()
	if v == nil {
		t.Fatal("NewDefault() returned nil")
	}

	// Should block localhost
	if err := v.Validate("https://localhost/file"); err == nil {
		t.Error("NewDefault validator should block localhost")
	}

	// Should allow public URLs
	if err := v.Validate("https://example.com/file"); err != nil {
		t.Errorf("NewDefault validator should allow public URLs: %v", err)
	}
}

func TestValidate_EmptyHost(t *testing.T) {
	v := NewDefault()

	// URL with no host after scheme
	err := v.Validate("https:///path/file")
	if err == nil {
		t.Error("should reject URL with empty host")
	}
}

func TestValidate_CaseInsensitiveScheme(t *testing.T) {
	v := NewDefault()

	tests := []string{
		"HTTPS://example.com/file",
		"Https://example.com/file",
		"HtTpS://example.com/file",
	}

	for _, url := range tests {
		t.Run(url, func(t *testing.T) {
			err := v.Validate(url)
			if err != nil {
				t.Errorf("should accept case-insensitive scheme: %v", err)
			}
		})
	}
}

func TestValidate_CaseInsensitiveHost(t *testing.T) {
	v := NewDefault()

	tests := []string{
		"https://LOCALHOST/file",
		"https://Localhost/file",
		"https://LocalHost/file",
	}

	for _, url := range tests {
		t.Run(url, func(t *testing.T) {
			err := v.Validate(url)
			if err == nil {
				t.Error("should block localhost regardless of case")
			}
		})
	}
}
