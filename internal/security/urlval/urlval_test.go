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
