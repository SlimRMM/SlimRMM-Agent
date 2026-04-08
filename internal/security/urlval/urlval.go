// Package urlval provides URL validation for security.
// It prevents access to dangerous URL schemes and hosts.
package urlval

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	// ErrInvalidScheme indicates the URL scheme is not allowed.
	ErrInvalidScheme = errors.New("url scheme not allowed")

	// ErrInvalidHost indicates the URL host is not allowed.
	ErrInvalidHost = errors.New("url host not allowed")

	// ErrPrivateIP indicates the URL resolves to a private IP.
	ErrPrivateIP = errors.New("url resolves to private IP address")

	// ErrLocalhost indicates the URL points to localhost.
	ErrLocalhost = errors.New("url points to localhost")

	// ErrInvalidURL indicates the URL is malformed.
	ErrInvalidURL = errors.New("invalid url format")

	// ErrDNSResolutionFailed indicates that DNS resolution failed.
	ErrDNSResolutionFailed = errors.New("dns resolution failed")
)

// AllowedSchemes defines which URL schemes are permitted.
var AllowedSchemes = map[string]bool{
	"http":  true,
	"https": true,
}

// BlockedHosts defines hosts that should never be accessed.
var BlockedHosts = map[string]bool{
	"localhost":        true,
	"127.0.0.1":        true,
	"::1":              true,
	"0.0.0.0":          true,
	"metadata.google.internal":      true, // GCP metadata
	"169.254.169.254":               true, // Cloud metadata endpoints
	"metadata.google.internal.":     true,
}

// Validator provides URL validation functionality.
type Validator struct {
	allowedSchemes  map[string]bool
	blockedHosts    map[string]bool
	blockPrivateIPs bool
	blockLocalhost  bool
}

// Config holds URL validator configuration.
type Config struct {
	AllowedSchemes  map[string]bool
	BlockedHosts    map[string]bool
	BlockPrivateIPs bool // Block private IP ranges (10.x, 172.16-31.x, 192.168.x)
	BlockLocalhost  bool // Block localhost and loopback
}

// DefaultConfig returns secure default configuration.
func DefaultConfig() Config {
	return Config{
		AllowedSchemes:  AllowedSchemes,
		BlockedHosts:    BlockedHosts,
		BlockPrivateIPs: true,
		BlockLocalhost:  true,
	}
}

// New creates a new URL validator with the given configuration.
func New(cfg Config) *Validator {
	return &Validator{
		allowedSchemes:  cfg.AllowedSchemes,
		blockedHosts:    cfg.BlockedHosts,
		blockPrivateIPs: cfg.BlockPrivateIPs,
		blockLocalhost:  cfg.BlockLocalhost,
	}
}

// NewDefault creates a URL validator with default security settings.
func NewDefault() *Validator {
	return New(DefaultConfig())
}

// Validate checks if a URL is safe to access.
func (v *Validator) Validate(rawURL string) error {
	// Parse URL
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}

	// Validate scheme
	scheme := strings.ToLower(u.Scheme)
	if !v.allowedSchemes[scheme] {
		return fmt.Errorf("%w: %s (allowed: http, https)", ErrInvalidScheme, scheme)
	}

	// Extract host without port
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: empty host", ErrInvalidURL)
	}

	// Check blocked hosts
	hostLower := strings.ToLower(host)
	if v.blockedHosts[hostLower] {
		return fmt.Errorf("%w: %s", ErrInvalidHost, host)
	}

	// Check for localhost patterns
	if v.blockLocalhost && isLocalhost(hostLower) {
		return fmt.Errorf("%w: %s", ErrLocalhost, host)
	}

	// Check for private IPs
	if v.blockPrivateIPs {
		// Try to parse as IP directly
		ip := net.ParseIP(host)
		if ip != nil {
			if isPrivateIP(ip) {
				return fmt.Errorf("%w: %s", ErrPrivateIP, host)
			}
		}
	}

	return nil
}

// ValidationResult holds the outcome of a DNS-validated URL check, including
// the resolved IP addresses. Callers must use PinnedTransport (or the
// convenience method PinnedHTTPClient) to ensure the actual HTTP connection
// goes to one of these validated IPs, preventing DNS rebinding attacks.
type ValidationResult struct {
	// ResolvedIPs contains the validated IP addresses the hostname resolved to.
	// Empty when the URL already contained a literal IP address.
	ResolvedIPs []net.IP

	// Host is the original hostname from the URL.
	Host string
}

// PinnedTransport returns an *http.Transport whose DialContext is locked to the
// resolved IPs returned by ValidateWithDNS. This prevents DNS rebinding: the
// HTTP client will connect only to the IPs that were checked, not re-resolve
// the hostname. If ResolvedIPs is empty (the URL used a literal IP), a default
// transport is returned.
func (vr *ValidationResult) PinnedTransport() *http.Transport {
	if len(vr.ResolvedIPs) == 0 {
		return &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		}
	}

	// Round-robin index for multiple IPs
	ips := vr.ResolvedIPs
	host := vr.Host

	return &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// addr is "host:port" — extract port
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address %q: %w", addr, err)
			}

			// Try each validated IP
			var lastErr error
			d := &net.Dialer{Timeout: 30 * time.Second}
			for _, ip := range ips {
				pinnedAddr := net.JoinHostPort(ip.String(), port)
				conn, err := d.DialContext(ctx, network, pinnedAddr)
				if err != nil {
					lastErr = err
					continue
				}
				return conn, nil
			}
			return nil, fmt.Errorf("all validated IPs for %s failed: %w", host, lastErr)
		},
	}
}

// PinnedHTTPClient returns an *http.Client that uses PinnedTransport and the
// given timeout.
func (vr *ValidationResult) PinnedHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: vr.PinnedTransport(),
		Timeout:   timeout,
	}
}

// ValidateWithDNS validates the URL and also checks DNS resolution for private IPs.
// This prevents SSRF attacks where a hostname resolves to a private IP.
// It returns a ValidationResult containing the resolved IPs so that callers can
// pin HTTP connections to those IPs, preventing DNS rebinding attacks.
// On DNS resolution failure the function fails closed (returns an error).
func (v *Validator) ValidateWithDNS(rawURL string) (*ValidationResult, error) {
	// First perform basic validation
	if err := v.Validate(rawURL); err != nil {
		return nil, err
	}

	// Parse URL to get host
	u, _ := url.Parse(rawURL) // Already validated above
	host := u.Hostname()

	if !v.blockPrivateIPs {
		return &ValidationResult{Host: host}, nil
	}

	// Skip DNS check if it's already an IP
	if net.ParseIP(host) != nil {
		return &ValidationResult{Host: host}, nil // Already checked in Validate()
	}

	// Resolve hostname and check all returned IPs
	ips, err := net.LookupIP(host)
	if err != nil {
		// Fail closed: DNS resolution failure must block the request.
		// An attacker could exploit transient DNS failures to bypass validation.
		return nil, fmt.Errorf("%w: %s: %v", ErrDNSResolutionFailed, host, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: %s: no addresses returned", ErrDNSResolutionFailed, host)
	}

	for _, ip := range ips {
		if isPrivateIP(ip) {
			return nil, fmt.Errorf("%w: %s resolves to %s", ErrPrivateIP, host, ip.String())
		}
		if v.blockLocalhost && ip.IsLoopback() {
			return nil, fmt.Errorf("%w: %s resolves to loopback %s", ErrLocalhost, host, ip.String())
		}
	}

	return &ValidationResult{ResolvedIPs: ips, Host: host}, nil
}

// isLocalhost checks if a hostname is localhost or loopback.
func isLocalhost(host string) bool {
	hostLower := strings.ToLower(host)
	if hostLower == "localhost" || hostLower == "localhost." {
		return true
	}
	if strings.HasSuffix(hostLower, ".localhost") || strings.HasSuffix(hostLower, ".localhost.") {
		return true
	}

	// Check for IPv6 loopback
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return true
	}

	return false
}

// isPrivateIP checks if an IP address is in a private range.
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check for IPv4 private ranges
	private4Ranges := []struct {
		start net.IP
		end   net.IP
	}{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
		{net.ParseIP("127.0.0.0"), net.ParseIP("127.255.255.255")},
		{net.ParseIP("169.254.0.0"), net.ParseIP("169.254.255.255")}, // Link-local
	}

	// Convert to IPv4 if possible
	ip4 := ip.To4()
	if ip4 != nil {
		for _, r := range private4Ranges {
			if bytesInRange(ip4, r.start.To4(), r.end.To4()) {
				return true
			}
		}
	}

	// Check IPv6 private addresses
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Check for IPv4-mapped IPv6 addresses
	if ip4 == nil && len(ip) == 16 {
		// Check ::ffff:x.x.x.x format
		if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 &&
			ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
			ip[8] == 0 && ip[9] == 0 && ip[10] == 0xff && ip[11] == 0xff {
			ip4 := ip[12:16]
			for _, r := range private4Ranges {
				if bytesInRange(ip4, r.start.To4(), r.end.To4()) {
					return true
				}
			}
		}
	}

	// Check for unique local addresses (fc00::/7)
	if len(ip) == 16 && (ip[0]&0xfe) == 0xfc {
		return true
	}

	return false
}

// bytesInRange checks if an IP is within a range (inclusive).
func bytesInRange(ip, start, end []byte) bool {
	if len(ip) != len(start) || len(ip) != len(end) {
		return false
	}
	for i := range ip {
		if ip[i] < start[i] || ip[i] > end[i] {
			if ip[i] < start[i] {
				return false
			}
			if ip[i] > end[i] {
				return false
			}
		}
		// If this byte is in range, check next byte
		if ip[i] > start[i] && ip[i] < end[i] {
			return true
		}
	}
	return true
}
