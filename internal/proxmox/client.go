// Package proxmox provides a client wrapper for Proxmox API access.
package proxmox

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/luthermonson/go-proxmox"
)

// Client wraps the Proxmox API client with automatic token management.
type Client struct {
	client    *proxmox.Client
	nodeName  string
	configDir string
	mu        sync.RWMutex
}

const (
	defaultAPIPort    = 8006
	clientTimeout     = 30 * time.Second
	localAPIURL       = "https://127.0.0.1:8006/api2/json"
)

// ErrTokenNotConfigured is returned when no API token is available.
var ErrTokenNotConfigured = fmt.Errorf("proxmox API token not configured")

// NewClient creates a new Proxmox client with the configured token.
// Returns ErrTokenNotConfigured if no token has been set up.
func NewClient(ctx context.Context, configDir string) (*Client, error) {
	// Load existing token (don't auto-create)
	token := LoadToken(configDir)
	if token == nil {
		return nil, ErrTokenNotConfigured
	}

	// Create HTTP client with TLS configuration
	// SECURITY: InsecureSkipVerify is only used for localhost (127.0.0.1:8006)
	// connections to the local Proxmox API which typically uses self-signed certs.
	// This is acceptable because:
	// 1. The connection never leaves the local machine
	// 2. An attacker with localhost access already has full system access
	httpClient := &http.Client{
		Timeout: clientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // #nosec G402 - localhost only
				MinVersion:         tls.VersionTLS13,
			},
		},
	}

	// Create Proxmox client
	client := proxmox.NewClient(localAPIURL,
		proxmox.WithHTTPClient(httpClient),
		proxmox.WithAPIToken(token.TokenID, token.Secret),
	)

	// Get local node name
	info := Detect(ctx)
	nodeName := info.NodeName
	if nodeName == "" {
		// Fallback: try to get from API
		version, err := client.Version(ctx)
		if err == nil && version != nil {
			nodeName = "localhost"
		}
	}

	return &Client{
		client:    client,
		nodeName:  nodeName,
		configDir: configDir,
	}, nil
}

// GetNode returns the local Proxmox node.
func (c *Client) GetNode(ctx context.Context) (*proxmox.Node, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.client.Node(ctx, c.nodeName)
}

// GetNodes returns all nodes in the cluster.
func (c *Client) GetNodes(ctx context.Context) ([]*proxmox.Node, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Get list of all node statuses
	nodeStatuses, err := c.client.Nodes(ctx)
	if err != nil {
		// Fallback: return local node only
		node, err := c.client.Node(ctx, c.nodeName)
		if err != nil {
			return nil, err
		}
		return []*proxmox.Node{node}, nil
	}

	// Convert NodeStatuses to []*Node by fetching each node
	nodes := make([]*proxmox.Node, 0, len(nodeStatuses))
	for _, ns := range nodeStatuses {
		node, err := c.client.Node(ctx, ns.Node)
		if err != nil {
			continue // Skip nodes we can't access
		}
		nodes = append(nodes, node)
	}

	if len(nodes) == 0 {
		// Fallback: at least return local node
		node, err := c.client.Node(ctx, c.nodeName)
		if err != nil {
			return nil, err
		}
		return []*proxmox.Node{node}, nil
	}

	return nodes, nil
}

// GetVersion returns the Proxmox version information.
func (c *Client) GetVersion(ctx context.Context) (*proxmox.Version, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.client.Version(ctx)
}

// GetClusterStatus returns cluster status information.
func (c *Client) GetClusterStatus(ctx context.Context) (proxmox.NodeStatuses, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.client.Nodes(ctx)
}

// Close cleans up the client resources.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// No cleanup needed for HTTP client
	return nil
}

// NodeName returns the local node name.
func (c *Client) NodeName() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nodeName
}

// RefreshToken recreates the API token.
func (c *Client) RefreshToken(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Clear cached token
	ClearCachedToken()

	// Delete and recreate token
	if err := DeleteToken(ctx, c.configDir); err != nil {
		return err
	}

	// Get new token
	token, err := GetOrCreateToken(ctx, c.configDir)
	if err != nil {
		return err
	}

	// Create new HTTP client (localhost only - see NewClient for security rationale)
	httpClient := &http.Client{
		Timeout: clientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // #nosec G402 - localhost only
				MinVersion:         tls.VersionTLS13,
			},
		},
	}

	// Recreate Proxmox client with new token
	c.client = proxmox.NewClient(localAPIURL,
		proxmox.WithHTTPClient(httpClient),
		proxmox.WithAPIToken(token.TokenID, token.Secret),
	)

	return nil
}
