// Package hyperv provides PowerShell-based Hyper-V management.
package hyperv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Client provides PowerShell-based Hyper-V management.
type Client struct {
	hostName string
	mu       sync.RWMutex
}

const (
	defaultTimeout = 30 * time.Second
	psShell        = "powershell"
)

var (
	// singleton client instance
	clientInstance *Client
	clientMu       sync.RWMutex
)

// NewClient creates a new Hyper-V client.
func NewClient(ctx context.Context) (*Client, error) {
	clientMu.Lock()
	defer clientMu.Unlock()

	if clientInstance != nil {
		return clientInstance, nil
	}

	// Verify Hyper-V is available
	if !IsHyperVHost() {
		return nil, fmt.Errorf("hyper-v is not available on this host")
	}

	info := Detect(ctx)
	clientInstance = &Client{
		hostName: info.HostName,
	}

	return clientInstance, nil
}

// GetClient returns the singleton client instance.
func GetClient(ctx context.Context) (*Client, error) {
	clientMu.RLock()
	if clientInstance != nil {
		clientMu.RUnlock()
		return clientInstance, nil
	}
	clientMu.RUnlock()

	return NewClient(ctx)
}

// ExecutePS executes a PowerShell command and returns the output.
func (c *Client) ExecutePS(ctx context.Context, command string) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return ExecutePowerShell(ctx, command)
}

// ExecutePSWithJSON executes a PowerShell command and unmarshals JSON output.
func (c *Client) ExecutePSWithJSON(ctx context.Context, command string, result interface{}) error {
	output, err := c.ExecutePS(ctx, command)
	if err != nil {
		return err
	}

	// Handle empty output
	output = bytes.TrimSpace(output)
	if len(output) == 0 {
		return nil
	}

	return json.Unmarshal(output, result)
}

// HostName returns the Hyper-V host name.
func (c *Client) HostName() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hostName
}

// Close cleans up the client (no-op for PowerShell-based client).
func (c *Client) Close() error {
	return nil
}

// ExecutePowerShell executes a PowerShell command and returns the output.
func ExecutePowerShell(ctx context.Context, command string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	cmd := exec.CommandContext(ctx, psShell, "-NoProfile", "-NonInteractive", "-Command", command)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg != "" {
			return nil, fmt.Errorf("powershell error: %s", errMsg)
		}
		return nil, fmt.Errorf("powershell execution failed: %w", err)
	}

	return stdout.Bytes(), nil
}

// ExecutePowerShellWithJSON executes a PowerShell command and unmarshals JSON output.
func ExecutePowerShellWithJSON(ctx context.Context, command string, result interface{}) error {
	output, err := ExecutePowerShell(ctx, command)
	if err != nil {
		return err
	}

	// Handle empty output
	output = bytes.TrimSpace(output)
	if len(output) == 0 {
		return nil
	}

	return json.Unmarshal(output, result)
}

// PSEscape escapes a string for safe use in PowerShell commands.
func PSEscape(s string) string {
	// Escape single quotes by doubling them
	s = strings.ReplaceAll(s, "'", "''")
	return s
}

// PSString wraps a string in single quotes for PowerShell.
func PSString(s string) string {
	return fmt.Sprintf("'%s'", PSEscape(s))
}
