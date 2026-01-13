// Package helper provides helper process management.
// This stub is for non-Windows platforms where the helper is not needed.
//go:build !windows

package helper

import "fmt"

// Client is a no-op on non-Windows platforms
type Client struct{}

// Monitor information
type Monitor struct {
	ID      int  `json:"id"`
	Left    int  `json:"left"`
	Top     int  `json:"top"`
	Width   int  `json:"width"`
	Height  int  `json:"height"`
	Primary bool `json:"primary"`
}

// FrameResponse contains captured frame metadata
type FrameResponse struct {
	Width    int    `json:"width"`
	Height   int    `json:"height"`
	Format   string `json:"format"`
	DataSize int    `json:"data_size"`
}

// InputEvent represents mouse/keyboard input
type InputEvent struct {
	Type   string `json:"type"`
	X      int    `json:"x,omitempty"`
	Y      int    `json:"y,omitempty"`
	Button int    `json:"button,omitempty"`
	Key    string `json:"key,omitempty"`
	DeltaX int    `json:"delta_x,omitempty"`
	DeltaY int    `json:"delta_y,omitempty"`
}

// WingetUpdate represents an available winget update
type WingetUpdate struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	Version   string `json:"version"`
	Available string `json:"available"`
	Source    string `json:"source"`
}

// WingetScanResult contains the winget scan results
type WingetScanResult struct {
	Updates []WingetUpdate `json:"updates"`
	Error   string         `json:"error,omitempty"`
}

// NewClient creates a new helper client
func NewClient() *Client {
	return &Client{}
}

// Start is a no-op on non-Windows
func (c *Client) Start() error {
	return fmt.Errorf("helper not supported on this platform")
}

// Stop is a no-op on non-Windows
func (c *Client) Stop() error {
	return nil
}

// IsConnected always returns false on non-Windows
func (c *Client) IsConnected() bool {
	return false
}

// Ping is a no-op on non-Windows
func (c *Client) Ping() error {
	return fmt.Errorf("helper not supported on this platform")
}

// GetMonitors is a no-op on non-Windows
func (c *Client) GetMonitors() ([]Monitor, error) {
	return nil, fmt.Errorf("helper not supported on this platform")
}

// CaptureScreen is a no-op on non-Windows
func (c *Client) CaptureScreen(monitorID, quality int, scale float64) ([]byte, *FrameResponse, error) {
	return nil, nil, fmt.Errorf("helper not supported on this platform")
}

// SendInput is a no-op on non-Windows
func (c *Client) SendInput(event InputEvent) error {
	return fmt.Errorf("helper not supported on this platform")
}

// Reconnect is a no-op on non-Windows
func (c *Client) Reconnect() error {
	return fmt.Errorf("helper not supported on this platform")
}

// ScanWingetUpdates is a no-op on non-Windows
func (c *Client) ScanWingetUpdates() (*WingetScanResult, error) {
	return nil, fmt.Errorf("helper not supported on this platform")
}
