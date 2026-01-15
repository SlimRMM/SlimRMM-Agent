// Package helper provides Windows helper process management.
// This file provides stubs for non-Windows platforms.
//go:build !windows

package helper

import (
	"fmt"
	"sync"
)

// Manager provides shared access to a single helper client instance.
// On non-Windows platforms, this is a stub.
type Manager struct{}

var (
	globalManager     *Manager
	globalManagerOnce sync.Once
)

// GetManager returns the singleton helper manager instance.
func GetManager() *Manager {
	globalManagerOnce.Do(func() {
		globalManager = &Manager{}
	})
	return globalManager
}

// Acquire returns an error on non-Windows platforms.
func (m *Manager) Acquire() (*Client, error) {
	return nil, fmt.Errorf("helper not supported on this platform")
}

// Release is a no-op on non-Windows platforms.
func (m *Manager) Release() {}

// ForceStop is a no-op on non-Windows platforms.
func (m *Manager) ForceStop() {}

// IsRunning always returns false on non-Windows platforms.
func (m *Manager) IsRunning() bool {
	return false
}

// RefCount always returns 0 on non-Windows platforms.
func (m *Manager) RefCount() int32 {
	return 0
}

// Reconnect returns an error on non-Windows platforms.
func (m *Manager) Reconnect() (*Client, error) {
	return nil, fmt.Errorf("helper not supported on this platform")
}

// GetClient returns nil on non-Windows platforms.
func (m *Manager) GetClient() *Client {
	return nil
}
