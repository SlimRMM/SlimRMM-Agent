// Package helper provides Windows helper process management.
// This file implements a singleton manager for the helper client.
//go:build windows

package helper

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// Manager provides shared access to a single helper client instance.
// This prevents race conditions where multiple operations try to start
// their own helper processes simultaneously.
type Manager struct {
	mu           sync.RWMutex
	client       *Client
	refCount     int32 // Number of active users
	idleTimeout  time.Duration
	idleTimer    *time.Timer
	shuttingDown atomic.Bool
}

var (
	globalManager     *Manager
	globalManagerOnce sync.Once
)

// GetManager returns the singleton helper manager instance.
func GetManager() *Manager {
	globalManagerOnce.Do(func() {
		globalManager = &Manager{
			idleTimeout: 30 * time.Second, // Stop helper after 30s of idle
		}
	})
	return globalManager
}

// Acquire gets a reference to the shared helper client.
// The caller must call Release() when done.
// Returns the client and any error from starting the helper.
func (m *Manager) Acquire() (*Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Cancel any pending idle shutdown
	if m.idleTimer != nil {
		m.idleTimer.Stop()
		m.idleTimer = nil
	}

	// Check if shutting down
	if m.shuttingDown.Load() {
		// Wait for shutdown to complete
		m.mu.Unlock()
		time.Sleep(500 * time.Millisecond)
		m.mu.Lock()
		m.shuttingDown.Store(false)
	}

	// Start client if not already running
	if m.client == nil {
		m.client = NewClient()
		if err := m.client.Start(); err != nil {
			m.client = nil
			return nil, err
		}
		log.Printf("[HELPER-MANAGER] Started new helper client")
	}

	// Increment reference count
	atomic.AddInt32(&m.refCount, 1)
	log.Printf("[HELPER-MANAGER] Acquired helper, refCount=%d", atomic.LoadInt32(&m.refCount))

	return m.client, nil
}

// Release decrements the reference count.
// When no users remain, the helper will be stopped after idle timeout.
func (m *Manager) Release() {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := atomic.AddInt32(&m.refCount, -1)
	log.Printf("[HELPER-MANAGER] Released helper, refCount=%d", count)

	if count <= 0 {
		atomic.StoreInt32(&m.refCount, 0)
		// Schedule idle shutdown
		m.scheduleIdleShutdown()
	}
}

// scheduleIdleShutdown schedules the helper to be stopped after idle timeout.
// Must be called with mu held.
func (m *Manager) scheduleIdleShutdown() {
	if m.idleTimer != nil {
		m.idleTimer.Stop()
	}

	m.idleTimer = time.AfterFunc(m.idleTimeout, func() {
		m.mu.Lock()
		defer m.mu.Unlock()

		// Double-check refCount is still 0
		if atomic.LoadInt32(&m.refCount) > 0 {
			return
		}

		if m.client != nil {
			log.Printf("[HELPER-MANAGER] Stopping idle helper client")
			m.shuttingDown.Store(true)
			m.client.Stop()
			m.client = nil
			m.shuttingDown.Store(false)
		}
	})
}

// ForceStop immediately stops the helper client.
// Use this during agent shutdown.
func (m *Manager) ForceStop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.idleTimer != nil {
		m.idleTimer.Stop()
		m.idleTimer = nil
	}

	if m.client != nil {
		log.Printf("[HELPER-MANAGER] Force stopping helper client")
		m.client.Stop()
		m.client = nil
	}

	atomic.StoreInt32(&m.refCount, 0)
}

// IsRunning returns whether the helper client is currently active.
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.client != nil && m.client.IsConnected()
}

// RefCount returns the current reference count (for debugging).
func (m *Manager) RefCount() int32 {
	return atomic.LoadInt32(&m.refCount)
}

// Reconnect attempts to reconnect the helper client.
// This is safe to call from any user - it will only reconnect once.
// Returns the new client after reconnection.
func (m *Manager) Reconnect() (*Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.client == nil {
		return nil, fmt.Errorf("no client to reconnect")
	}

	// Check if client is still connected
	if m.client.IsConnected() {
		return m.client, nil // Already connected, no need to reconnect
	}

	log.Printf("[HELPER-MANAGER] Reconnecting helper client")

	// Stop the old client
	m.client.Stop()

	// Create and start a new client
	m.client = NewClient()
	if err := m.client.Start(); err != nil {
		m.client = nil
		return nil, fmt.Errorf("reconnect failed: %w", err)
	}

	log.Printf("[HELPER-MANAGER] Reconnected helper client successfully")
	return m.client, nil
}

// GetClient returns the current client without affecting ref count.
// Use this only if you already have an active reference via Acquire().
func (m *Manager) GetClient() *Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.client
}
