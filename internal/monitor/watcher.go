// Package monitor provides system monitoring capabilities including change detection.
package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// ChangeType represents the type of inventory change.
type ChangeType string

const (
	ChangeInstalled ChangeType = "installed"
	ChangeRemoved   ChangeType = "removed"
	ChangeUpdated   ChangeType = "updated"
	ChangeStarted   ChangeType = "started"
	ChangeStopped   ChangeType = "stopped"
	ChangeModified  ChangeType = "modified"
)

// SoftwareChange represents a change in installed software.
type SoftwareChange struct {
	Type       ChangeType `json:"type"`
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	OldVersion string     `json:"old_version,omitempty"`
	Timestamp  int64      `json:"timestamp"`
}

// ServiceChange represents a change in service state.
type ServiceChange struct {
	Type      ChangeType `json:"type"`
	Name      string     `json:"name"`
	OldState  string     `json:"old_state,omitempty"`
	NewState  string     `json:"new_state"`
	Timestamp int64      `json:"timestamp"`
}

// SoftwareItem represents an installed software item for hashing.
type SoftwareItem struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ServiceItem represents a service state for tracking.
type ServiceItem struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Status string `json:"status"`
}

// InventoryWatcher monitors for inventory changes and pushes updates.
type InventoryWatcher struct {
	mu sync.RWMutex

	// Software tracking
	softwareHash  string
	lastSoftware  map[string]SoftwareItem
	softwareCheck time.Duration

	// Service tracking
	serviceHash  string
	lastServices map[string]ServiceItem
	serviceCheck time.Duration

	// Callbacks
	onSoftwareChange func(changes []SoftwareChange)
	onServiceChange  func(changes []ServiceChange)

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// WatcherConfig configures the inventory watcher.
type WatcherConfig struct {
	SoftwareCheckInterval time.Duration
	ServiceCheckInterval  time.Duration
}

// DefaultWatcherConfig returns default watcher configuration.
func DefaultWatcherConfig() WatcherConfig {
	return WatcherConfig{
		SoftwareCheckInterval: 5 * time.Minute,
		ServiceCheckInterval:  1 * time.Minute,
	}
}

// NewInventoryWatcher creates a new inventory watcher.
func NewInventoryWatcher(cfg WatcherConfig) *InventoryWatcher {
	ctx, cancel := context.WithCancel(context.Background())
	return &InventoryWatcher{
		softwareCheck: cfg.SoftwareCheckInterval,
		serviceCheck:  cfg.ServiceCheckInterval,
		lastSoftware:  make(map[string]SoftwareItem),
		lastServices:  make(map[string]ServiceItem),
		ctx:           ctx,
		cancel:        cancel,
	}
}

// SetSoftwareCallback sets the callback for software changes.
func (w *InventoryWatcher) SetSoftwareCallback(cb func(changes []SoftwareChange)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onSoftwareChange = cb
}

// SetServiceCallback sets the callback for service changes.
func (w *InventoryWatcher) SetServiceCallback(cb func(changes []ServiceChange)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onServiceChange = cb
}

// Start begins watching for inventory changes.
func (w *InventoryWatcher) Start() {
	w.wg.Add(2)
	go w.watchSoftware()
	go w.watchServices()
}

// Stop stops the inventory watcher.
func (w *InventoryWatcher) Stop() {
	w.cancel()
	w.wg.Wait()
}

// watchSoftware monitors for software changes.
func (w *InventoryWatcher) watchSoftware() {
	defer w.wg.Done()
	ticker := time.NewTicker(w.softwareCheck)
	defer ticker.Stop()

	// Initial scan
	w.scanSoftware()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.scanSoftware()
		}
	}
}

// watchServices monitors for service changes.
func (w *InventoryWatcher) watchServices() {
	defer w.wg.Done()
	ticker := time.NewTicker(w.serviceCheck)
	defer ticker.Stop()

	// Initial scan
	w.scanServices()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.scanServices()
		}
	}
}

// scanSoftware scans for software changes.
func (w *InventoryWatcher) scanSoftware() {
	software := getSoftwareList()
	newHash := calculateSoftwareHash(software)

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.softwareHash == "" {
		// First scan - store baseline
		w.softwareHash = newHash
		w.lastSoftware = software
		return
	}

	if newHash == w.softwareHash {
		// No changes
		return
	}

	// Detect changes
	changes := detectSoftwareChanges(w.lastSoftware, software)
	if len(changes) > 0 && w.onSoftwareChange != nil {
		w.onSoftwareChange(changes)
	}

	w.softwareHash = newHash
	w.lastSoftware = software
}

// scanServices scans for service changes.
func (w *InventoryWatcher) scanServices() {
	services := getServiceList()
	newHash := calculateServiceHash(services)

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.serviceHash == "" {
		// First scan - store baseline
		w.serviceHash = newHash
		w.lastServices = services
		return
	}

	if newHash == w.serviceHash {
		// No changes
		return
	}

	// Detect changes
	changes := detectServiceChanges(w.lastServices, services)
	if len(changes) > 0 && w.onServiceChange != nil {
		w.onServiceChange(changes)
	}

	w.serviceHash = newHash
	w.lastServices = services
}

// GetSoftwareHash returns the current software hash.
func (w *InventoryWatcher) GetSoftwareHash() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.softwareHash
}

// GetServiceHash returns the current service hash.
func (w *InventoryWatcher) GetServiceHash() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.serviceHash
}

// detectSoftwareChanges compares old and new software lists.
func detectSoftwareChanges(old, new map[string]SoftwareItem) []SoftwareChange {
	var changes []SoftwareChange
	now := time.Now().Unix()

	// Check for removed and updated software
	for name, oldItem := range old {
		if newItem, exists := new[name]; !exists {
			changes = append(changes, SoftwareChange{
				Type:      ChangeRemoved,
				Name:      name,
				Version:   oldItem.Version,
				Timestamp: now,
			})
		} else if oldItem.Version != newItem.Version {
			changes = append(changes, SoftwareChange{
				Type:       ChangeUpdated,
				Name:       name,
				Version:    newItem.Version,
				OldVersion: oldItem.Version,
				Timestamp:  now,
			})
		}
	}

	// Check for new software
	for name, newItem := range new {
		if _, exists := old[name]; !exists {
			changes = append(changes, SoftwareChange{
				Type:      ChangeInstalled,
				Name:      name,
				Version:   newItem.Version,
				Timestamp: now,
			})
		}
	}

	return changes
}

// detectServiceChanges compares old and new service states.
func detectServiceChanges(old, new map[string]ServiceItem) []ServiceChange {
	var changes []ServiceChange
	now := time.Now().Unix()

	// Check for removed and changed services
	for name, oldItem := range old {
		if newItem, exists := new[name]; !exists {
			changes = append(changes, ServiceChange{
				Type:      ChangeRemoved,
				Name:      name,
				OldState:  oldItem.State,
				NewState:  "removed",
				Timestamp: now,
			})
		} else if oldItem.State != newItem.State {
			var changeType ChangeType
			switch newItem.State {
			case "running":
				changeType = ChangeStarted
			case "stopped":
				changeType = ChangeStopped
			default:
				changeType = ChangeModified
			}
			changes = append(changes, ServiceChange{
				Type:      changeType,
				Name:      name,
				OldState:  oldItem.State,
				NewState:  newItem.State,
				Timestamp: now,
			})
		}
	}

	// Check for new services
	for name, newItem := range new {
		if _, exists := old[name]; !exists {
			changes = append(changes, ServiceChange{
				Type:      ChangeInstalled,
				Name:      name,
				NewState:  newItem.State,
				Timestamp: now,
			})
		}
	}

	return changes
}

// calculateSoftwareHash creates a hash of the software list.
func calculateSoftwareHash(software map[string]SoftwareItem) string {
	// Sort by name for consistent hashing
	var names []string
	for name := range software {
		names = append(names, name)
	}
	sort.Strings(names)

	h := sha256.New()
	for _, name := range names {
		item := software[name]
		h.Write([]byte(name))
		h.Write([]byte(item.Version))
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// calculateServiceHash creates a hash of the service list.
func calculateServiceHash(services map[string]ServiceItem) string {
	// Sort by name for consistent hashing
	var names []string
	for name := range services {
		names = append(names, name)
	}
	sort.Strings(names)

	h := sha256.New()
	for _, name := range names {
		item := services[name]
		h.Write([]byte(name))
		h.Write([]byte(item.State))
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// SyncState represents the current sync state for incremental updates.
type SyncState struct {
	Software   string            `json:"software_hash"`
	Services   string            `json:"services_hash"`
	Users      string            `json:"users_hash"`
	Network    string            `json:"network_hash"`
	Disks      string            `json:"disks_hash"`
	LastSync   map[string]int64  `json:"last_sync"`
}

// NewSyncState creates a new sync state.
func NewSyncState() *SyncState {
	return &SyncState{
		LastSync: make(map[string]int64),
	}
}

// ToJSON serializes the sync state to JSON.
func (s *SyncState) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}

// GetHashes returns all current hashes for sync checking.
func (s *SyncState) GetHashes() map[string]string {
	return map[string]string{
		"software": s.Software,
		"services": s.Services,
		"users":    s.Users,
		"network":  s.Network,
		"disks":    s.Disks,
	}
}
