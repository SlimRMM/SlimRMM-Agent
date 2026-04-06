package eventlog

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// batchSize is the maximum number of events sent per batch.
	batchSize = 500

	// defaultLookback is how far back to look when no previous sync time exists.
	defaultLookback = 1 * time.Hour

	// stateFileMode restricts the sync state file to owner-only access.
	stateFileMode = 0600
)

// Manager orchestrates periodic event log collection and delivery.
type Manager struct {
	collector Collector
	config    Config
	sendFn    SendFunc
	logger    *slog.Logger
	syncState SyncState
	stateFile string
	mu        sync.RWMutex
	stopCh    chan struct{}
	running   bool
}

// NewManager creates a new event log Manager that persists sync state in dataDir.
func NewManager(dataDir string, sendFn SendFunc, logger *slog.Logger) *Manager {
	return &Manager{
		collector: NewPlatformCollector(),
		config:    Config{Enabled: false},
		sendFn:    sendFn,
		logger:    logger,
		syncState: SyncState{LastSync: make(map[string]time.Time)},
		stateFile: filepath.Join(dataDir, "eventlog_sync.json"),
		stopCh:    make(chan struct{}),
	}
}

// UpdateConfig applies a new configuration. It starts or stops the poll loop
// as needed based on the Enabled flag.
func (m *Manager) UpdateConfig(cfg Config) {
	m.mu.Lock()
	defer m.mu.Unlock()

	wasRunning := m.running
	m.config = cfg

	if cfg.Enabled && !wasRunning {
		m.running = true
		go m.pollLoop()
	} else if !cfg.Enabled && wasRunning {
		close(m.stopCh)
		m.stopCh = make(chan struct{})
		m.running = false
	}
}

// Stop shuts down the poll loop if it is running.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		close(m.stopCh)
		m.stopCh = make(chan struct{})
		m.running = false
	}
}

// pollLoop runs the periodic collection cycle until stopped.
func (m *Manager) pollLoop() {
	m.loadState()

	// Initial collection right away.
	m.collectAll()

	m.mu.RLock()
	interval := m.pollInterval()
	stopCh := m.stopCh
	m.mu.RUnlock()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			m.collectAll()

			// Check if the interval changed and reset the ticker.
			m.mu.RLock()
			newInterval := m.pollInterval()
			newStopCh := m.stopCh
			m.mu.RUnlock()

			if newInterval != interval {
				interval = newInterval
				ticker.Reset(interval)
			}
			// Update stopCh in case config was swapped.
			stopCh = newStopCh
		}
	}
}

// pollInterval returns the configured poll interval, defaulting to 5 minutes.
func (m *Manager) pollInterval() time.Duration {
	sec := m.config.PollIntervalSeconds
	if sec <= 0 {
		sec = 300
	}
	return time.Duration(sec) * time.Second
}

// collectAll iterates over configured channels, collects events, sends them
// in batches, and persists the updated sync state.
func (m *Manager) collectAll() {
	m.mu.RLock()
	channels := make([]string, len(m.config.Channels))
	copy(channels, m.config.Channels)
	m.mu.RUnlock()

	var allEntries []EventEntry

	for _, ch := range channels {
		since := m.getSyncTime(ch)

		entries, latestTime, err := m.collector.Collect(ch, since)
		if err != nil {
			m.logger.Warn("event log collection failed",
				"channel", ch,
				"error", err,
			)
			continue
		}

		if len(entries) > 0 {
			allEntries = append(allEntries, entries...)

			m.mu.Lock()
			m.syncState.LastSync[ch] = latestTime
			m.mu.Unlock()
		}
	}

	if len(allEntries) == 0 {
		return
	}

	// Send in batches.
	for i := 0; i < len(allEntries); i += batchSize {
		end := i + batchSize
		if end > len(allEntries) {
			end = len(allEntries)
		}

		batch := allEntries[i:end]
		if err := m.sendFn(batch); err != nil {
			m.logger.Error("failed to send event log batch",
				"batch_size", len(batch),
				"error", err,
			)
			// Stop sending further batches on failure; state will not be saved
			// so the same events are retried next cycle.
			return
		}
	}

	// Persist state only after all batches were sent successfully.
	m.saveState()
}

// getSyncTime returns the last sync time for a channel, defaulting to
// defaultLookback ago if there is no recorded time.
func (m *Manager) getSyncTime(channel string) time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if t, ok := m.syncState.LastSync[channel]; ok {
		return t
	}
	return time.Now().Add(-defaultLookback)
}

// loadState reads the sync state from the JSON file on disk.
func (m *Manager) loadState() {
	data, err := os.ReadFile(m.stateFile)
	if err != nil {
		if !os.IsNotExist(err) {
			m.logger.Warn("failed to read event log sync state", "error", err)
		}
		return
	}

	var state SyncState
	if err := json.Unmarshal(data, &state); err != nil {
		m.logger.Warn("failed to parse event log sync state", "error", err)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if state.LastSync != nil {
		m.syncState = state
	}
}

// saveState writes the current sync state to disk as JSON.
func (m *Manager) saveState() {
	m.mu.RLock()
	data, err := json.MarshalIndent(m.syncState, "", "  ")
	m.mu.RUnlock()
	if err != nil {
		m.logger.Error("failed to marshal event log sync state", "error", err)
		return
	}

	// Ensure the parent directory exists.
	dir := filepath.Dir(m.stateFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		m.logger.Error("failed to create state directory", "error", err)
		return
	}

	if err := os.WriteFile(m.stateFile, data, stateFileMode); err != nil {
		m.logger.Error("failed to write event log sync state", "error", err)
	}
}
