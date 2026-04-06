package eventlog

import "time"

// EventEntry represents a single event log entry from any platform.
type EventEntry struct {
	EventID   int               `json:"event_id,omitempty"`
	Channel   string            `json:"channel"`
	Provider  string            `json:"provider,omitempty"`
	Level     string            `json:"level"`
	Message   string            `json:"message"`
	Timestamp string            `json:"timestamp"`
	RawData   map[string]string `json:"raw_data,omitempty"`
}

// Config holds the configuration for event log collection.
type Config struct {
	Channels            []string `json:"channels"`
	PollIntervalSeconds int      `json:"poll_interval_seconds"`
	Enabled             bool     `json:"enabled"`
}

// DefaultWindowsConfig returns the default event log configuration for Windows.
func DefaultWindowsConfig() Config {
	return Config{
		Channels:            []string{"Application", "System", "Security"},
		PollIntervalSeconds: 300,
		Enabled:             true,
	}
}

// DefaultLinuxConfig returns the default event log configuration for Linux.
func DefaultLinuxConfig() Config {
	return Config{
		Channels:            []string{"syslog"},
		PollIntervalSeconds: 300,
		Enabled:             true,
	}
}

// SyncState tracks the last sync time per channel.
type SyncState struct {
	LastSync map[string]time.Time `json:"last_sync"`
}

// Collector defines the interface for platform-specific event log collection.
type Collector interface {
	Collect(channel string, since time.Time) ([]EventEntry, time.Time, error)
}

// SendFunc is a callback for sending collected events to the backend.
type SendFunc func(events []EventEntry) error
