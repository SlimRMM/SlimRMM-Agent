//go:build darwin

package eventlog

import "time"

// DarwinCollector is a no-op event log collector for macOS.
type DarwinCollector struct{}

// NewPlatformCollector returns a DarwinCollector (no-op stub) on macOS.
func NewPlatformCollector() Collector {
	return &DarwinCollector{}
}

// Collect is a no-op on macOS. It returns nil entries and the original since time.
func (c *DarwinCollector) Collect(channel string, since time.Time) ([]EventEntry, time.Time, error) {
	return nil, since, nil
}
