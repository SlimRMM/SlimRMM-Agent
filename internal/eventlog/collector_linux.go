//go:build linux

package eventlog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// LinuxCollector collects events from the systemd journal via journalctl.
type LinuxCollector struct{}

// NewPlatformCollector returns a LinuxCollector for journal-based event collection.
func NewPlatformCollector() Collector {
	return &LinuxCollector{}
}

// journalEntry represents a single JSON line from journalctl output.
type journalEntry struct {
	RealtimeTimestamp string `json:"__REALTIME_TIMESTAMP"`
	Priority          string `json:"PRIORITY"`
	SyslogIdentifier  string `json:"SYSLOG_IDENTIFIER"`
	SystemdUnit       string `json:"_SYSTEMD_UNIT"`
	Message           string `json:"MESSAGE"`
}

// Collect reads journal entries since the given time and returns them as EventEntry slices.
// The channel parameter is ignored on Linux; all entries come from "syslog".
func (c *LinuxCollector) Collect(channel string, since time.Time) ([]EventEntry, time.Time, error) {
	sinceUTC := since.UTC().Format("2006-01-02 15:04:05")

	cmd := exec.Command("journalctl",
		"--output=json",
		"--since", sinceUTC,
		"--no-pager",
		"-n", "500",
	)

	output, err := cmd.Output()
	if err != nil {
		return nil, since, fmt.Errorf("journalctl exec failed: %w", err)
	}

	var entries []EventEntry
	latestTime := since

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var je journalEntry
		if err := json.Unmarshal([]byte(line), &je); err != nil {
			continue
		}

		ts := parseRealtimeTimestamp(je.RealtimeTimestamp)
		if ts.After(latestTime) {
			latestTime = ts
		}

		provider := je.SyslogIdentifier
		if provider == "" {
			provider = je.SystemdUnit
		}

		entry := EventEntry{
			Channel:   "syslog",
			Provider:  provider,
			Level:     priorityToLevel(je.Priority),
			Message:   je.Message,
			Timestamp: ts.UTC().Format(time.RFC3339),
		}
		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return entries, latestTime, fmt.Errorf("error scanning journalctl output: %w", err)
	}

	return entries, latestTime, nil
}

// parseRealtimeTimestamp converts a __REALTIME_TIMESTAMP (microseconds since epoch) to time.Time.
func parseRealtimeTimestamp(us string) time.Time {
	usec, err := strconv.ParseInt(us, 10, 64)
	if err != nil {
		return time.Time{}
	}
	sec := usec / 1_000_000
	nsec := (usec % 1_000_000) * 1000
	return time.Unix(sec, nsec)
}

// priorityToLevel converts a syslog priority string ("0"-"7") to a human-readable level.
func priorityToLevel(p string) string {
	switch p {
	case "0", "1", "2":
		return "critical"
	case "3":
		return "error"
	case "4":
		return "warning"
	case "5", "6":
		return "info"
	case "7":
		return "verbose"
	default:
		return "info"
	}
}
