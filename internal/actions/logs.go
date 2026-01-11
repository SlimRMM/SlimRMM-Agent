// Package actions provides log reading functionality.
package actions

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// LogEntry represents a single log entry.
type LogEntry struct {
	Time    string                 `json:"time"`
	Level   string                 `json:"level"`
	Source  string                 `json:"source,omitempty"`
	Message string                 `json:"msg"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// ReadAgentLogs reads log entries from agent log files.
func ReadAgentLogs(ctx context.Context, afterTime time.Time, limit int) ([]LogEntry, error) {
	logDir := getLogDirectory()

	// Find all log files
	logFiles, err := findLogFiles(logDir)
	if err != nil {
		return nil, err
	}

	var allLogs []LogEntry

	for _, logFile := range logFiles {
		logs, err := readLogFile(logFile, afterTime, limit-len(allLogs))
		if err != nil {
			continue // Skip files that can't be read
		}
		allLogs = append(allLogs, logs...)
		if len(allLogs) >= limit {
			break
		}
	}

	// Sort by timestamp descending (newest first)
	sort.Slice(allLogs, func(i, j int) bool {
		return allLogs[i].Time > allLogs[j].Time
	})

	// Limit results
	if len(allLogs) > limit {
		allLogs = allLogs[:limit]
	}

	return allLogs, nil
}

// getLogDirectory returns the log directory for the current OS.
func getLogDirectory() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "SlimRMM", "logs")
	case "darwin":
		return "/Library/Logs/SlimRMM"
	default: // linux
		return "/var/log/slimrmm-agent"
	}
}

// findLogFiles returns all log files in the directory, sorted by modification time (newest first).
func findLogFiles(logDir string) ([]string, error) {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		return nil, err
	}

	type fileWithTime struct {
		path    string
		modTime time.Time
	}

	var files []fileWithTime
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".log") || strings.HasSuffix(name, ".json") {
			info, err := entry.Info()
			if err != nil {
				continue
			}
			files = append(files, fileWithTime{
				path:    filepath.Join(logDir, name),
				modTime: info.ModTime(),
			})
		}
	}

	// Sort by modification time (newest first)
	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.After(files[j].modTime)
	})

	var paths []string
	for _, f := range files {
		paths = append(paths, f.path)
	}
	return paths, nil
}

// readLogFile reads log entries from a single file.
func readLogFile(path string, afterTime time.Time, limit int) ([]LogEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var logs []LogEntry
	scanner := bufio.NewScanner(file)

	// Increase buffer size for potentially long log lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() && len(logs) < limit {
		line := scanner.Text()
		if line == "" {
			continue
		}

		entry, err := parseLogLine(line)
		if err != nil {
			continue // Skip unparseable lines
		}

		// Filter by timestamp if provided
		if !afterTime.IsZero() {
			entryTime, err := time.Parse(time.RFC3339, entry.Time)
			if err == nil && !entryTime.After(afterTime) {
				continue
			}
		}

		logs = append(logs, entry)
	}

	return logs, nil
}

// parseLogLine parses a single log line.
// Supports JSON format (slog) and plain text.
func parseLogLine(line string) (LogEntry, error) {
	// Try JSON format first (slog output)
	if strings.HasPrefix(line, "{") {
		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err == nil {
			entry := LogEntry{
				Details: make(map[string]interface{}),
			}

			// Extract known fields
			if t, ok := raw["time"].(string); ok {
				entry.Time = t
				delete(raw, "time")
			}
			if l, ok := raw["level"].(string); ok {
				entry.Level = strings.ToLower(l)
				delete(raw, "level")
			}
			if m, ok := raw["msg"].(string); ok {
				entry.Message = m
				delete(raw, "msg")
			}
			if s, ok := raw["source"].(string); ok {
				entry.Source = s
				delete(raw, "source")
			}
			if c, ok := raw["component"].(string); ok {
				entry.Source = c
				delete(raw, "component")
			}

			// Remaining fields go to details
			for k, v := range raw {
				entry.Details[k] = v
			}

			return entry, nil
		}
	}

	// Fall back to plain text parsing
	// Try to extract timestamp from line
	entry := LogEntry{
		Time:    time.Now().UTC().Format(time.RFC3339),
		Level:   "info",
		Message: line,
	}

	// Try to detect log level from line content
	lineLower := strings.ToLower(line)
	if strings.Contains(lineLower, "error") || strings.Contains(lineLower, "err") {
		entry.Level = "error"
	} else if strings.Contains(lineLower, "warn") {
		entry.Level = "warn"
	} else if strings.Contains(lineLower, "debug") {
		entry.Level = "debug"
	}

	return entry, nil
}
