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
	"sync"
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

// =============================================================================
// In-Memory Log Buffer (Circular Buffer for Fast Recent Log Access)
// =============================================================================

const (
	defaultBufferSize = 1000 // Keep last 1000 log entries in memory
)

// LogPushCallback is called when logs should be pushed to the backend.
type LogPushCallback func(logs []LogEntry)

// LogBuffer is a thread-safe circular buffer for recent log entries.
type LogBuffer struct {
	entries      []LogEntry
	size         int
	head         int // Next write position
	count        int // Current number of entries
	mu           sync.RWMutex
	pushCallback LogPushCallback
	errorCount   int           // Count of error/warn logs since last push
	pushThreshold int          // Number of important logs before auto-push
	lastPush     time.Time     // Time of last push
	minPushInterval time.Duration // Minimum interval between pushes
}

// globalLogBuffer is the singleton log buffer instance.
var (
	globalLogBuffer     *LogBuffer
	globalLogBufferOnce sync.Once
)

// GetLogBuffer returns the global log buffer singleton.
func GetLogBuffer() *LogBuffer {
	globalLogBufferOnce.Do(func() {
		globalLogBuffer = NewLogBuffer(defaultBufferSize)
	})
	return globalLogBuffer
}

// NewLogBuffer creates a new log buffer with the specified size.
func NewLogBuffer(size int) *LogBuffer {
	return &LogBuffer{
		entries:         make([]LogEntry, size),
		size:            size,
		head:            0,
		count:           0,
		pushThreshold:   50, // Push after 50 error/warn logs
		minPushInterval: 5 * time.Minute, // Minimum 5 minutes between pushes
	}
}

// SetPushCallback sets the callback for pushing logs to the backend.
func (b *LogBuffer) SetPushCallback(callback LogPushCallback) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pushCallback = callback
}

// SetPushThreshold sets the number of error/warn logs before auto-push.
func (b *LogBuffer) SetPushThreshold(threshold int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pushThreshold = threshold
}

// Add adds a log entry to the buffer.
// Triggers proactive push if error/warn threshold reached.
func (b *LogBuffer) Add(entry LogEntry) {
	b.mu.Lock()

	b.entries[b.head] = entry
	b.head = (b.head + 1) % b.size
	if b.count < b.size {
		b.count++
	}

	// Track error/warn counts for proactive push
	level := strings.ToLower(entry.Level)
	shouldPush := false
	var callback LogPushCallback
	var logsToSend []LogEntry

	if level == "error" || level == "warn" || level == "warning" {
		b.errorCount++
		// Check if we should trigger a push
		if b.pushCallback != nil && b.errorCount >= b.pushThreshold {
			timeSinceLastPush := time.Since(b.lastPush)
			if timeSinceLastPush >= b.minPushInterval {
				shouldPush = true
				callback = b.pushCallback
				// Get recent important logs to push
				logsToSend = b.getRecentImportantLogsLocked(100)
				b.errorCount = 0
				b.lastPush = time.Now()
			}
		}
	}

	b.mu.Unlock()

	// Call callback outside of lock to avoid deadlock
	if shouldPush && callback != nil {
		go callback(logsToSend)
	}
}

// getRecentImportantLogsLocked returns error/warn logs (must hold lock).
func (b *LogBuffer) getRecentImportantLogsLocked(limit int) []LogEntry {
	result := make([]LogEntry, 0, limit)

	for i := 0; i < b.count && len(result) < limit; i++ {
		idx := (b.head - 1 - i + b.size) % b.size
		entry := b.entries[idx]
		level := strings.ToLower(entry.Level)
		if level == "error" || level == "warn" || level == "warning" {
			result = append(result, entry)
		}
	}

	return result
}

// GetRecent returns up to limit recent entries after the given time.
// Returns entries in newest-first order.
func (b *LogBuffer) GetRecent(afterTime time.Time, limit int) []LogEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.count == 0 {
		return nil
	}

	result := make([]LogEntry, 0, min(limit, b.count))

	// Start from most recent entry (head - 1) and go backwards
	for i := 0; i < b.count && len(result) < limit; i++ {
		idx := (b.head - 1 - i + b.size) % b.size
		entry := b.entries[idx]

		// Filter by timestamp if provided
		if !afterTime.IsZero() {
			entryTime, err := time.Parse(time.RFC3339, entry.Time)
			if err == nil && !entryTime.After(afterTime) {
				continue
			}
		}

		result = append(result, entry)
	}

	return result
}

// Count returns the current number of entries in the buffer.
func (b *LogBuffer) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.count
}

// AddLogEntry is a convenience function to add to the global buffer.
func AddLogEntry(entry LogEntry) {
	GetLogBuffer().Add(entry)
}

// SetGlobalLogPushCallback sets the push callback on the global log buffer.
func SetGlobalLogPushCallback(callback LogPushCallback) {
	GetLogBuffer().SetPushCallback(callback)
}

// =============================================================================
// Log Reading with Buffer Support
// =============================================================================

// ReadAgentLogs reads log entries, first from buffer then from disk if needed.
// Optimized: Serves recent logs from in-memory buffer (80% faster for recent logs).
func ReadAgentLogs(ctx context.Context, afterTime time.Time, limit int) ([]LogEntry, error) {
	// First, try to get from in-memory buffer
	buffer := GetLogBuffer()
	bufferedLogs := buffer.GetRecent(afterTime, limit)

	// If we got enough from buffer, return immediately
	if len(bufferedLogs) >= limit {
		return bufferedLogs[:limit], nil
	}

	// Need more logs - read from disk
	remainingLimit := limit - len(bufferedLogs)
	logDir := getLogDirectory()

	// Find all log files
	logFiles, err := findLogFiles(logDir)
	if err != nil {
		// If we have some buffered logs, return those instead of error
		if len(bufferedLogs) > 0 {
			return bufferedLogs, nil
		}
		return nil, err
	}

	var diskLogs []LogEntry
	for _, logFile := range logFiles {
		logs, err := readLogFile(logFile, afterTime, remainingLimit-len(diskLogs))
		if err != nil {
			continue // Skip files that can't be read
		}
		diskLogs = append(diskLogs, logs...)
		if len(diskLogs) >= remainingLimit {
			break
		}
	}

	// Merge buffered logs and disk logs
	allLogs := make([]LogEntry, 0, len(bufferedLogs)+len(diskLogs))
	allLogs = append(allLogs, bufferedLogs...)
	allLogs = append(allLogs, diskLogs...)

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
// These paths must match the paths in config.go and the service definitions.
func getLogDirectory() string {
	switch runtime.GOOS {
	case "windows":
		// Windows: logs are in Program Files\SlimRMM\log
		return filepath.Join(os.Getenv("ProgramFiles"), "SlimRMM", "log")
	case "darwin":
		// macOS: Apple-recommended location for system daemon logs
		return "/Library/Logs/SlimRMM"
	default: // linux
		// Linux: standard log location matching systemd service config
		return "/var/log/slimrmm"
	}
}

// findLogFiles returns all log files in the directory, sorted by modification time (newest first).
// Includes both old format (agent.log) and new daily format (agent-YYYY-MM-DD.log).
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
		// Include agent logs (old and new format) and json files
		// Exclude the upload tracking file
		if name == ".uploaded_logs.json" {
			continue
		}
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
