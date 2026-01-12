// Package monitor provides system monitoring capabilities.
package monitor

import (
	"math"
	"sync"
	"time"
)

// ActivityLevel represents the current system activity level.
type ActivityLevel int

const (
	// ActivityIdle indicates low system activity.
	ActivityIdle ActivityLevel = iota
	// ActivityNormal indicates normal system activity.
	ActivityNormal
	// ActivityHigh indicates high system activity.
	ActivityHigh
	// ActivityCritical indicates critical system activity or errors.
	ActivityCritical
)

// HeartbeatType represents the type of heartbeat to send.
type HeartbeatType string

const (
	// HeartbeatMinimal sends only alive status.
	HeartbeatMinimal HeartbeatType = "minimal"
	// HeartbeatStats sends basic statistics.
	HeartbeatStats HeartbeatType = "stats"
	// HeartbeatFull sends complete system information.
	HeartbeatFull HeartbeatType = "full"
)

// AdaptiveHeartbeat manages dynamic heartbeat intervals based on system activity.
type AdaptiveHeartbeat struct {
	mu sync.RWMutex

	// Interval configuration
	baseInterval time.Duration
	minInterval  time.Duration
	maxInterval  time.Duration

	// Current state
	activityLevel     ActivityLevel
	lastStats         *SystemSnapshot
	significantChange float64 // Threshold for detecting significant changes (default 5%)

	// Error tracking for critical state
	consecutiveErrors int
}

// SystemSnapshot holds a snapshot of system statistics for comparison.
type SystemSnapshot struct {
	CPUPercent    float64
	MemoryPercent float64
	DiskPercent   float64
	Timestamp     time.Time
}

// AdaptiveConfig configures the adaptive heartbeat system.
type AdaptiveConfig struct {
	BaseInterval      time.Duration // Default interval (30s)
	MinInterval       time.Duration // Minimum interval when high activity (5s)
	MaxInterval       time.Duration // Maximum interval when idle (60s)
	SignificantChange float64       // Threshold percentage for significant changes (5.0)
}

// DefaultAdaptiveConfig returns default adaptive heartbeat configuration.
func DefaultAdaptiveConfig() AdaptiveConfig {
	return AdaptiveConfig{
		BaseInterval:      30 * time.Second,
		MinInterval:       5 * time.Second,
		MaxInterval:       60 * time.Second,
		SignificantChange: 5.0,
	}
}

// NewAdaptiveHeartbeat creates a new adaptive heartbeat manager.
func NewAdaptiveHeartbeat(cfg AdaptiveConfig) *AdaptiveHeartbeat {
	return &AdaptiveHeartbeat{
		baseInterval:      cfg.BaseInterval,
		minInterval:       cfg.MinInterval,
		maxInterval:       cfg.MaxInterval,
		significantChange: cfg.SignificantChange,
		activityLevel:     ActivityNormal,
	}
}

// GetNextInterval determines the next heartbeat interval based on current system state.
func (h *AdaptiveHeartbeat) GetNextInterval(currentStats *SystemSnapshot) time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()

	// First run - use base interval
	if h.lastStats == nil {
		h.lastStats = currentStats
		return h.baseInterval
	}

	// Check for critical errors
	if h.consecutiveErrors >= 3 {
		h.activityLevel = ActivityCritical
		h.lastStats = currentStats
		return h.minInterval
	}

	// Calculate deltas
	cpuDelta := math.Abs(currentStats.CPUPercent - h.lastStats.CPUPercent)
	memDelta := math.Abs(currentStats.MemoryPercent - h.lastStats.MemoryPercent)

	// Determine activity level
	if cpuDelta > h.significantChange || memDelta > h.significantChange {
		h.activityLevel = ActivityHigh
	} else if currentStats.CPUPercent > 80 || currentStats.MemoryPercent > 90 {
		h.activityLevel = ActivityHigh
	} else if currentStats.CPUPercent < 10 && memDelta < 2 {
		h.activityLevel = ActivityIdle
	} else {
		h.activityLevel = ActivityNormal
	}

	h.lastStats = currentStats

	// Return interval based on activity level
	switch h.activityLevel {
	case ActivityCritical:
		return h.minInterval
	case ActivityHigh:
		return h.minInterval * 3 // 15s when high activity
	case ActivityIdle:
		return h.maxInterval
	default:
		return h.baseInterval
	}
}

// GetHeartbeatType determines what type of heartbeat to send based on activity level.
func (h *AdaptiveHeartbeat) GetHeartbeatType() HeartbeatType {
	h.mu.RLock()
	defer h.mu.RUnlock()

	switch h.activityLevel {
	case ActivityIdle:
		return HeartbeatMinimal
	case ActivityCritical:
		return HeartbeatFull
	default:
		return HeartbeatStats
	}
}

// RecordError records an error occurrence for critical state tracking.
func (h *AdaptiveHeartbeat) RecordError() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.consecutiveErrors++
}

// RecordSuccess resets the error counter on successful operations.
func (h *AdaptiveHeartbeat) RecordSuccess() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.consecutiveErrors = 0
}

// GetActivityLevel returns the current activity level.
func (h *AdaptiveHeartbeat) GetActivityLevel() ActivityLevel {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.activityLevel
}

// String returns a string representation of the activity level.
func (l ActivityLevel) String() string {
	switch l {
	case ActivityIdle:
		return "idle"
	case ActivityNormal:
		return "normal"
	case ActivityHigh:
		return "high"
	case ActivityCritical:
		return "critical"
	default:
		return "unknown"
	}
}
