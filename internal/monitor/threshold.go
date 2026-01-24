// Package monitor provides system monitoring with proactive threshold alerts.
package monitor

import (
	"runtime"
	"strings"
	"sync"
	"time"
)

// AlertSeverity represents the severity of a threshold alert.
type AlertSeverity string

const (
	// SeverityWarning indicates a warning condition.
	SeverityWarning AlertSeverity = "warning"
	// SeverityCritical indicates a critical condition.
	SeverityCritical AlertSeverity = "critical"
)

// MetricType represents the type of metric being monitored.
type MetricType string

const (
	MetricCPU    MetricType = "cpu"
	MetricMemory MetricType = "memory"
	MetricDisk   MetricType = "disk"
)

// ThresholdAlert represents an alert generated when thresholds are exceeded.
type ThresholdAlert struct {
	Metric          MetricType    `json:"metric"`
	CurrentValue    float64       `json:"current_value"`
	Threshold       float64       `json:"threshold"`
	Severity        AlertSeverity `json:"severity"`
	DurationSeconds int           `json:"duration_seconds"`
	Timestamp       time.Time     `json:"timestamp"`
	Message         string        `json:"message,omitempty"`
}

// ThresholdConfig defines thresholds for monitoring.
type ThresholdConfig struct {
	CPUWarning       float64 // CPU % warning threshold (default 80)
	CPUCritical      float64 // CPU % critical threshold (default 95)
	MemoryWarning    float64 // Memory % warning threshold (default 85)
	MemoryCritical   float64 // Memory % critical threshold (default 95)
	DiskWarning      float64 // Disk % warning threshold (default 85)
	DiskCritical     float64 // Disk % critical threshold (default 95)
	SustainedMinutes int     // Minutes threshold must be exceeded (default 2)
	CooldownMinutes  int     // Minutes between repeated alerts (default 5)
}

// DefaultThresholdConfig returns sensible default thresholds.
func DefaultThresholdConfig() ThresholdConfig {
	return ThresholdConfig{
		CPUWarning:       80.0,
		CPUCritical:      95.0,
		MemoryWarning:    85.0,
		MemoryCritical:   95.0,
		DiskWarning:      85.0,
		DiskCritical:     95.0,
		SustainedMinutes: 2,
		CooldownMinutes:  5,
	}
}

// metricState tracks the state of a single metric for threshold detection.
type metricState struct {
	firstExceeded time.Time
	lastAlerted   time.Time
	currentValue  float64
	isExceeded    bool
}

// ThresholdMonitor monitors system metrics and generates alerts when thresholds are exceeded.
type ThresholdMonitor struct {
	mu            sync.RWMutex
	config        ThresholdConfig
	states        map[MetricType]*metricState
	alertCallback func(ThresholdAlert)
	enabled       bool
}

// NewThresholdMonitor creates a new threshold monitor.
func NewThresholdMonitor(cfg ThresholdConfig) *ThresholdMonitor {
	return &ThresholdMonitor{
		config:  cfg,
		states:  make(map[MetricType]*metricState),
		enabled: true,
	}
}

// SetAlertCallback sets the function to call when an alert is triggered.
func (m *ThresholdMonitor) SetAlertCallback(callback func(ThresholdAlert)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alertCallback = callback
}

// SetEnabled enables or disables the monitor.
func (m *ThresholdMonitor) SetEnabled(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = enabled
}

// Update updates the monitor with current system stats and checks thresholds.
// Returns any alerts that should be sent.
func (m *ThresholdMonitor) Update(stats *Stats) []ThresholdAlert {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.enabled {
		return nil
	}

	var alerts []ThresholdAlert
	now := time.Now()

	// Check CPU threshold
	if alert := m.checkMetric(MetricCPU, stats.CPU.UsagePercent, m.config.CPUWarning, m.config.CPUCritical, now); alert != nil {
		alerts = append(alerts, *alert)
	}

	// Check memory threshold
	if alert := m.checkMetric(MetricMemory, stats.Memory.UsedPercent, m.config.MemoryWarning, m.config.MemoryCritical, now); alert != nil {
		alerts = append(alerts, *alert)
	}

	// Check disk threshold (only monitor system drive, not removable media)
	systemDiskUsage := getSystemDiskUsage(stats.Disk)
	if systemDiskUsage > 0 {
		if alert := m.checkMetric(MetricDisk, systemDiskUsage, m.config.DiskWarning, m.config.DiskCritical, now); alert != nil {
			alerts = append(alerts, *alert)
		}
	}

	// Call callback for each alert
	if m.alertCallback != nil {
		for _, alert := range alerts {
			m.alertCallback(alert)
		}
	}

	return alerts
}

// checkMetric checks a single metric against thresholds and returns an alert if needed.
func (m *ThresholdMonitor) checkMetric(
	metric MetricType,
	value float64,
	warning float64,
	critical float64,
	now time.Time,
) *ThresholdAlert {
	// Get or create state for this metric
	state, exists := m.states[metric]
	if !exists {
		state = &metricState{}
		m.states[metric] = state
	}

	state.currentValue = value

	// Determine severity
	var severity AlertSeverity
	var threshold float64
	if value >= critical {
		severity = SeverityCritical
		threshold = critical
	} else if value >= warning {
		severity = SeverityWarning
		threshold = warning
	} else {
		// Below all thresholds - reset state
		state.isExceeded = false
		state.firstExceeded = time.Time{}
		return nil
	}

	// Track sustained duration
	if !state.isExceeded {
		state.isExceeded = true
		state.firstExceeded = now
	}

	sustainedDuration := now.Sub(state.firstExceeded)
	sustainedRequired := time.Duration(m.config.SustainedMinutes) * time.Minute
	cooldownPeriod := time.Duration(m.config.CooldownMinutes) * time.Minute

	// Check if sustained long enough and cooldown passed
	if sustainedDuration >= sustainedRequired {
		timeSinceLastAlert := now.Sub(state.lastAlerted)
		if state.lastAlerted.IsZero() || timeSinceLastAlert >= cooldownPeriod {
			state.lastAlerted = now

			return &ThresholdAlert{
				Metric:          metric,
				CurrentValue:    value,
				Threshold:       threshold,
				Severity:        severity,
				DurationSeconds: int(sustainedDuration.Seconds()),
				Timestamp:       now,
				Message:         m.getAlertMessage(metric, severity, value),
			}
		}
	}

	return nil
}

// getAlertMessage generates a human-readable alert message.
func (m *ThresholdMonitor) getAlertMessage(metric MetricType, severity AlertSeverity, value float64) string {
	var metricName string
	switch metric {
	case MetricCPU:
		metricName = "CPU usage"
	case MetricMemory:
		metricName = "Memory usage"
	case MetricDisk:
		metricName = "Disk usage"
	}

	switch severity {
	case SeverityCritical:
		return metricName + " is critically high"
	case SeverityWarning:
		return metricName + " is above warning threshold"
	default:
		return metricName + " alert"
	}
}

// GetCurrentState returns the current state of all monitored metrics.
func (m *ThresholdMonitor) GetCurrentState() map[MetricType]struct {
	Value    float64
	Exceeded bool
	Duration time.Duration
} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[MetricType]struct {
		Value    float64
		Exceeded bool
		Duration time.Duration
	})

	now := time.Now()
	for metric, state := range m.states {
		duration := time.Duration(0)
		if state.isExceeded && !state.firstExceeded.IsZero() {
			duration = now.Sub(state.firstExceeded)
		}
		result[metric] = struct {
			Value    float64
			Exceeded bool
			Duration time.Duration
		}{
			Value:    state.currentValue,
			Exceeded: state.isExceeded,
			Duration: duration,
		}
	}

	return result
}

// Reset clears all tracking state.
func (m *ThresholdMonitor) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states = make(map[MetricType]*metricState)
}

// getSystemDiskUsage returns the usage percentage of the system drive only.
// This avoids false alerts from removable media (USB sticks, CDs, etc.).
// On Windows: returns C: drive usage
// On Linux/macOS: returns / (root) mount point usage
func getSystemDiskUsage(disks []DiskStats) float64 {
	if len(disks) == 0 {
		return 0
	}

	// Determine system mount point based on OS
	var systemMountPoints []string
	switch runtime.GOOS {
	case "windows":
		// Windows: C: drive is the system drive
		systemMountPoints = []string{"C:", "C:\\"}
	default:
		// Linux/macOS: root mount point
		systemMountPoints = []string{"/"}
	}

	// Find the system drive
	for _, d := range disks {
		mountpoint := strings.TrimSuffix(d.Mountpoint, "\\")
		for _, sysMountpoint := range systemMountPoints {
			if strings.EqualFold(mountpoint, sysMountpoint) {
				return d.UsedPercent
			}
		}
	}

	// Fallback: if no system drive found, use first "real" disk
	// (one with > 10GB total to exclude small removable media)
	const minDiskSize = 10 * 1024 * 1024 * 1024 // 10 GB
	for _, d := range disks {
		if d.Total > minDiskSize {
			return d.UsedPercent
		}
	}

	return 0
}
