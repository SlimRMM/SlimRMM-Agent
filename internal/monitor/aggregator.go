// Package monitor provides system monitoring capabilities.
package monitor

import (
	"sync"
	"time"
)

// StatsAggregator collects and aggregates system statistics over time.
// Instead of sending every individual sample, it aggregates samples
// and sends summarized data to reduce network and database overhead.
type StatsAggregator struct {
	mu sync.Mutex

	samples     []statSample
	maxSamples  int           // Maximum samples to keep before flush
	flushPeriod time.Duration // How often to flush aggregated data

	// Callback to send aggregated stats
	onFlush func(AggregatedStats)

	// Control
	ticker *time.Ticker
	done   chan struct{}
}

// statSample holds a single sample of system statistics.
type statSample struct {
	CPUPercent    float64
	MemoryPercent float64
	MemoryUsed    uint64
	MemoryTotal   uint64
	Timestamp     time.Time
}

// AggregatedStats contains aggregated statistics over a period.
type AggregatedStats struct {
	PeriodStart   time.Time `json:"period_start"`
	PeriodSeconds int64     `json:"period_seconds"`

	// CPU statistics
	CPUAvg float64 `json:"cpu_avg"`
	CPUMax float64 `json:"cpu_max"`
	CPUMin float64 `json:"cpu_min"`

	// Memory statistics
	MemoryAvg float64 `json:"memory_avg"`
	MemoryMax float64 `json:"memory_max"`
	MemoryMin float64 `json:"memory_min"`

	// Memory bytes (from last sample)
	MemoryUsed  uint64 `json:"memory_used"`
	MemoryTotal uint64 `json:"memory_total"`

	// Metadata
	SampleCount int `json:"sample_count"`
}

// AggregatorConfig configures the stats aggregator.
type AggregatorConfig struct {
	MaxSamples  int           // Maximum samples before forced flush (default: 6)
	FlushPeriod time.Duration // Period between flushes (default: 3 minutes)
}

// DefaultAggregatorConfig returns default aggregator configuration.
func DefaultAggregatorConfig() AggregatorConfig {
	return AggregatorConfig{
		MaxSamples:  6,              // 6 samples at 30s = 3 minutes
		FlushPeriod: 3 * time.Minute,
	}
}

// NewStatsAggregator creates a new stats aggregator.
func NewStatsAggregator(cfg AggregatorConfig) *StatsAggregator {
	return &StatsAggregator{
		samples:     make([]statSample, 0, cfg.MaxSamples),
		maxSamples:  cfg.MaxSamples,
		flushPeriod: cfg.FlushPeriod,
		done:        make(chan struct{}),
	}
}

// SetFlushCallback sets the callback for when aggregated stats are ready.
func (a *StatsAggregator) SetFlushCallback(cb func(AggregatedStats)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onFlush = cb
}

// Start begins the periodic flush timer.
func (a *StatsAggregator) Start() {
	a.ticker = time.NewTicker(a.flushPeriod)
	go func() {
		for {
			select {
			case <-a.done:
				return
			case <-a.ticker.C:
				a.Flush()
			}
		}
	}()
}

// Stop stops the aggregator.
func (a *StatsAggregator) Stop() {
	if a.ticker != nil {
		a.ticker.Stop()
	}
	close(a.done)

	// Final flush
	a.Flush()
}

// AddSample adds a new statistics sample.
func (a *StatsAggregator) AddSample(cpuPercent, memoryPercent float64, memoryUsed, memoryTotal uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.samples = append(a.samples, statSample{
		CPUPercent:    cpuPercent,
		MemoryPercent: memoryPercent,
		MemoryUsed:    memoryUsed,
		MemoryTotal:   memoryTotal,
		Timestamp:     time.Now(),
	})

	// Flush if we've reached max samples
	if len(a.samples) >= a.maxSamples {
		a.flushLocked()
	}
}

// Flush aggregates and sends the current samples.
func (a *StatsAggregator) Flush() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.flushLocked()
}

// flushLocked performs the flush while holding the lock.
func (a *StatsAggregator) flushLocked() {
	if len(a.samples) == 0 || a.onFlush == nil {
		return
	}

	// Calculate aggregates
	result := AggregatedStats{
		PeriodStart:   a.samples[0].Timestamp,
		PeriodSeconds: int64(a.flushPeriod.Seconds()),
		SampleCount:   len(a.samples),
		CPUMin:        a.samples[0].CPUPercent,
		CPUMax:        a.samples[0].CPUPercent,
		MemoryMin:     a.samples[0].MemoryPercent,
		MemoryMax:     a.samples[0].MemoryPercent,
	}

	var cpuSum, memSum float64
	for _, s := range a.samples {
		cpuSum += s.CPUPercent
		memSum += s.MemoryPercent

		if s.CPUPercent < result.CPUMin {
			result.CPUMin = s.CPUPercent
		}
		if s.CPUPercent > result.CPUMax {
			result.CPUMax = s.CPUPercent
		}
		if s.MemoryPercent < result.MemoryMin {
			result.MemoryMin = s.MemoryPercent
		}
		if s.MemoryPercent > result.MemoryMax {
			result.MemoryMax = s.MemoryPercent
		}
	}

	result.CPUAvg = cpuSum / float64(len(a.samples))
	result.MemoryAvg = memSum / float64(len(a.samples))

	// Use last sample for absolute memory values
	lastSample := a.samples[len(a.samples)-1]
	result.MemoryUsed = lastSample.MemoryUsed
	result.MemoryTotal = lastSample.MemoryTotal

	// Clear samples
	a.samples = a.samples[:0]

	// Send callback
	a.onFlush(result)
}

// GetSampleCount returns the current number of samples waiting to be flushed.
func (a *StatsAggregator) GetSampleCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.samples)
}
