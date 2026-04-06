package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/monitor"
	"github.com/slimrmm/slimrmm-agent/internal/osquery"
	"github.com/slimrmm/slimrmm-agent/pkg/version"
)

// heartbeatPump sends periodic heartbeats with adaptive intervals.
func (h *Handler) heartbeatPump(ctx context.Context) error {
	// Send initial heartbeat
	snapshot := h.sendHeartbeatWithSnapshot(ctx)

	// Initialize last cert check if not set
	if h.lastCertCheck.IsZero() {
		h.lastCertCheck = time.Now()
	}

	// Get initial interval
	nextInterval := h.adaptiveHeartbeat.GetNextInterval(snapshot)
	timer := time.NewTimer(nextInterval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			snapshot = h.sendHeartbeatWithSnapshot(ctx)

			// Get next adaptive interval
			nextInterval = h.adaptiveHeartbeat.GetNextInterval(snapshot)
			timer.Reset(nextInterval)

			h.logger.Debug("adaptive heartbeat",
				"interval", nextInterval,
				"activity", h.adaptiveHeartbeat.GetActivityLevel().String(),
			)

			// Check for certificate renewal (every 24 hours like Python agent)
			if h.cfg.IsMTLSEnabled() && time.Since(h.lastCertCheck) >= certCheckInterval {
				h.checkAndRenewCertificates(ctx)
			}
		}
	}
}

// sendHeartbeatWithSnapshot sends a heartbeat and returns a snapshot for adaptive calculation.
func (h *Handler) sendHeartbeatWithSnapshot(ctx context.Context) *monitor.SystemSnapshot {
	stats, err := h.monitor.GetStats(ctx)
	if err != nil {
		h.logger.Error("getting stats for heartbeat", "error", err)
		h.adaptiveHeartbeat.RecordError()
		return nil
	}

	h.adaptiveHeartbeat.RecordSuccess()

	// Record connection success for self-healing watchdog
	// This resets the connection timeout on each successful heartbeat
	h.recordConnectionSuccess()

	// Calculate average disk usage for snapshot
	var avgDiskPercent float64
	if len(stats.Disk) > 0 {
		for _, d := range stats.Disk {
			avgDiskPercent += d.UsedPercent
		}
		avgDiskPercent /= float64(len(stats.Disk))
	}

	// Create snapshot for adaptive calculation
	snapshot := &monitor.SystemSnapshot{
		CPUPercent:    stats.CPU.UsagePercent,
		MemoryPercent: stats.Memory.UsedPercent,
		DiskPercent:   avgDiskPercent,
		Timestamp:     time.Now(),
	}

	// Determine heartbeat type based on activity
	heartbeatType := h.adaptiveHeartbeat.GetHeartbeatType()

	// Force full heartbeat periodically to ensure Proxmox/winget data is sent.
	// Also force full on first heartbeat (counter == 1) after connection.
	// Thread-safe access to fullHeartbeatCounter
	h.mu.Lock()
	h.fullHeartbeatCounter++
	counterVal := h.fullHeartbeatCounter
	if counterVal >= fullHeartbeatInterval || counterVal == 1 {
		heartbeatType = monitor.HeartbeatFull
		if counterVal >= fullHeartbeatInterval {
			h.fullHeartbeatCounter = 0
		}
	}
	h.mu.Unlock()

	// Send appropriate heartbeat based on type
	h.sendHeartbeatByType(ctx, stats, heartbeatType)

	return snapshot
}

// hashStruct creates a SHA256 hash of a struct for delta comparison.
// Returns empty string if marshaling fails.
func hashStruct(v interface{}) string {
	if v == nil {
		return ""
	}
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes for efficiency
}

// getSerialNumber retrieves and caches the hardware serial number using osquery.
// The serial number is fetched once and cached since it doesn't change.
// Thread-safe: uses mutex for cached value access.
func (h *Handler) getSerialNumber(ctx context.Context) string {
	h.mu.RLock()
	if h.serialNumberFetched {
		serial := h.cachedSerialNumber
		h.mu.RUnlock()
		return serial
	}
	h.mu.RUnlock()

	h.logger.Info("fetching hardware serial number from osquery")

	client := osquery.New()
	if !client.IsAvailable() {
		h.logger.Warn("osquery not available, cannot fetch serial number")
		h.mu.Lock()
		h.serialNumberFetched = true
		h.mu.Unlock()
		return ""
	}

	result, err := client.GetSystemInfo(ctx)
	if err != nil {
		h.logger.Warn("failed to get system info for serial number", "error", err)
		h.mu.Lock()
		h.serialNumberFetched = true
		h.mu.Unlock()
		return ""
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if len(result.Rows) > 0 {
		if serial, ok := result.Rows[0]["hardware_serial"]; ok && serial != "" {
			h.cachedSerialNumber = serial
			h.logger.Info("hardware serial number detected", "serial_number", serial)
		} else {
			h.logger.Warn("hardware_serial field empty or not found in osquery system_info")
		}
	} else {
		h.logger.Warn("osquery system_info returned no rows")
	}

	h.serialNumberFetched = true
	return h.cachedSerialNumber
}

// sendHeartbeat sends a heartbeat message in the format expected by the backend.
// Optimized: Only sends Proxmox/winget info when changed (delta-based).
func (h *Handler) sendHeartbeat(ctx context.Context) {
	stats, err := h.monitor.GetStats(ctx)
	if err != nil {
		h.logger.Error("getting stats for heartbeat", "error", err)
		return
	}

	// Build base heartbeat message
	heartbeat := h.buildBaseHeartbeat(ctx, stats)

	// Add platform-specific info (delta-based)
	h.addProxmoxInfo(ctx, &heartbeat)
	h.addHyperVInfo(ctx, &heartbeat)
	h.addDockerInfo(ctx, &heartbeat)
	h.addWingetInfo(ctx, &heartbeat)
	h.addBackupCapabilities(ctx, &heartbeat)

	// Send heartbeat
	h.SendRaw(heartbeat)
	h.recordConnectionSuccess()

	// Check thresholds and send proactive alerts
	h.thresholdMonitor.Update(stats)

	// Update last heartbeat time
	h.cfg.SetLastHeartbeat(time.Now().UTC().Format(time.RFC3339))

	// Periodically save config
	if h.incrementHeartbeatCount() {
		if err := h.cfg.Save(); err != nil {
			h.logger.Warn("failed to save config with heartbeat", "error", err)
		}
	}
}

// sendHeartbeatByType sends a heartbeat based on the adaptive heartbeat type.
// Minimal heartbeats only send alive status, stats sends basic metrics,
// and full sends complete system information.
func (h *Handler) sendHeartbeatByType(ctx context.Context, stats *monitor.Stats, heartbeatType monitor.HeartbeatType) {
	switch heartbeatType {
	case monitor.HeartbeatMinimal:
		// Minimal heartbeat - just alive status
		h.SendRaw(map[string]interface{}{
			"action":        "heartbeat",
			"type":          "minimal",
			"agent_version": version.Version,
			"alive":         true,
			"timestamp":     time.Now().Unix(),
		})
		h.recordConnectionSuccess()

	case monitor.HeartbeatStats:
		// Stats heartbeat - basic metrics without disk details
		h.SendRaw(map[string]interface{}{
			"action":        "heartbeat",
			"type":          "stats",
			"agent_version": version.Version,
			"stats": map[string]interface{}{
				"cpu_percent":    stats.CPU.UsagePercent,
				"memory_percent": stats.Memory.UsedPercent,
				"memory_used":    stats.Memory.Used,
				"memory_total":   stats.Memory.Total,
				"uptime_seconds": stats.Uptime,
				"process_count":  stats.ProcessCount,
				"timezone":       stats.Timezone,
			},
		})
		h.recordConnectionSuccess()

	case monitor.HeartbeatFull:
		// Full heartbeat - use existing sendHeartbeat logic
		h.sendHeartbeat(ctx)
		return
	}

	// Update last heartbeat time in config
	h.cfg.SetLastHeartbeat(time.Now().UTC().Format(time.RFC3339))

	// Periodically save config to persist LastHeartbeat
	// Thread-safe access to heartbeatCount
	h.mu.Lock()
	h.heartbeatCount++
	shouldSave := h.heartbeatCount >= configSaveInterval
	if shouldSave {
		h.heartbeatCount = 0
	}
	h.mu.Unlock()

	if shouldSave {
		if err := h.cfg.Save(); err != nil {
			h.logger.Warn("failed to save config with heartbeat", "error", err)
		}
	}
}
