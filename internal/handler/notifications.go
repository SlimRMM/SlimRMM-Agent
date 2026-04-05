package handler

import (
	"context"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/actions"
	"github.com/slimrmm/slimrmm-agent/internal/logging"
	"github.com/slimrmm/slimrmm-agent/internal/monitor"
	"github.com/slimrmm/slimrmm-agent/internal/tamper"
)

// Default delay before scheduling a reboot after policy execution.
const defaultRebootDelaySeconds = 30

// ScheduleReboot schedules a system reboot after the default delay (30 seconds).
// This consolidates the reboot scheduling logic used across multiple handlers,
// allowing pending operations to complete before the system restarts.
// The reboot runs in a background goroutine and logs the reason for auditing.
// If the handler is shut down (h.done closed) before the delay elapses, the
// scheduled reboot is cancelled so a stopping agent does not reboot the host.
func (h *Handler) ScheduleReboot(reason string) {
	go func() {
		select {
		case <-time.After(defaultRebootDelaySeconds * time.Second):
			h.logger.Info("initiating scheduled reboot", "reason", reason)
			// Use a background context here because the reboot command itself
			// must outlive the agent's shutdown — but the *wait* above honours
			// h.done so we only reach this point if shutdown did not fire.
			if err := actions.RestartSystem(context.Background(), false, 0); err != nil {
				h.logger.Error("failed to schedule reboot", "error", err, "reason", reason)
			}
		case <-h.done:
			h.logger.Info("scheduled reboot cancelled due to agent shutdown", "reason", reason)
			return
		}
	}()
}

// sendThresholdAlert sends a threshold alert to the backend.
func (h *Handler) sendThresholdAlert(alert monitor.ThresholdAlert) {
	h.logger.Warn("threshold alert triggered",
		"metric", alert.Metric,
		"value", alert.CurrentValue,
		"threshold", alert.Threshold,
		"severity", alert.Severity,
		"duration_seconds", alert.DurationSeconds,
	)
	h.SendRaw(map[string]interface{}{
		"action":           "threshold_alert",
		"metric":           alert.Metric,
		"current_value":    alert.CurrentValue,
		"threshold":        alert.Threshold,
		"severity":         alert.Severity,
		"duration_seconds": alert.DurationSeconds,
		"timestamp":        alert.Timestamp.Format(time.RFC3339),
		"message":          alert.Message,
	})
}

// sendLogsPush proactively sends important logs to the backend.
// Called when error/warn threshold is reached.
func (h *Handler) sendLogsPush(logs []actions.LogEntry) {
	if len(logs) == 0 {
		return
	}

	h.logger.Info("proactively pushing important logs to backend",
		"log_count", len(logs),
	)

	h.SendRaw(map[string]interface{}{
		"action":    "logs_push",
		"logs":      logs,
		"count":     len(logs),
		"timestamp": time.Now().Format(time.RFC3339),
		"push_type": "threshold",
	})

	// Mark current log file as uploaded for rotation tracking
	logging.MarkCurrentLogUploaded()
}

// sendSoftwareChanges sends software inventory changes to the backend.
func (h *Handler) sendSoftwareChanges(changes []monitor.SoftwareChange) {
	h.logger.Info("software changes detected", "count", len(changes))
	h.SendRaw(map[string]interface{}{
		"action":      "inventory_change",
		"change_type": "software_change",
		"changes":     changes,
		"hash":        h.inventoryWatcher.GetSoftwareHash(),
	})
}

// sendServiceChanges sends service state changes to the backend.
func (h *Handler) sendServiceChanges(changes []monitor.ServiceChange) {
	h.logger.Info("service changes detected", "count", len(changes))
	h.SendRaw(map[string]interface{}{
		"action":      "inventory_change",
		"change_type": "service_change",
		"changes":     changes,
		"hash":        h.inventoryWatcher.GetServiceHash(),
	})
}

// sendMaintenanceStatus sends maintenance mode status to the backend.
func (h *Handler) sendMaintenanceStatus(enabled bool, reason string) {
	h.SendRaw(map[string]interface{}{
		"action":  "set_maintenance",
		"enabled": enabled,
		"reason":  reason,
	})
}

// sendTamperAlert sends a tamper detection alert to the backend.
func (h *Handler) sendTamperAlert(event tamper.TamperEvent) {
	h.SendRaw(map[string]interface{}{
		"action":    "tamper_alert",
		"type":      event.Type,
		"path":      event.Path,
		"details":   event.Details,
		"timestamp": event.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
	})
}

// installWatchdog installs the platform-specific watchdog service.
func (h *Handler) installWatchdog() error {
	return tamper.InstallWatchdog()
}

// uninstallWatchdog removes the platform-specific watchdog service.
func (h *Handler) uninstallWatchdog() error {
	return tamper.UninstallWatchdog()
}
