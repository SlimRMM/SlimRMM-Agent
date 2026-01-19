// Package handler provides WebSocket message handling for the agent.
// It processes incoming messages and dispatches them to action handlers.
package handler

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/slimrmm/slimrmm-agent/internal/actions"
	"github.com/slimrmm/slimrmm-agent/internal/config"
	"github.com/slimrmm/slimrmm-agent/internal/logging"
	"github.com/slimrmm/slimrmm-agent/internal/monitor"
	"github.com/slimrmm/slimrmm-agent/internal/osquery"
	"github.com/slimrmm/slimrmm-agent/internal/security/antireplay"
	"github.com/slimrmm/slimrmm-agent/internal/security/audit"
	"github.com/slimrmm/slimrmm-agent/internal/security/mtls"
	"github.com/slimrmm/slimrmm-agent/internal/security/ratelimit"
	"github.com/slimrmm/slimrmm-agent/internal/services/models"
	"github.com/slimrmm/slimrmm-agent/internal/services/software"
	"github.com/slimrmm/slimrmm-agent/internal/services/validation"
	"github.com/slimrmm/slimrmm-agent/internal/tamper"
	"github.com/slimrmm/slimrmm-agent/internal/updater"
	"github.com/slimrmm/slimrmm-agent/internal/winget"
	"github.com/slimrmm/slimrmm-agent/pkg/version"
)

const (
	// WebSocket timing constants
	writeWait         = 10 * time.Second
	pongWait          = 60 * time.Second
	pingPeriod        = (pongWait * 9) / 10
	heartbeatPeriod   = 30 * time.Second
	maxMessageSize    = 10 * 1024 * 1024 // 10 MB
	certCheckInterval = 24 * time.Hour   // Check certificates every 24 hours

	// Connection constants
	connectionTimeout  = 30 * time.Second
	tcpKeepAlive       = 30 * time.Second
	handshakeTimeout   = 15 * time.Second
	wsEndpoint         = "/api/v1/ws/agent"
	httpClientTimeout  = 30 * time.Second

	// Heartbeat configuration
	fullHeartbeatInterval   = 10  // Full heartbeat every N heartbeats (~5 minutes)
	configSaveInterval      = 10  // Save config every N heartbeats (~5 minutes)
	wingetUpdateInterval    = 120 // Winget update check every N heartbeats (~60 minutes)
)

// actionToResponseAction maps request action names to their response action names.
// This is needed because the backend expects specific action names for certain responses.
var actionToResponseAction = map[string]string{
	"pull_logs": "logs_result",
}

// Message represents a WebSocket message from the backend.
// The backend sends all fields at root level, not inside a "data" object.
type Message struct {
	Action    string          `json:"action"`
	RequestID string          `json:"request_id,omitempty"`
	ScanType  string          `json:"scan_type,omitempty"`
	Query     string          `json:"query,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	// Additional fields used by various actions
	// We store the raw message to extract action-specific fields
	Raw json.RawMessage `json:"-"`
}

// Response represents a WebSocket response.
type Response struct {
	Action    string      `json:"action"`
	RequestID string      `json:"request_id,omitempty"`
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
}

// HeartbeatMessage is the format expected by the backend (Python-compatible).
type HeartbeatMessage struct {
	Action       string              `json:"action"`
	Type         string              `json:"type,omitempty"`
	AgentVersion string              `json:"agent_version"`
	Stats        HeartbeatStats      `json:"stats"`
	ExternalIP   string              `json:"external_ip,omitempty"`
	SerialNumber string              `json:"serial_number,omitempty"`
	Proxmox      *HeartbeatProxmox   `json:"proxmox,omitempty"`
	Winget       *HeartbeatWinget    `json:"winget,omitempty"`
}

// HeartbeatWinget contains Windows Package Manager (winget) information.
type HeartbeatWinget struct {
	Available                   bool   `json:"available"`
	Version                     string `json:"version,omitempty"`
	BinaryPath                  string `json:"binary_path,omitempty"`
	SystemLevel                 bool   `json:"system_level"`
	HelperAvailable             bool   `json:"helper_available"`                // Available via helper in user context
	PowerShell7Available        bool   `json:"powershell7_available"`           // PowerShell 7 is installed
	WinGetClientModuleAvailable bool   `json:"winget_client_module_available"`  // Microsoft.WinGet.Client module is available
}

// HeartbeatProxmox contains Proxmox host information.
type HeartbeatProxmox struct {
	IsProxmox      bool   `json:"is_proxmox"`
	Version        string `json:"version,omitempty"`
	Release        string `json:"release,omitempty"`
	KernelVersion  string `json:"kernel_version,omitempty"`
	ClusterName    string `json:"cluster_name,omitempty"`
	NodeName       string `json:"node_name,omitempty"`
	RepositoryType string `json:"repository_type,omitempty"`
}

// HeartbeatStats contains the stats in the format expected by the backend.
// Matches Python agent format for API compatibility.
type HeartbeatStats struct {
	CPUPercent    float64             `json:"cpu_percent"`
	MemoryPercent float64             `json:"memory_percent"`
	MemoryUsed    uint64              `json:"memory_used"`
	MemoryTotal   uint64              `json:"memory_total"`
	Disk          []HeartbeatDisk     `json:"disk,omitempty"`
	NetworkIO     *HeartbeatNetworkIO `json:"network_io,omitempty"`
	UptimeSeconds uint64              `json:"uptime_seconds,omitempty"`
	ProcessCount  int                 `json:"process_count,omitempty"`
	Timezone      string              `json:"timezone,omitempty"`
}

// HeartbeatDisk contains disk statistics for heartbeat.
type HeartbeatDisk struct {
	Device      string  `json:"device"`
	Mountpoint  string  `json:"mountpoint"`
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"used_percent"`
}

// HeartbeatNetworkIO contains network I/O statistics.
type HeartbeatNetworkIO struct {
	BytesSent   uint64 `json:"bytes_sent"`
	BytesRecv   uint64 `json:"bytes_recv"`
	PacketsSent uint64 `json:"packets_sent"`
	PacketsRecv uint64 `json:"packets_recv"`
}

// OsqueryResponse is the format expected by the backend for osquery results.
type OsqueryResponse struct {
	Action    string      `json:"action"`
	ScanType  string      `json:"scan_type"`
	Data      interface{} `json:"data"`
	RequestID string      `json:"request_id,omitempty"`
}

// ActionHandler is a function that handles a specific action.
type ActionHandler func(ctx context.Context, data json.RawMessage) (interface{}, error)

// Handler manages WebSocket communication.
type Handler struct {
	cfg       *config.Config
	paths     config.Paths
	conn      *websocket.Conn
	tlsConfig *tls.Config
	monitor   *monitor.Monitor
	logger    *slog.Logger

	handlers        map[string]ActionHandler
	terminalManager *actions.TerminalManager
	uploadManager   *actions.UploadManager
	sendCh          chan []byte
	done            chan struct{}
	mu              sync.RWMutex

	// Certificate renewal tracking
	lastCertCheck time.Time

	// Auto-updater
	updater *updater.Updater

	// Tamper protection
	tamperProtection *tamper.Protection

	// Heartbeat counter for periodic config saves
	heartbeatCount int

	// Full heartbeat counter - force full heartbeat every N heartbeats
	fullHeartbeatCounter int

	// Inventory watcher for event-driven updates
	inventoryWatcher *monitor.InventoryWatcher

	// Adaptive heartbeat for dynamic intervals
	adaptiveHeartbeat *monitor.AdaptiveHeartbeat

	// Threshold monitor for proactive alerts
	thresholdMonitor *monitor.ThresholdMonitor

	// Delta tracking for heartbeat optimization - only send when changed
	lastProxmoxHash string
	lastWingetHash  string

	// Winget helper availability (updated by update scans)
	wingetHelperAvailable bool

	// Cached hardware serial number (doesn't change)
	cachedSerialNumber     string
	serialNumberFetched    bool

	// Security modules for multi-layered protection
	rateLimiter      *ratelimit.ActionLimiter
	antiReplay       *antireplay.Protector
	auditLogger      *audit.Logger

	// Self-healing watchdog for connection monitoring
	selfHealingWatchdog SelfHealingWatchdog

	// Software services for installation/uninstallation operations
	softwareServices *software.Services

	// Validation service for pre-uninstall validation
	validationService *validation.DefaultValidationService
}

// SelfHealingWatchdog is the interface for the self-healing watchdog.
type SelfHealingWatchdog interface {
	RecordConnectionSuccess()
	RecordConnectionFailure()
}

// New creates a new Handler.
func New(cfg *config.Config, paths config.Paths, tlsConfig *tls.Config, logger *slog.Logger) *Handler {
	uploadManager := actions.NewUploadManager()

	// Initialize tamper protection
	tamperConfig := tamper.Config{
		Enabled:         cfg.IsTamperProtectionEnabled(),
		UninstallKeyHash: cfg.GetUninstallKeyHash(),
		WatchdogEnabled: cfg.IsWatchdogEnabled(),
		AlertOnTamper:   cfg.IsTamperAlertEnabled(),
	}
	tamperProtection := tamper.New(tamperConfig, logger)

	// Initialize inventory watcher for event-driven updates
	watcherCfg := monitor.DefaultWatcherConfig()
	inventoryWatcher := monitor.NewInventoryWatcher(watcherCfg)

	// Initialize adaptive heartbeat for dynamic intervals
	adaptiveCfg := monitor.DefaultAdaptiveConfig()
	adaptiveHeartbeat := monitor.NewAdaptiveHeartbeat(adaptiveCfg)

	// Initialize threshold monitor for proactive alerts
	thresholdCfg := monitor.DefaultThresholdConfig()
	thresholdMonitor := monitor.NewThresholdMonitor(thresholdCfg)

	// Initialize security modules for multi-layered protection
	rateLimiter := ratelimit.NewActionLimiter(ratelimit.DefaultConfig())
	antiReplay := antireplay.New(antireplay.DefaultConfig())
	auditLogger := audit.GetLogger()

	logger.Info("security modules initialized",
		"rate_limiter", "enabled",
		"anti_replay", "enabled",
		"audit_logging", "enabled",
	)

	// Initialize software services for installation/uninstallation
	softwareServices := software.NewServices(logger)

	// Initialize validation service for pre-uninstall validation
	validationService := validation.NewServices(logger)

	h := &Handler{
		cfg:               cfg,
		paths:             paths,
		tlsConfig:         tlsConfig,
		monitor:           monitor.New(),
		logger:            logger,
		handlers:          make(map[string]ActionHandler),
		terminalManager:   actions.NewTerminalManager(),
		uploadManager:     uploadManager,
		sendCh:            make(chan []byte, 256),
		done:              make(chan struct{}),
		updater:           updater.New(logger),
		tamperProtection:  tamperProtection,
		inventoryWatcher:  inventoryWatcher,
		adaptiveHeartbeat: adaptiveHeartbeat,
		thresholdMonitor:  thresholdMonitor,
		rateLimiter:       rateLimiter,
		antiReplay:        antiReplay,
		auditLogger:       auditLogger,
		softwareServices:  softwareServices,
		validationService: validationService,
	}

	h.registerHandlers()

	// Set up software service progress callbacks to send via WebSocket
	h.softwareServices.SetInstallationProgressCallback(func(progress interface{}) {
		if p, ok := progress.(*models.InstallProgress); ok {
			h.SendRaw(map[string]interface{}{
				"action":           "software_install_progress",
				"installation_id":  p.InstallationID,
				"status":           p.Status,
				"output":           p.Output,
				"progress_percent": p.Percent,
			})
		}
	})
	h.softwareServices.SetUninstallationProgressCallback(func(progress interface{}) {
		if p, ok := progress.(*models.UninstallProgress); ok {
			h.SendRaw(map[string]interface{}{
				"action":            "software_uninstall_progress",
				"uninstallation_id": p.UninstallationID,
				"status":            p.Status,
				"output":            p.Output,
				"phase":             p.Phase,
			})
		}
	})

	// Set up maintenance callback for updater
	h.updater.SetMaintenanceCallback(h.sendMaintenanceStatus)

	// Set up tamper detection callback
	tamperProtection.SetTamperCallback(h.sendTamperAlert)

	// Start background cleanup for stale upload sessions
	uploadManager.StartCleanup()

	// Start tamper protection if enabled
	if cfg.IsTamperProtectionEnabled() {
		if err := tamperProtection.Start(); err != nil {
			logger.Warn("failed to start tamper protection", "error", err)
		}
	}

	// Set up inventory watcher callbacks for event-driven updates
	inventoryWatcher.SetSoftwareCallback(h.sendSoftwareChanges)
	inventoryWatcher.SetServiceCallback(h.sendServiceChanges)

	// Set up threshold monitor callback for proactive alerts
	thresholdMonitor.SetAlertCallback(h.sendThresholdAlert)

	// Set up log push callback for proactive log forwarding
	actions.SetGlobalLogPushCallback(h.sendLogsPush)

	// Bootstrap PowerShell 7 and WinGet.Client module on startup (Windows only)
	// This runs in background to not block agent startup
	go func() {
		bootstrapCtx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		logger.Info("initial WinGet environment bootstrap starting")
		changed, err := winget.BootstrapWinGetEnvironment(bootstrapCtx, logger)
		if err != nil {
			logger.Warn("initial WinGet environment bootstrap failed", "error", err)
		} else if changed {
			logger.Info("WinGet environment initialized (PS7 and/or WinGet.Client module installed)")
		} else {
			logger.Debug("WinGet environment already up to date")
		}
	}()

	return h
}

// SetSelfHealingWatchdog sets the self-healing watchdog for connection monitoring.
func (h *Handler) SetSelfHealingWatchdog(w SelfHealingWatchdog) {
	h.selfHealingWatchdog = w
}

// recordConnectionSuccess notifies the watchdog of a successful connection.
func (h *Handler) recordConnectionSuccess() {
	if h.selfHealingWatchdog != nil {
		h.selfHealingWatchdog.RecordConnectionSuccess()
	}
}

// recordConnectionFailure notifies the watchdog of a connection failure.
func (h *Handler) recordConnectionFailure() {
	if h.selfHealingWatchdog != nil {
		h.selfHealingWatchdog.RecordConnectionFailure()
	}
}

// SetWingetHelperAvailable sets whether winget is available via helper in user context.
// This is called when an update scan via helper succeeds.
func (h *Handler) SetWingetHelperAvailable(available bool) {
	h.mu.Lock()
	h.wingetHelperAvailable = available
	h.mu.Unlock()
	if available {
		h.logger.Debug("winget helper availability updated", "available", available)
	}
}

// Default delay before scheduling a reboot after policy execution.
const defaultRebootDelaySeconds = 30

// ScheduleReboot schedules a system reboot after a delay.
// This consolidates the reboot scheduling logic used across multiple handlers.
func (h *Handler) ScheduleReboot(reason string) {
	go func() {
		time.Sleep(defaultRebootDelaySeconds * time.Second)
		h.logger.Info("initiating scheduled reboot", "reason", reason)
		if err := actions.RestartSystem(context.Background(), false, 0); err != nil {
			h.logger.Error("failed to schedule reboot", "error", err, "reason", reason)
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

// Note: registerHandlers is defined in actions.go

// Connect establishes a WebSocket connection to the server.
func (h *Handler) Connect(ctx context.Context) error {
	serverURL := h.cfg.GetServer()
	u, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("parsing server URL: %w", err)
	}

	// Convert HTTP(S) to WS(S)
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}
	u.Path = wsEndpoint
	u.RawQuery = "uuid=" + h.cfg.GetUUID()

	// Create custom dialer with TCP keepalive for better connection stability
	// This helps with NAT timeout issues and dead connection detection
	netDialer := &net.Dialer{
		Timeout:   connectionTimeout,
		KeepAlive: tcpKeepAlive,
	}

	dialer := websocket.Dialer{
		TLSClientConfig:   h.tlsConfig,
		HandshakeTimeout:  handshakeTimeout,
		NetDialContext:    netDialer.DialContext,
		EnableCompression: true,
	}

	headers := http.Header{}

	h.logger.Debug("connecting to server", "url", u.String())

	conn, resp, err := dialer.DialContext(ctx, u.String(), headers)
	if err != nil {
		// Audit log connection failure
		h.auditLogger.LogConnect(ctx, false, serverURL, err)

		if resp != nil {
			return fmt.Errorf("connecting to server (status %d): %w", resp.StatusCode, err)
		}
		return fmt.Errorf("connecting to server: %w", err)
	}

	h.mu.Lock()
	h.conn = conn
	h.mu.Unlock()

	// Notify self-healing watchdog of successful connection
	h.recordConnectionSuccess()

	h.logger.Info("connected to server")
	return nil
}

// Run starts the message handling loops.
func (h *Handler) Run(ctx context.Context) error {
	h.mu.RLock()
	conn := h.conn
	h.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("not connected")
	}

	// Exit maintenance mode on successful startup (handles post-update scenario)
	// This is safe to call even if we weren't in maintenance mode
	h.sendMaintenanceStatus(false, "Agent started successfully")
	h.logger.Info("sent maintenance mode exit signal")

	conn.SetReadLimit(maxMessageSize)
	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	// Start background auto-updater for agent
	h.updater.StartBackgroundUpdater(ctx)

	// Start background osquery updater (checks weekly)
	osquery.StartBackgroundUpdater(ctx, h.logger)

	// Start inventory watcher for event-driven updates
	h.inventoryWatcher.Start()
	h.logger.Info("inventory watcher started for software and service change detection")

	// Create a child context to cancel all goroutines when any one fails
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Start goroutines
	errCh := make(chan error, 3)

	go func() {
		errCh <- h.readPump(runCtx)
	}()

	go func() {
		errCh <- h.writePump(runCtx)
	}()

	go func() {
		errCh <- h.heartbeatPump(runCtx)
	}()

	var firstErr error
	select {
	case <-ctx.Done():
		firstErr = ctx.Err()
	case err := <-errCh:
		firstErr = err
	}

	// Notify self-healing watchdog of connection failure
	if firstErr != nil {
		h.recordConnectionFailure()
	}

	// Cancel all goroutines and drain send channel to prevent blocking
	cancel()
	h.drainSendChannel()

	return firstErr
}

// drainSendChannel removes all pending messages from the send channel.
// This prevents goroutines from blocking when the connection is lost.
func (h *Handler) drainSendChannel() {
	for {
		select {
		case <-h.sendCh:
			// Discard message
		default:
			return
		}
	}
}

// readPump handles incoming messages.
func (h *Handler) readPump(ctx context.Context) error {
	h.mu.RLock()
	conn := h.conn
	h.mu.RUnlock()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return nil
			}
			return fmt.Errorf("reading message: %w", err)
		}

		go h.handleMessage(ctx, message)
	}
}

// writePump handles outgoing messages.
func (h *Handler) writePump(ctx context.Context) error {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	h.mu.RLock()
	conn := h.conn
	h.mu.RUnlock()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case message := <-h.sendCh:
			conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return fmt.Errorf("writing message: %w", err)
			}
		case <-ticker.C:
			conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return fmt.Errorf("writing ping: %w", err)
			}
		}
	}
}

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

// checkAndRenewCertificates checks if certificates need renewal.
func (h *Handler) checkAndRenewCertificates(ctx context.Context) {
	h.logger.Info("performing periodic certificate check")
	h.lastCertCheck = time.Now()

	// Attempt certificate renewal
	if err := h.renewCertificates(ctx); err != nil {
		h.logger.Warn("certificate renewal check failed", "error", err)
		return
	}

	h.logger.Info("certificate check completed successfully")
}

// renewCertificates attempts to renew certificates from the server.
func (h *Handler) renewCertificates(ctx context.Context) error {
	client := &http.Client{
		Timeout: httpClientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: h.tlsConfig,
		},
	}

	url := h.cfg.GetServer() + "/api/v1/agents/" + h.cfg.GetUUID() + "/renew-cert"
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("X-Agent-UUID", h.cfg.GetUUID())

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	// 304 Not Modified means certificates are still valid
	if resp.StatusCode == http.StatusNotModified {
		h.logger.Debug("certificates are still valid")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("renewal failed with status %d", resp.StatusCode)
	}

	// Parse and save new certificates
	var renewResp struct {
		CACert     string `json:"ca_cert"`
		ClientCert string `json:"client_cert"`
		ClientKey  string `json:"client_key"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&renewResp); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	// Only save if we got new certificates
	if renewResp.CACert != "" && renewResp.ClientCert != "" && renewResp.ClientKey != "" {
		h.logger.Info("received new certificates, saving...")

		certPaths := mtls.CertPaths{
			CACert:     h.paths.CACert,
			ClientCert: h.paths.ClientCert,
			ClientKey:  h.paths.ClientKey,
		}

		if err := mtls.SaveCertificates(certPaths,
			[]byte(renewResp.CACert),
			[]byte(renewResp.ClientCert),
			[]byte(renewResp.ClientKey),
		); err != nil {
			return fmt.Errorf("saving certificates: %w", err)
		}

		h.logger.Info("certificates renewed and saved successfully")
	}

	return nil
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

	// Convert disk stats
	diskStats := make([]HeartbeatDisk, 0, len(stats.Disk))
	for _, d := range stats.Disk {
		diskStats = append(diskStats, HeartbeatDisk{
			Device:      d.Device,
			Mountpoint:  d.Mountpoint,
			Total:       d.Total,
			Used:        d.Used,
			Free:        d.Free,
			UsedPercent: d.UsedPercent,
		})
	}

	// Aggregate network I/O
	var totalBytesSent, totalBytesRecv, totalPacketsSent, totalPacketsRecv uint64
	for _, n := range stats.Network {
		totalBytesSent += n.BytesSent
		totalBytesRecv += n.BytesRecv
		totalPacketsSent += n.PacketsSent
		totalPacketsRecv += n.PacketsRecv
	}

	// Format heartbeat in the structure expected by the backend (Python-compatible)
	heartbeat := HeartbeatMessage{
		Action:       "heartbeat",
		Type:         "full",
		AgentVersion: version.Version,
		Stats: HeartbeatStats{
			CPUPercent:    stats.CPU.UsagePercent,
			MemoryPercent: stats.Memory.UsedPercent,
			MemoryUsed:    stats.Memory.Used,
			MemoryTotal:   stats.Memory.Total,
			Disk:          diskStats,
			NetworkIO: &HeartbeatNetworkIO{
				BytesSent:   totalBytesSent,
				BytesRecv:   totalBytesRecv,
				PacketsSent: totalPacketsSent,
				PacketsRecv: totalPacketsRecv,
			},
			UptimeSeconds: stats.Uptime,
			ProcessCount:  stats.ProcessCount,
			Timezone:      stats.Timezone,
		},
		ExternalIP:   stats.ExternalIP,
		SerialNumber: h.getSerialNumber(ctx),
	}

	// Add Proxmox info if this is a Proxmox host - delta-based (only send if changed)
	// Thread-safe access to lastProxmoxHash
	if proxmoxInfo := GetProxmoxInfo(ctx); proxmoxInfo != nil {
		proxmoxData := &HeartbeatProxmox{
			IsProxmox:      proxmoxInfo.IsProxmox,
			Version:        proxmoxInfo.Version,
			Release:        proxmoxInfo.Release,
			KernelVersion:  proxmoxInfo.KernelVersion,
			ClusterName:    proxmoxInfo.ClusterName,
			NodeName:       proxmoxInfo.NodeName,
			RepositoryType: proxmoxInfo.RepositoryType,
		}
		currentHash := hashStruct(proxmoxData)
		h.mu.Lock()
		if currentHash != h.lastProxmoxHash {
			heartbeat.Proxmox = proxmoxData
			h.lastProxmoxHash = currentHash
			h.logger.Debug("proxmox info changed, including in heartbeat")
		}
		h.mu.Unlock()
		// If unchanged, omit Proxmox field entirely to save bandwidth
	}

	// Add winget info on Windows - always include on full heartbeats
	// Auto-install winget if not available (runs asynchronously)
	if runtime.GOOS == "windows" {
		wingetClient := winget.GetDefault()
		// Periodically refresh winget detection to reduce CPU overhead
		h.mu.RLock()
		shouldRefresh := h.heartbeatCount%fullHeartbeatInterval == 0
		helperAvailable := h.wingetHelperAvailable
		h.mu.RUnlock()
		if shouldRefresh {
			wingetClient.Refresh()
		}
		status := wingetClient.GetStatus()

		// Auto-install winget if not available (trigger asynchronously every full heartbeat cycle)
		if !status.Available && shouldRefresh {
			go func() {
				installCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
				defer cancel()
				h.logger.Info("winget not available, attempting auto-installation")
				if err := winget.EnsureInstalled(installCtx, h.logger); err != nil {
					h.logger.Warn("winget auto-installation failed during heartbeat",
						"error", err)
				} else {
					// After successful installation, ensure only system-wide version exists
					h.logger.Info("cleaning up any per-user winget installations")
					_ = winget.EnsureSystemOnly(installCtx, h.logger)
				}
			}()
		}

		// Periodically clean up per-user winget installations (every 5 min)
		// This ensures users who install winget from Microsoft Store don't end up with duplicate installations
		if status.Available && shouldRefresh {
			go func() {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				_ = winget.EnsureSystemOnly(cleanupCtx, h.logger)
			}()
		}

		// Check for and install winget updates (every 60 min, tied to agent update interval)
		shouldCheckWingetUpdate := h.heartbeatCount%wingetUpdateInterval == 0
		if status.Available && shouldCheckWingetUpdate {
			go func() {
				updateCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
				defer cancel()
				h.logger.Info("checking for winget updates (60-minute cycle)")
				updated, err := winget.CheckAndUpdate(updateCtx, h.logger)
				if err != nil {
					h.logger.Warn("winget auto-update check failed", "error", err)
				} else if updated {
					h.logger.Info("winget was auto-updated to latest version")
				}
			}()
		}

		// Bootstrap PowerShell 7 and WinGet.Client module (every 60 min, alongside winget updates)
		// This ensures the optimal WinGet execution method is available
		if shouldCheckWingetUpdate {
			go func() {
				bootstrapCtx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
				defer cancel()
				h.logger.Info("bootstrapping WinGet environment (PS7 + WinGet.Client module)")
				changed, err := winget.BootstrapWinGetEnvironment(bootstrapCtx, h.logger)
				if err != nil {
					h.logger.Warn("WinGet environment bootstrap failed", "error", err)
				} else if changed {
					h.logger.Info("WinGet environment was updated (PS7 or WinGet.Client module installed/updated)")
					// Refresh winget status after bootstrap
					wingetClient.Refresh()
				}
			}()
		}

		wingetData := &HeartbeatWinget{
			Available:                   status.Available,
			Version:                     status.Version,
			BinaryPath:                  status.BinaryPath,
			SystemLevel:                 status.SystemLevel,
			HelperAvailable:             helperAvailable,
			PowerShell7Available:        status.PowerShell7Available,
			WinGetClientModuleAvailable: status.WinGetClientModuleAvailable,
		}
		// Always include winget data on full heartbeats so backend can trigger auto-install
		heartbeat.Winget = wingetData
		// Update hash for tracking changes (used elsewhere)
		currentHash := hashStruct(wingetData)
		h.mu.Lock()
		if currentHash != h.lastWingetHash {
			h.lastWingetHash = currentHash
			h.logger.Debug("winget status changed",
				"available", status.Available,
				"version", status.Version,
				"binary_path", status.BinaryPath,
				"system_level", status.SystemLevel,
			)
		}
		h.mu.Unlock()
	}

	h.SendRaw(heartbeat)

	// Check thresholds and send proactive alerts if needed
	// This runs alongside every heartbeat to detect critical conditions early
	h.thresholdMonitor.Update(stats)

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

// handleMessage processes an incoming message.
func (h *Handler) handleMessage(ctx context.Context, data []byte) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		h.logger.Error("parsing message", "error", err)
		return
	}
	// Store raw message for handlers that need to parse additional fields
	msg.Raw = data

	h.logger.Debug("received message", "action", msg.Action, "request_id", msg.RequestID, "scan_type", msg.ScanType)

	// Security Layer 1: Rate limiting
	if !h.rateLimiter.Allow(msg.Action) {
		h.logger.Warn("rate limit exceeded",
			"action", msg.Action,
			"request_id", msg.RequestID,
		)
		h.auditLogger.LogRateLimit(ctx, msg.Action, 0, 0)
		h.Send(Response{
			Action:    msg.Action,
			RequestID: msg.RequestID,
			Success:   false,
			Error:     "rate limit exceeded",
		})
		return
	}

	// Security Layer 2: Anti-replay protection (for requests with request_id)
	if msg.RequestID != "" {
		// Extract timestamp if present in message
		var msgWithTime struct {
			Timestamp int64 `json:"timestamp"`
		}
		json.Unmarshal(data, &msgWithTime)

		requestTime := time.Now()
		if msgWithTime.Timestamp > 0 {
			requestTime = time.Unix(msgWithTime.Timestamp, 0)
		}

		if err := h.antiReplay.ValidateRequest(msg.RequestID, requestTime); err != nil {
			h.logger.Warn("replay detection triggered",
				"action", msg.Action,
				"request_id", msg.RequestID,
				"error", err,
			)
			h.auditLogger.LogReplayAttempt(ctx, msg.RequestID, requestTime)
			h.Send(Response{
				Action:    msg.Action,
				RequestID: msg.RequestID,
				Success:   false,
				Error:     "request validation failed",
			})
			return
		}
	}

	handler, ok := h.handlers[msg.Action]
	if !ok {
		h.logger.Warn("unknown action", "action", msg.Action)
		h.Send(Response{
			Action:    msg.Action,
			RequestID: msg.RequestID,
			Success:   false,
			Error:     fmt.Sprintf("unknown action: %s", msg.Action),
		})
		return
	}

	// Log handler dispatch for software installation actions
	if msg.Action == "download_and_install_pkg" || msg.Action == "download_and_install_msi" ||
		msg.Action == "download_and_install_cask" || msg.Action == "install_software" {
		h.logger.Info("dispatching software installation action", "action", msg.Action)
	}

	// Determine what data to pass to the handler
	// Some actions have fields at the root level rather than in a nested "data" object
	var handlerData json.RawMessage
	rootLevelActions := map[string]bool{
		// osquery
		"run_osquery": true,
		"osquery":     true,
		// Terminal actions - fields are at root level (rows, cols, data, etc.)
		"terminal":        true,
		"terminal_input":  true,
		"terminal_resize": true,
		"start_terminal":  true,
		"stop_terminal":   true,
		"terminal_stop":   true,
		"terminal_output": true,
		// File browser actions - path, old_path, new_path at root
		"list_dir":      true,
		"create_folder": true,
		"create_dir":    true,
		"delete_entry":  true,
		"rename_entry":  true,
		"zip_entry":     true,
		"unzip_entry":   true,
		"download_file": true,
		"chmod":         true,
		"chown":         true,
		// Upload actions - path, data, offset, is_last at root
		"upload_chunk":   true,
		"start_upload":   true,
		"finish_upload":  true,
		"cancel_upload":  true,
		"download_chunk": true,
		"download_url":   true,
		// Compliance checks - policy_id, checks at root
		"run_compliance_check": true,
		// Software installation actions - all fields at root
		"install_software":           true,
		"download_and_install_msi":   true,
		"download_and_install_pkg":   true,
		"download_and_install_cask":  true,
		"cancel_software_install":    true,
		// Software uninstallation actions - all fields at root
		"uninstall_software":         true,
		"uninstall_msi":              true,
		"uninstall_pkg":              true,
		"uninstall_cask":             true,
		"uninstall_deb":              true,
		"uninstall_rpm":              true,
		"cancel_software_uninstall":  true,
	}
	if rootLevelActions[msg.Action] {
		handlerData = msg.Raw
	} else if len(msg.Data) > 0 {
		handlerData = msg.Data
	} else {
		// If no data field, pass the raw message so handlers can parse root-level fields
		handlerData = msg.Raw
	}

	result, err := handler(ctx, handlerData)

	// For run_osquery, use the OsqueryResponse format expected by the backend
	if msg.Action == "run_osquery" {
		osqResp := OsqueryResponse{
			Action:    "run_osquery",
			ScanType:  msg.ScanType,
			Data:      result,
			RequestID: msg.RequestID,
		}
		if err != nil {
			osqResp.Data = map[string]string{"error": err.Error()}
		}
		h.SendRaw(osqResp)
		return
	}

	// Map request actions to response actions where needed
	responseAction := msg.Action
	if mapped, ok := actionToResponseAction[msg.Action]; ok {
		responseAction = mapped
	}

	resp := Response{
		Action:    responseAction,
		RequestID: msg.RequestID,
		Success:   err == nil,
		Data:      result,
	}
	if err != nil {
		resp.Error = err.Error()
	}

	h.Send(resp)
}

// Send sends a response to the server.
func (h *Handler) Send(resp Response) {
	data, err := json.Marshal(resp)
	if err != nil {
		h.logger.Error("marshaling response", "error", err)
		return
	}

	select {
	case h.sendCh <- data:
	default:
		h.logger.Warn("send channel full, dropping message")
	}
}

// SendRaw sends any message to the server without wrapping.
func (h *Handler) SendRaw(msg interface{}) {
	data, err := json.Marshal(msg)
	if err != nil {
		h.logger.Error("marshaling message", "error", err)
		return
	}

	select {
	case h.sendCh <- data:
	default:
		h.logger.Warn("send channel full, dropping message")
	}
}

// Close closes the WebSocket connection.
func (h *Handler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Stop inventory watcher
	if h.inventoryWatcher != nil {
		h.inventoryWatcher.Stop()
	}

	// Stop upload manager cleanup goroutine
	if h.uploadManager != nil {
		h.uploadManager.Stop()
	}

	// Stop anti-replay protection cleanup
	if h.antiReplay != nil {
		h.antiReplay.Stop()
	}

	// Close audit logger
	if h.auditLogger != nil {
		h.auditLogger.Close()
	}

	// Close Proxmox client
	CloseProxmoxClient()

	if h.conn != nil {
		h.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		return h.conn.Close()
	}
	return nil
}

// Basic handler implementations

func (h *Handler) handlePing(ctx context.Context, data json.RawMessage) (interface{}, error) {
	return map[string]string{"pong": "ok"}, nil
}

func (h *Handler) handleGetSystemStats(ctx context.Context, data json.RawMessage) (interface{}, error) {
	return h.monitor.GetStats(ctx)
}

func (h *Handler) handleHeartbeat(ctx context.Context, data json.RawMessage) (interface{}, error) {
	return h.monitor.GetStats(ctx)
}
