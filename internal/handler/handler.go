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
	"github.com/slimrmm/slimrmm-agent/internal/monitor"
	"github.com/slimrmm/slimrmm-agent/internal/osquery"
	"github.com/slimrmm/slimrmm-agent/internal/security/mtls"
	"github.com/slimrmm/slimrmm-agent/internal/tamper"
	"github.com/slimrmm/slimrmm-agent/internal/updater"
	"github.com/slimrmm/slimrmm-agent/internal/winget"
	"github.com/slimrmm/slimrmm-agent/pkg/version"
)

const (
	writeWait         = 10 * time.Second
	pongWait          = 60 * time.Second
	pingPeriod        = (pongWait * 9) / 10
	heartbeatPeriod   = 30 * time.Second
	maxMessageSize    = 10 * 1024 * 1024 // 10 MB
	certCheckInterval = 24 * time.Hour   // Check certificates every 24 hours (like Python)
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
	AgentVersion string              `json:"agent_version"`
	Stats        HeartbeatStats      `json:"stats"`
	ExternalIP   string              `json:"external_ip,omitempty"`
	Proxmox      *HeartbeatProxmox   `json:"proxmox,omitempty"`
	Winget       *HeartbeatWinget    `json:"winget,omitempty"`
}

// HeartbeatWinget contains Windows Package Manager (winget) information.
type HeartbeatWinget struct {
	Available   bool   `json:"available"`
	Version     string `json:"version,omitempty"`
	SystemLevel bool   `json:"system_level"`
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

	// Inventory watcher for event-driven updates
	inventoryWatcher *monitor.InventoryWatcher

	// Adaptive heartbeat for dynamic intervals
	adaptiveHeartbeat *monitor.AdaptiveHeartbeat

	// Threshold monitor for proactive alerts
	thresholdMonitor *monitor.ThresholdMonitor

	// Delta tracking for heartbeat optimization - only send when changed
	lastProxmoxHash string
	lastWingetHash  string
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
	}

	h.registerHandlers()

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

	return h
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
	u.Path = "/api/v1/ws/agent"
	u.RawQuery = "uuid=" + h.cfg.GetUUID()

	// Create custom dialer with TCP keepalive for better connection stability
	// This helps with NAT timeout issues and dead connection detection
	netDialer := &net.Dialer{
		Timeout:   30 * time.Second, // Connection timeout
		KeepAlive: 30 * time.Second, // TCP keepalive interval
	}

	dialer := websocket.Dialer{
		TLSClientConfig:   h.tlsConfig,
		HandshakeTimeout:  15 * time.Second,
		NetDialContext:    netDialer.DialContext,
		EnableCompression: true, // Enable compression for better performance over slow links
	}

	headers := http.Header{}

	h.logger.Info("connecting to server", "url", u.String())

	conn, resp, err := dialer.DialContext(ctx, u.String(), headers)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("connecting to server (status %d): %w", resp.StatusCode, err)
		}
		return fmt.Errorf("connecting to server: %w", err)
	}

	h.mu.Lock()
	h.conn = conn
	h.mu.Unlock()

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

	// Start goroutines
	errCh := make(chan error, 3)

	go func() {
		errCh <- h.readPump(ctx)
	}()

	go func() {
		errCh <- h.writePump(ctx)
	}()

	go func() {
		errCh <- h.heartbeatPump(ctx)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
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
		Timeout: 30 * time.Second,
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
		ExternalIP: stats.ExternalIP,
	}

	// Add Proxmox info if this is a Proxmox host - delta-based (only send if changed)
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
		if currentHash != h.lastProxmoxHash {
			heartbeat.Proxmox = proxmoxData
			h.lastProxmoxHash = currentHash
			h.logger.Debug("proxmox info changed, including in heartbeat")
		}
		// If unchanged, omit Proxmox field entirely to save bandwidth
	}

	// Add winget info on Windows - delta-based (only send if changed)
	if runtime.GOOS == "windows" {
		wingetClient := winget.GetDefault()
		// Only refresh winget detection every 10 heartbeats (~5 minutes)
		// to reduce CPU overhead while still detecting changes
		if h.heartbeatCount%10 == 0 {
			wingetClient.Refresh()
		}
		status := wingetClient.GetStatus()
		wingetData := &HeartbeatWinget{
			Available:   status.Available,
			Version:     status.Version,
			SystemLevel: status.SystemLevel,
		}
		currentHash := hashStruct(wingetData)
		if currentHash != h.lastWingetHash {
			heartbeat.Winget = wingetData
			h.lastWingetHash = currentHash
			h.logger.Debug("winget status changed, including in heartbeat",
				"available", status.Available,
				"version", status.Version,
				"system_level", status.SystemLevel,
			)
		}
		// If unchanged, omit Winget field entirely to save bandwidth
	}

	h.SendRaw(heartbeat)

	// Check thresholds and send proactive alerts if needed
	// This runs alongside every heartbeat to detect critical conditions early
	h.thresholdMonitor.Update(stats)

	// Update last heartbeat time in config
	h.cfg.SetLastHeartbeat(time.Now().UTC().Format(time.RFC3339))

	// Periodically save config to persist LastHeartbeat (every 10 heartbeats = ~5 minutes)
	h.heartbeatCount++
	if h.heartbeatCount >= 10 {
		h.heartbeatCount = 0
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
	h.heartbeatCount++
	if h.heartbeatCount >= 10 {
		h.heartbeatCount = 0
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
