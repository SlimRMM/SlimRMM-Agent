// Package handler provides WebSocket message handling for the agent.
// It processes incoming messages and dispatches them to action handlers.
package handler

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/slimrmm/slimrmm-agent/internal/actions"
	"github.com/slimrmm/slimrmm-agent/internal/config"
	"github.com/slimrmm/slimrmm-agent/internal/eventlog"
	"github.com/slimrmm/slimrmm-agent/internal/monitor"
	"github.com/slimrmm/slimrmm-agent/internal/osquery"
	"github.com/slimrmm/slimrmm-agent/internal/security/antireplay"
	"github.com/slimrmm/slimrmm-agent/internal/security/audit"
	"github.com/slimrmm/slimrmm-agent/internal/security/ratelimit"
	"github.com/slimrmm/slimrmm-agent/internal/services/backup"
	"github.com/slimrmm/slimrmm-agent/internal/services/compliance"
	"github.com/slimrmm/slimrmm-agent/internal/services/models"
	"github.com/slimrmm/slimrmm-agent/internal/services/process"
	"github.com/slimrmm/slimrmm-agent/internal/services/software"
	"github.com/slimrmm/slimrmm-agent/internal/services/validation"
	wingetservice "github.com/slimrmm/slimrmm-agent/internal/services/winget"
	"github.com/slimrmm/slimrmm-agent/internal/tamper"
	"github.com/slimrmm/slimrmm-agent/internal/updater"
	"github.com/slimrmm/slimrmm-agent/internal/winget"
)

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

	// msgSem is a buffered semaphore that caps concurrently-executing message
	// handler goroutines spawned by readPump. Acquiring the slot before the
	// goroutine is spawned creates natural backpressure — if the server floods
	// the agent with messages, WebSocket reads will stall instead of spawning
	// unbounded goroutines (memory DoS).
	msgSem chan struct{}

	// maintenanceMode indicates whether the agent is currently in operator-managed
	// maintenance. Accessed via atomic.Bool from IsInMaintenance / SetMaintenance.
	maintenanceMode atomic.Bool

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
	lastHyperVHash  string
	lastDockerHash  string
	lastWingetHash  string

	// Winget update failure tracking (exponential backoff on repeated failures)
	wingetUpdateFailCount    int
	wingetUpdateBackoffUntil time.Time

	// Winget helper availability (updated by update scans)
	wingetHelperAvailable bool

	// Cached hardware serial number (doesn't change)
	cachedSerialNumber  string
	serialNumberFetched bool

	// Security modules for multi-layered protection
	rateLimiter *ratelimit.ActionLimiter
	antiReplay  *antireplay.Protector
	auditLogger *audit.Logger

	// Self-healing watchdog for connection monitoring
	selfHealingWatchdog SelfHealingWatchdog

	// Software services for installation/uninstallation operations
	softwareServices *software.Services

	// Validation service for pre-uninstall validation
	validationService *validation.DefaultValidationService

	// Compliance service for compliance check operations
	complianceService *compliance.DefaultComplianceService

	// Process service for process management operations
	processService *process.DefaultProcessService

	// Backup services for backup orchestration
	backupOrchestrator         *backup.Orchestrator
	restoreOrchestrator        *backup.RestoreOrchestrator
	collectorRegistry          *backup.CollectorRegistry
	restorerRegistry           *backup.RestorerRegistry
	capabilityDetector         *backup.CapabilityDetector
	lastBackupCapsHash         string
	cachedBackupCaps           *backup.BackupCapabilities
	streamingOrchestrator      *backup.StreamingOrchestrator
	streamingCollectorRegistry *backup.StreamingCollectorRegistry

	// Winget upgrade service for package upgrades
	wingetUpgradeService *wingetservice.UpgradeService

	// Event log collection manager
	eventLogManager *eventlog.Manager
}

// New creates a new Handler.
func New(cfg *config.Config, paths config.Paths, tlsConfig *tls.Config, logger *slog.Logger) *Handler {
	uploadManager := actions.NewUploadManager()

	// Initialize tamper protection
	tamperConfig := tamper.Config{
		Enabled:          cfg.IsTamperProtectionEnabled(),
		UninstallKeyHash: cfg.GetUninstallKeyHash(),
		WatchdogEnabled:  cfg.IsWatchdogEnabled(),
		AlertOnTamper:    cfg.IsTamperAlertEnabled(),
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

	// Initialize compliance service for compliance checks
	complianceService := compliance.NewServices(logger)

	// Initialize process service for process management
	processService := process.NewServices(logger)

	// Initialize backup orchestration services
	collectorRegistry := backup.NewCollectorRegistry()
	restorerRegistry := backup.NewRestorerRegistry()

	// Register Docker collectors
	dockerDeps := backup.NewDefaultDockerDeps()
	backupLogger := backup.NewSlogLogger(logger)
	collectorRegistry.Register(backup.NewDockerContainerCollector(dockerDeps, backupLogger))
	collectorRegistry.Register(backup.NewDockerVolumeCollector(dockerDeps, backupLogger))
	collectorRegistry.Register(backup.NewDockerImageCollector(dockerDeps, backupLogger))
	collectorRegistry.Register(backup.NewDockerComposeCollector(backupLogger))

	// Register Agent collectors
	agentPaths := backup.AgentPaths{
		ConfigFile: paths.ConfigFile,
		CACert:     paths.CACert,
		ClientCert: paths.ClientCert,
		LogDir:     paths.LogDir,
		DataDir:    paths.BaseDir,
	}
	configWrapper := backup.NewConfigWrapper(cfg)
	osqueryWrapper := backup.NewOsqueryWrapper()
	collectorRegistry.Register(backup.NewAgentConfigCollector(agentPaths, configWrapper))
	collectorRegistry.Register(backup.NewAgentLogsCollector(agentPaths, configWrapper, backupLogger))
	collectorRegistry.Register(backup.NewSystemStateCollector(configWrapper, osqueryWrapper))
	collectorRegistry.Register(backup.NewSoftwareInventoryCollector(configWrapper, osqueryWrapper))
	// ComplianceCache path is in the data directory
	collectorRegistry.Register(backup.NewComplianceResultsCollector(configWrapper, ""))

	// Register Files and Folders collector
	collectorRegistry.Register(backup.NewFilesAndFoldersCollector(configWrapper, backupLogger))

	// Register Database collectors
	collectorRegistry.Register(backup.NewPostgreSQLCollector())
	collectorRegistry.Register(backup.NewMySQLCollector())

	// Register Restorers
	restorerRegistry.Register(backup.NewDockerContainerRestorer(dockerDeps, backupLogger))
	restorerRegistry.Register(backup.NewDockerVolumeRestorer(dockerDeps, backupLogger))
	restorerRegistry.Register(backup.NewDockerImageRestorer(dockerDeps, backupLogger))
	restorerRegistry.Register(backup.NewFilesAndFoldersRestorer(backupLogger))
	restorerRegistry.Register(backup.NewAgentConfigRestorer(agentPaths, backupLogger))
	restorerRegistry.Register(backup.NewAgentLogsRestorer(agentPaths, backupLogger))
	// Database restorers
	restorerRegistry.Register(backup.NewPostgreSQLRestorer(backupLogger))
	restorerRegistry.Register(backup.NewMySQLRestorer(backupLogger))

	// Initialize STREAMING collector registry for memory-safe Docker backups
	// This prevents OOM by piping data directly from docker export to upload
	// instead of loading entire container into memory
	streamingCollectorRegistry := backup.NewStreamingCollectorRegistry()
	tempDir := paths.BaseDir // Use agent data dir for temp files
	streamingCollectorRegistry.Register(backup.NewStreamingDockerContainerCollector(logger, tempDir))
	streamingCollectorRegistry.Register(backup.NewStreamingDockerVolumeCollector(logger, tempDir))
	streamingCollectorRegistry.Register(backup.NewStreamingDockerImageCollector(logger, tempDir))
	streamingCollectorRegistry.Register(backup.NewStreamingDockerComposeCollector(logger, tempDir))
	// Database streaming collectors for memory-safe database backups
	streamingCollectorRegistry.Register(backup.NewStreamingPostgreSQLCollector(logger))
	streamingCollectorRegistry.Register(backup.NewStreamingMySQLCollector(logger))

	// Create streaming orchestrator for large backups (Docker types and databases)
	streamingOrchestrator := backup.NewStreamingOrchestrator(streamingCollectorRegistry, backup.StreamingOrchestratorConfig{
		Logger:           logger,
		CompressionLevel: backup.CompressionBalanced,
		MaxMemoryUsage:   512 * 1024 * 1024, // 512 MB max
		TempDir:          tempDir,
	})

	backupOrchestrator := backup.NewOrchestrator(collectorRegistry, backup.OrchestratorConfig{
		Logger: logger,
	})
	restoreOrchestrator := backup.NewRestoreOrchestrator(restorerRegistry, backup.OrchestratorConfig{
		Logger: logger,
	})

	// Initialize backup capability detector
	capabilityDetector := backup.NewCapabilityDetector(collectorRegistry)

	// Initialize winget upgrade service
	wingetUpgradeService := wingetservice.NewUpgradeService(logger)

	h := &Handler{
		cfg:                        cfg,
		paths:                      paths,
		tlsConfig:                  tlsConfig,
		monitor:                    monitor.New(),
		logger:                     logger,
		handlers:                   make(map[string]ActionHandler),
		terminalManager:            actions.NewTerminalManager(),
		uploadManager:              uploadManager,
		sendCh:                     make(chan []byte, 256),
		done:                       make(chan struct{}),
		msgSem:                     make(chan struct{}, MaxConcurrentHandlers),
		updater:                    updater.New(logger),
		tamperProtection:           tamperProtection,
		inventoryWatcher:           inventoryWatcher,
		adaptiveHeartbeat:          adaptiveHeartbeat,
		thresholdMonitor:           thresholdMonitor,
		rateLimiter:                rateLimiter,
		antiReplay:                 antiReplay,
		auditLogger:                auditLogger,
		softwareServices:           softwareServices,
		validationService:          validationService,
		complianceService:          complianceService,
		processService:             processService,
		backupOrchestrator:         backupOrchestrator,
		restoreOrchestrator:        restoreOrchestrator,
		collectorRegistry:          collectorRegistry,
		restorerRegistry:           restorerRegistry,
		capabilityDetector:         capabilityDetector,
		streamingOrchestrator:      streamingOrchestrator,
		streamingCollectorRegistry: streamingCollectorRegistry,
		wingetUpgradeService:       wingetUpgradeService,
	}

	// Initialize event log collection manager
	h.eventLogManager = eventlog.NewManager(
		paths.BaseDir,
		func(events []eventlog.EventEntry) error {
			h.SendRaw(map[string]interface{}{
				"action": "event_logs_batch",
				"events": events,
			})
			return nil
		},
		logger,
	)

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
// The watchdog receives connection success/failure notifications to trigger
// automatic recovery actions when the agent loses connectivity.
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

// SetWingetHelperAvailable sets whether winget is available via the helper process.
// This is called when an update scan via helper succeeds, indicating that winget
// can be used in user context through the helper binary for interactive operations.
func (h *Handler) SetWingetHelperAvailable(available bool) {
	h.mu.Lock()
	h.wingetHelperAvailable = available
	h.mu.Unlock()
	if available {
		h.logger.Debug("winget helper availability updated", "available", available)
	}
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

	// Report watchdog restart to backend if this connection follows a restart
	if h.selfHealingWatchdog != nil {
		if restartCount := h.selfHealingWatchdog.GetRestartCount(); restartCount > 0 {
			h.logger.Warn("WATCHDOG: reporting restart recovery to backend",
				"restart_count", restartCount,
			)
			h.SendRaw(map[string]interface{}{
				"action": "watchdog_restart",
				"data": map[string]interface{}{
					"restart_count": restartCount,
					"reason":        "connection_timeout",
				},
			})
		}
	}

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

// Send marshals and sends a Response to the server via WebSocket.
// Thread-safe: uses a buffered channel for non-blocking sends.
// If the send channel is full, the message is dropped with a warning log.
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

// SendRaw marshals and sends any message to the server without Response wrapping.
// Use this for custom message formats like heartbeats, alerts, and progress updates.
// Thread-safe: uses a buffered channel for non-blocking sends.
// If the send channel is full, the message is dropped with a warning log.
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

// Close gracefully shuts down the handler and closes the WebSocket connection.
// It stops all background services including the inventory watcher, upload manager,
// anti-replay protection, and audit logger. Sends a WebSocket close message
// before closing the underlying connection. Thread-safe.
func (h *Handler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Signal all background goroutines (e.g. ScheduleReboot timers) that the
	// agent is shutting down. Closing is idempotent: guarded by a select to
	// avoid a double-close panic if Close() is ever invoked twice.
	select {
	case <-h.done:
		// already closed
	default:
		close(h.done)
	}

	// Stop event log manager
	if h.eventLogManager != nil {
		h.eventLogManager.Stop()
	}

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
		if wErr := h.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")); wErr != nil {
			h.logger.Debug("writing websocket close frame", "error", wErr)
		}
		if cErr := h.conn.Close(); cErr != nil {
			h.logger.Warn("closing websocket connection", "error", cErr)
			return cErr
		}
	}
	return nil
}
