// Package selfhealing provides self-healing capabilities for the agent.
// It monitors connection state and automatically restarts the service
// when problems are detected to ensure maximum availability.
package selfhealing

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultConnectionTimeout is the maximum time without a successful connection
	// before triggering a service restart.
	DefaultConnectionTimeout = 30 * time.Minute

	// DefaultHealthCheckInterval is how often to check the connection health.
	DefaultHealthCheckInterval = 1 * time.Minute

	// RestartCooldown prevents rapid restart loops.
	RestartCooldown = 5 * time.Minute

	// MaxConsecutiveRestarts limits restart attempts to prevent infinite loops.
	MaxConsecutiveRestarts = 3
)

// Config holds the self-healing configuration.
type Config struct {
	// ConnectionTimeout is the maximum time without connection before restart.
	ConnectionTimeout time.Duration

	// HealthCheckInterval is how often to check health.
	HealthCheckInterval time.Duration

	// Enabled controls whether self-healing is active.
	Enabled bool
}

// DefaultConfig returns the default self-healing configuration.
func DefaultConfig() Config {
	return Config{
		ConnectionTimeout:   DefaultConnectionTimeout,
		HealthCheckInterval: DefaultHealthCheckInterval,
		Enabled:             true,
	}
}

// Watchdog monitors agent health and triggers restarts when needed.
type Watchdog struct {
	config Config
	logger *slog.Logger

	// Connection tracking
	lastSuccessfulConnection atomic.Value // time.Time
	isConnected              atomic.Bool

	// Restart tracking
	lastRestartAttempt    time.Time
	consecutiveRestarts   int
	mu                    sync.Mutex

	// Shutdown
	done chan struct{}
	wg   sync.WaitGroup
}

// New creates a new self-healing watchdog.
func New(config Config, logger *slog.Logger) *Watchdog {
	w := &Watchdog{
		config: config,
		logger: logger,
		done:   make(chan struct{}),
	}
	w.lastSuccessfulConnection.Store(time.Now())
	return w
}

// Start begins the watchdog monitoring.
func (w *Watchdog) Start(ctx context.Context) {
	if !w.config.Enabled {
		w.logger.Info("self-healing watchdog disabled")
		return
	}

	w.wg.Add(1)
	go w.monitorLoop(ctx)
	w.logger.Info("self-healing watchdog started",
		"connection_timeout", w.config.ConnectionTimeout,
		"check_interval", w.config.HealthCheckInterval,
	)
}

// Stop stops the watchdog.
func (w *Watchdog) Stop() {
	close(w.done)
	w.wg.Wait()
}

// RecordConnectionSuccess records a successful connection/heartbeat.
func (w *Watchdog) RecordConnectionSuccess() {
	w.lastSuccessfulConnection.Store(time.Now())
	w.isConnected.Store(true)

	// Reset restart counter on successful connection
	w.mu.Lock()
	w.consecutiveRestarts = 0
	w.mu.Unlock()
}

// RecordConnectionFailure records a connection failure.
func (w *Watchdog) RecordConnectionFailure() {
	w.isConnected.Store(false)
}

// GetLastConnectionTime returns the last successful connection time.
func (w *Watchdog) GetLastConnectionTime() time.Time {
	return w.lastSuccessfulConnection.Load().(time.Time)
}

// IsHealthy returns true if the agent is considered healthy.
func (w *Watchdog) IsHealthy() bool {
	lastConn := w.GetLastConnectionTime()
	return time.Since(lastConn) < w.config.ConnectionTimeout
}

// monitorLoop runs the health check loop.
func (w *Watchdog) monitorLoop(ctx context.Context) {
	defer w.wg.Done()

	ticker := time.NewTicker(w.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
			w.checkHealth()
		}
	}
}

// checkHealth evaluates agent health and triggers restart if needed.
func (w *Watchdog) checkHealth() {
	lastConn := w.GetLastConnectionTime()
	timeSinceConnection := time.Since(lastConn)

	if timeSinceConnection >= w.config.ConnectionTimeout {
		w.logger.Warn("connection timeout exceeded",
			"last_connection", lastConn,
			"timeout", w.config.ConnectionTimeout,
			"time_since", timeSinceConnection,
		)
		w.triggerRestart("connection timeout exceeded")
	}
}

// triggerRestart initiates a service restart.
func (w *Watchdog) triggerRestart(reason string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Check cooldown
	if time.Since(w.lastRestartAttempt) < RestartCooldown {
		w.logger.Warn("restart skipped due to cooldown",
			"last_restart", w.lastRestartAttempt,
			"cooldown", RestartCooldown,
		)
		return
	}

	// Check consecutive restart limit
	if w.consecutiveRestarts >= MaxConsecutiveRestarts {
		w.logger.Error("max consecutive restarts reached, giving up",
			"max_restarts", MaxConsecutiveRestarts,
			"consecutive", w.consecutiveRestarts,
		)
		return
	}

	w.lastRestartAttempt = time.Now()
	w.consecutiveRestarts++

	w.logger.Warn("initiating service restart",
		"reason", reason,
		"attempt", w.consecutiveRestarts,
	)

	// Perform restart asynchronously to allow current operation to complete
	go w.performRestart()
}

// performRestart executes the platform-specific restart command.
func (w *Watchdog) performRestart() {
	// Small delay to allow log flush
	time.Sleep(2 * time.Second)

	var cmd *exec.Cmd
	var err error

	switch runtime.GOOS {
	case "darwin":
		// macOS: Use launchctl to restart the service
		// kickstart -k kills the current instance and starts a new one
		cmd = exec.Command("launchctl", "kickstart", "-k", "system/io.slimrmm.agent")
		err = cmd.Run()
		if err != nil {
			// Fallback: try stop and start
			w.logger.Warn("kickstart failed, trying stop/start", "error", err)
			exec.Command("launchctl", "stop", "io.slimrmm.agent").Run()
			time.Sleep(1 * time.Second)
			cmd = exec.Command("launchctl", "start", "io.slimrmm.agent")
			err = cmd.Run()
		}

	case "linux":
		// Linux: Use systemctl to restart the service
		cmd = exec.Command("systemctl", "restart", "slimrmm-agent")
		err = cmd.Run()

	case "windows":
		// Windows: Use sc.exe or net stop/start
		exec.Command("net", "stop", "SlimRMMAgent").Run()
		time.Sleep(2 * time.Second)
		cmd = exec.Command("net", "start", "SlimRMMAgent")
		err = cmd.Run()

	default:
		w.logger.Error("unsupported platform for self-restart", "os", runtime.GOOS)
		return
	}

	if err != nil {
		w.logger.Error("service restart failed", "error", err)
	} else {
		w.logger.Info("service restart initiated successfully")
	}

	// Exit this process - the service manager will start a new one
	os.Exit(0)
}

// TriggerImmediateRestart forces an immediate restart (for panic recovery).
func (w *Watchdog) TriggerImmediateRestart(reason string) {
	w.logger.Error("immediate restart triggered", "reason", reason)
	w.performRestart()
}

// RecoverFromPanic wraps a function with panic recovery.
// If a panic occurs, it logs the error and triggers a restart.
func (w *Watchdog) RecoverFromPanic(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			// Get stack trace
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			stack := string(buf[:n])

			w.logger.Error("panic recovered",
				"component", name,
				"panic", r,
				"stack", stack,
			)

			// Trigger restart
			w.TriggerImmediateRestart("panic in " + name)
		}
	}()
	fn()
}

// WrapWithRecovery returns a function wrapped with panic recovery.
func (w *Watchdog) WrapWithRecovery(name string, fn func()) func() {
	return func() {
		w.RecoverFromPanic(name, fn)
	}
}
