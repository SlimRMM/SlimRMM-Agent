// SlimRMM Agent - Remote Monitoring & Management Agent
// Copyright (c) 2025 Kiefer Networks
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/actions"
	"github.com/slimrmm/slimrmm-agent/internal/config"
	"github.com/slimrmm/slimrmm-agent/internal/handler"
	"github.com/slimrmm/slimrmm-agent/internal/installer"
	"github.com/slimrmm/slimrmm-agent/internal/logging"
	"github.com/slimrmm/slimrmm-agent/internal/osquery"
	"github.com/slimrmm/slimrmm-agent/internal/proxmox"
	"github.com/slimrmm/slimrmm-agent/internal/remotedesktop"
	"github.com/slimrmm/slimrmm-agent/internal/security/mtls"
	"github.com/slimrmm/slimrmm-agent/internal/selfhealing"
	"github.com/slimrmm/slimrmm-agent/internal/service"
	"github.com/slimrmm/slimrmm-agent/internal/updater"
	"github.com/slimrmm/slimrmm-agent/internal/winget"
	"github.com/slimrmm/slimrmm-agent/pkg/version"
)

const helpText = `SlimRMM Agent - Remote Monitoring & Management

Usage: slimrmm-agent [command] [options]

Commands:
  install     Install and configure the agent as a system service
  uninstall   Stop and remove the agent service
  info        Show agent status and configuration (alias: status)
  status      Show agent status and configuration (alias: info)
  update      Check for and install updates
  run         Run the agent in foreground (for debugging)

Options:
  -s, --server URL     Server URL (required for install)
  -k, --key TOKEN      Enrollment token for auto-approval (optional)
  -d, --debug          Enable debug logging
  -v, --version        Show version information
  -h, --help           Show this help message

Examples:
  # Install with enrollment token (recommended)
  sudo slimrmm-agent install -s https://rmm.example.com -k YOUR_TOKEN

  # Install without token (requires manual approval)
  sudo slimrmm-agent install -s https://rmm.example.com

  # Uninstall completely
  sudo slimrmm-agent uninstall

  # Check status/info
  slimrmm-agent info
  slimrmm-agent status

  # Update to latest version
  sudo slimrmm-agent update
`

func main() {
	// Parse arguments
	args := parseArgs(os.Args[1:])

	// Handle help (only when explicitly requested)
	if args.help {
		fmt.Print(helpText)
		os.Exit(0)
	}

	// Handle version
	if args.version {
		fmt.Println(version.Get().String())
		os.Exit(0)
	}

	// Get paths
	paths := config.DefaultPaths()

	// Setup logging
	logger, logCleanup, err := logging.SetupWithDefaults(paths.LogDir, args.debug)
	if err != nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
		logCleanup = func() {}
	}
	defer logCleanup()
	slog.SetDefault(logger)

	// Execute command
	var exitCode int
	switch args.command {
	case "install":
		exitCode = cmdInstall(args, paths, logger)
	case "uninstall":
		exitCode = cmdUninstall(paths, logger)
	case "info", "status":
		exitCode = cmdStatus(paths)
	case "update":
		exitCode = cmdUpdate(logger)
	case "run":
		exitCode = cmdRun(paths, logger)
	case "":
		// No command - check if this is being run as a service
		// On Windows, check if we're running as a Windows Service
		if runtime.GOOS == "windows" && service.IsRunningAsService() {
			// Running as Windows Service - use SCM handler
			exitCode = cmdRunAsWindowsService(paths, logger)
		} else if installer.IsServiceInstalled() {
			// Running from service manager (systemd/launchd) or manual start
			exitCode = cmdRun(paths, logger)
		} else {
			fmt.Print(helpText)
			exitCode = 0
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", args.command)
		fmt.Print(helpText)
		exitCode = 1
	}

	os.Exit(exitCode)
}

type arguments struct {
	command string
	server  string
	key     string
	debug   bool
	version bool
	help    bool
}

func parseArgs(args []string) arguments {
	result := arguments{}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-s", "--server":
			if i+1 < len(args) {
				result.server = args[i+1]
				i++
			}
		case "-k", "--key":
			if i+1 < len(args) {
				result.key = args[i+1]
				i++
			}
		case "-d", "--debug":
			result.debug = true
		case "-v", "--version":
			result.version = true
		case "-h", "--help":
			result.help = true
		case "install", "uninstall", "status", "info", "update", "run":
			result.command = arg
		default:
			// Check for legacy flags for backwards compatibility
			if arg == "--install-service" {
				result.command = "install"
			} else if arg == "--uninstall" {
				result.command = "uninstall"
			} else if arg == "--info" || arg == "--status" {
				result.command = "info"
			} else if arg == "--update" {
				result.command = "update"
			}
		}
	}

	// Check environment variables as fallback
	if result.server == "" {
		result.server = os.Getenv("SLIMRMM_SERVER")
	}
	if result.key == "" {
		result.key = os.Getenv("SLIMRMM_TOKEN")
	}

	return result
}

// cmdInstall installs and configures the agent
func cmdInstall(args arguments, paths config.Paths, logger *slog.Logger) int {
	fmt.Println("SlimRMM Agent Installation")
	fmt.Println("==========================")

	// Check if already configured
	existingCfg, err := config.Load(paths.ConfigFile)
	if err == nil && existingCfg.GetUUID() != "" {
		fmt.Printf("Agent already configured (UUID: %s)\n", existingCfg.GetUUID())

		// Stop existing service if running
		if installer.IsServiceInstalled() {
			fmt.Println("Stopping existing service...")
			if err := installer.StopService(); err != nil {
				logger.Warn("failed to stop service", "error", err)
			}
		}

		// Re-register to get fresh certificates
		if args.server == "" {
			args.server = existingCfg.GetServer()
		}

		fmt.Println("Re-registering to obtain new certificates...")
		_, err = installer.RegisterWithExistingUUID(args.server, args.key, paths, existingCfg.GetUUID())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Re-registration failed: %v\n", err)
			return 1
		}

		// Install and start service
		fmt.Println("Starting service...")
		if err := installer.InstallService(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start service: %v\n", err)
			return 1
		}

		fmt.Println("\n✓ Agent updated and running")
		return 0
	}

	// Fresh install - server URL required
	if args.server == "" {
		fmt.Fprintln(os.Stderr, "Error: Server URL required for fresh installation")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Usage: slimrmm-agent install -s https://your-server.com [-k TOKEN]")
		return 1
	}

	// Create directories
	fmt.Println("Creating directories...")
	if err := config.EnsureDirectories(paths); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create directories: %v\n", err)
		return 1
	}

	// Stop existing service if running (upgrade from old version)
	if installer.IsServiceInstalled() {
		fmt.Println("Stopping existing service...")
		_ = installer.StopService()
	}

	// Register with server
	fmt.Printf("Connecting to %s...\n", args.server)
	if args.key != "" {
		fmt.Println("Using enrollment token for auto-approval")
	} else {
		fmt.Println("No enrollment token provided - manual approval required")
		fmt.Println("An admin must approve this agent in the web UI")
		fmt.Println("")
	}

	// Progress callback for approval wait
	progressCb := func(status string, message string) {
		fmt.Printf("\r\033[K  %s", message) // Clear line and print status
		if status != "pending" {
			fmt.Println() // New line when done
		}
	}

	cfg, err := installer.RegisterWithProgress(args.server, args.key, paths, progressCb)
	if err != nil {
		fmt.Println() // Ensure we're on a new line
		if err == installer.ErrRejected {
			fmt.Fprintln(os.Stderr, "Registration rejected by admin")
		} else {
			fmt.Fprintf(os.Stderr, "Registration failed: %v\n", err)
		}
		return 1
	}

	fmt.Printf("Agent registered (UUID: %s)\n", cfg.GetUUID())

	// Install service
	fmt.Println("Installing service...")
	if err := installer.InstallService(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to install service: %v\n", err)
		return 1
	}

	fmt.Println("\n✓ Installation complete")
	fmt.Println("  Agent is now running and connected to the server")
	return 0
}

// cmdUninstall removes the agent
func cmdUninstall(paths config.Paths, logger *slog.Logger) int {
	fmt.Println("Uninstalling SlimRMM Agent...")

	// Stop and remove service
	if installer.IsServiceInstalled() {
		fmt.Println("Stopping service...")
		if err := installer.StopService(); err != nil {
			logger.Warn("failed to stop service", "error", err)
		}

		fmt.Println("Removing service...")
		if err := installer.UninstallService(); err != nil {
			logger.Warn("failed to remove service", "error", err)
		}
	}

	// Remove configuration
	fmt.Println("Removing configuration...")
	filesToRemove := []string{
		paths.ConfigFile,
		paths.CACert,
		paths.ClientCert,
		paths.ClientKey,
	}

	for _, f := range filesToRemove {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			logger.Warn("failed to remove file", "file", f, "error", err)
		}
	}

	fmt.Println("\n✓ Agent uninstalled")
	return 0
}

// cmdStatus shows agent status
func cmdStatus(paths config.Paths) int {
	fmt.Println("SlimRMM Agent Status")
	fmt.Println("====================")

	v := version.Get()
	fmt.Printf("Version:     %s\n", v.Version)
	fmt.Printf("Git Commit:  %s\n", v.GitCommit)
	fmt.Printf("Build Date:  %s\n", v.BuildDate)
	fmt.Println()

	// Check service status
	if installer.IsServiceInstalled() {
		running, err := installer.IsServiceRunning()
		if err != nil {
			fmt.Printf("Service:     Installed (status unknown)\n")
		} else if running {
			fmt.Printf("Service:     Running\n")
		} else {
			fmt.Printf("Service:     Stopped\n")
		}
	} else {
		fmt.Printf("Service:     Not installed\n")
	}

	// Load config
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		fmt.Printf("Config:      Not found\n")
		return 0
	}

	fmt.Printf("Config:      %s\n", paths.ConfigFile)
	fmt.Printf("Log Path:    %s\n", filepath.Join(paths.LogDir, "agent.log"))
	fmt.Println()

	hostname, _ := os.Hostname()
	fmt.Printf("UUID:        %s\n", cfg.GetUUID())
	fmt.Printf("Server:      %s\n", cfg.GetServer())
	fmt.Printf("mTLS:        %v\n", cfg.IsMTLSEnabled())
	fmt.Printf("Hostname:    %s\n", hostname)
	fmt.Printf("Platform:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println()

	// Connection status
	fmt.Println("Connection")
	fmt.Println("----------")
	fmt.Printf("Last Connection: %s\n", valueOrNA(cfg.GetLastConnection()))
	fmt.Printf("Last Heartbeat:  %s\n", valueOrNA(cfg.GetLastHeartbeat()))
	fmt.Println()

	// Security status
	fmt.Println("Security")
	fmt.Println("--------")
	tamperStatus := "Disabled"
	if cfg.IsTamperProtectionEnabled() {
		tamperStatus = "Enabled"
		if cfg.IsWatchdogEnabled() {
			tamperStatus += " (Watchdog active)"
		}
	}
	fmt.Printf("Tamper Protection: %s\n", tamperStatus)
	fmt.Println()

	// System information
	fmt.Println("System")
	fmt.Println("------")
	fmt.Printf("Boot Time:   %s\n", getSystemBootTime())

	// osquery availability
	osqueryClient := osquery.New()
	osqueryStatus := "Not available"
	if osqueryClient.IsAvailable() {
		version := osqueryClient.GetVersion()
		if version != "" {
			osqueryStatus = fmt.Sprintf("v%s (%s)", version, osqueryClient.GetBinaryPath())
		} else {
			osqueryStatus = fmt.Sprintf("Available (%s)", osqueryClient.GetBinaryPath())
		}
	}
	fmt.Printf("osquery:     %s\n", osqueryStatus)

	// winget availability (Windows only)
	if runtime.GOOS == "windows" {
		wingetClient := winget.New()
		wingetStatus := "Not available"
		if wingetClient.IsAvailable() {
			version := wingetClient.GetVersion()
			if version != "" {
				wingetStatus = fmt.Sprintf("v%s (%s)", version, wingetClient.GetBinaryPath())
			} else {
				wingetStatus = fmt.Sprintf("Available (%s)", wingetClient.GetBinaryPath())
			}
		}
		fmt.Printf("winget:      %s\n", wingetStatus)
	}

	// Docker availability
	dockerStatus := "Not available"
	if actions.IsDockerAvailable() {
		dockerStatus = "Available"
	}
	fmt.Printf("Docker:      %s\n", dockerStatus)

	// Proxmox availability
	proxmoxStatus := "Not available"
	if proxmox.IsProxmoxHost() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pveInfo := proxmox.Detect(ctx)
		if pveInfo.Version != "" {
			proxmoxStatus = fmt.Sprintf("Available (v%s)", pveInfo.Version)
		} else {
			proxmoxStatus = "Available"
		}
	}
	fmt.Printf("Proxmox:     %s\n", proxmoxStatus)

	return 0
}

// valueOrNA returns the value or "N/A" if empty.
func valueOrNA(s string) string {
	if s == "" {
		return "N/A"
	}
	return s
}

// getSystemBootTime returns the system boot time as a formatted string.
func getSystemBootTime() string {
	switch runtime.GOOS {
	case "darwin":
		return getDarwinBootTime()
	case "linux":
		return getLinuxBootTime()
	case "windows":
		return getWindowsBootTime()
	default:
		return "N/A"
	}
}

// getDarwinBootTime gets boot time on macOS using sysctl.
func getDarwinBootTime() string {
	cmd := exec.Command("sysctl", "-n", "kern.boottime")
	output, err := cmd.Output()
	if err != nil {
		return "N/A"
	}
	// Output format: { sec = 1704067200, usec = 0 } ...
	var sec int64
	_, err = fmt.Sscanf(string(output), "{ sec = %d,", &sec)
	if err != nil {
		return "N/A"
	}
	bootTime := time.Unix(sec, 0)
	return bootTime.Format("2006-01-02 15:04:05")
}

// getLinuxBootTime gets boot time on Linux from /proc/stat.
func getLinuxBootTime() string {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return "N/A"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "btime ") {
			var btime int64
			_, err := fmt.Sscanf(line, "btime %d", &btime)
			if err != nil {
				return "N/A"
			}
			bootTime := time.Unix(btime, 0)
			return bootTime.Format("2006-01-02 15:04:05")
		}
	}
	return "N/A"
}

// getWindowsBootTime gets boot time on Windows using wmic.
func getWindowsBootTime() string {
	cmd := exec.Command("wmic", "os", "get", "LastBootUpTime", "/value")
	output, err := cmd.Output()
	if err != nil {
		return "N/A"
	}
	// Output format: LastBootUpTime=20240101120000.000000+000
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "LastBootUpTime=") {
			timeStr := strings.TrimPrefix(line, "LastBootUpTime=")
			timeStr = strings.TrimSpace(timeStr)
			if len(timeStr) >= 14 {
				// Parse WMI datetime format: YYYYMMDDHHMMSS
				t, err := time.Parse("20060102150405", timeStr[:14])
				if err == nil {
					return t.Format("2006-01-02 15:04:05")
				}
			}
		}
	}
	return "N/A"
}

// cmdUpdate checks for and installs updates
func cmdUpdate(logger *slog.Logger) int {
	fmt.Println("Checking for updates...")

	u := updater.New(logger)
	ctx := context.Background()

	info, err := u.CheckForUpdate(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to check for updates: %v\n", err)
		return 1
	}

	if info == nil {
		fmt.Printf("Already running the latest version (%s)\n", version.Get().Version)
		return 0
	}

	fmt.Printf("Update available: %s -> %s\n", version.Get().Version, info.Version)
	fmt.Println("Downloading and installing...")

	result, err := u.PerformUpdate(ctx, info)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Update failed: %v\n", err)
		return 1
	}

	if result.Success {
		fmt.Println("\n✓ Update complete")
		if result.RestartNeeded {
			fmt.Println("  Service will restart automatically")
		}
		return 0
	}

	fmt.Fprintf(os.Stderr, "Update failed: %s\n", result.Error)
	return 1
}

// cmdRun runs the agent in foreground
func cmdRun(paths config.Paths, logger *slog.Logger) int {
	logger.Info("starting SlimRMM Agent", "version", version.Get().Version)

	// Initialize platform-specific permissions
	remotedesktop.InitializePermissions(logger)

	// Ensure osquery is installed (auto-install if not present)
	// This runs asynchronously to not block agent startup
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		if err := osquery.EnsureInstalled(ctx, logger); err != nil {
			if err == osquery.ErrArchLinux {
				logger.Warn("osquery auto-installation not available",
					"reason", "Arch Linux requires manual installation",
					"instruction", "Install from AUR: yay -S osquery")
			} else {
				logger.Warn("osquery auto-installation failed",
					"error", err,
					"note", "osquery features may be unavailable")
			}
		}
	}()

	// Load configuration
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		if err == config.ErrConfigNotFound {
			logger.Error("agent not configured - run 'slimrmm-agent install' first")
			return 1
		}
		logger.Error("failed to load config", "error", err)
		return 1
	}

	// Setup mTLS
	certPaths := &mtls.CertPaths{
		CACert:     paths.CACert,
		ClientCert: paths.ClientCert,
		ClientKey:  paths.ClientKey,
	}

	var tlsConfig *tls.Config
	if cfg.IsMTLSEnabled() && mtls.CertificatesExist(*certPaths) {
		tlsConfig, err = mtls.NewTLSConfig(certPaths, nil)
		if err != nil {
			logger.Error("failed to create TLS config", "error", err)
			return 1
		}
		logger.Info("mTLS enabled")
	} else {
		tlsConfig, err = mtls.NewTLSConfig(nil, nil)
		if err != nil {
			logger.Error("failed to create TLS config", "error", err)
			return 1
		}
		logger.Warn("mTLS not enabled or certificates not found")
	}

	// Create handler
	h := handler.New(cfg, paths, tlsConfig, logger)

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create and start self-healing watchdog
	watchdog := selfhealing.New(selfhealing.DefaultConfig(), logger)
	h.SetSelfHealingWatchdog(watchdog)
	watchdog.Start(ctx)
	defer watchdog.Stop()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	// Run the agent loop with panic recovery
	var exitCode int
	watchdog.RecoverFromPanic("agent_loop", func() {
		exitCode = runAgentLoop(ctx, h, cfg, logger)
	})
	return exitCode
}

// runAgentLoop contains the main connection loop logic, shared between cmdRun and Windows service mode
func runAgentLoop(ctx context.Context, h *handler.Handler, cfg *config.Config, logger *slog.Logger) int {
	// Connection loop with exponential backoff and jitter
	// Jitter prevents thundering herd when many agents reconnect simultaneously
	const (
		initialReconnectDelay = 5 * time.Second
		maxReconnectDelay     = 5 * time.Minute
		backoffMultiplier     = 2.0
		jitterFactor          = 0.3 // Add up to 30% random jitter
	)

	// addJitter adds random jitter to delay to prevent thundering herd
	addJitter := func(delay time.Duration) time.Duration {
		jitter := time.Duration(float64(delay) * jitterFactor * rand.Float64())
		return delay + jitter
	}

	reconnectDelay := initialReconnectDelay

	for {
		select {
		case <-ctx.Done():
			logger.Info("shutting down")
			return 0
		default:
		}

		if err := h.Connect(ctx); err != nil {
			delayWithJitter := addJitter(reconnectDelay)
			logger.Error("connection failed", "error", err, "retry_in", delayWithJitter.Round(time.Second))
			select {
			case <-ctx.Done():
				return 0
			case <-time.After(delayWithJitter):
				reconnectDelay = time.Duration(float64(reconnectDelay) * backoffMultiplier)
				if reconnectDelay > maxReconnectDelay {
					reconnectDelay = maxReconnectDelay
				}
				continue
			}
		}

		reconnectDelay = initialReconnectDelay
		logger.Info("connected successfully")

		cfg.SetLastConnection(time.Now().UTC().Format(time.RFC3339))
		cfg.Save()

		if err := h.Run(ctx); err != nil {
			if ctx.Err() != nil {
				return 0
			}
			delayWithJitter := addJitter(reconnectDelay)
			logger.Error("handler error", "error", err, "retry_in", delayWithJitter.Round(time.Second))
			h.Close()

			select {
			case <-ctx.Done():
				return 0
			case <-time.After(delayWithJitter):
				reconnectDelay = time.Duration(float64(reconnectDelay) * backoffMultiplier)
				if reconnectDelay > maxReconnectDelay {
					reconnectDelay = maxReconnectDelay
				}
				continue
			}
		}
	}
}

// agentRunner implements service.AgentRunner for Windows Service support
type agentRunner struct {
	paths    config.Paths
	logger   *slog.Logger
	handler  *handler.Handler
	cfg      *config.Config
	cancel   context.CancelFunc
	watchdog *selfhealing.Watchdog
}

// Run starts the agent and blocks until the context is cancelled
func (r *agentRunner) Run(ctx context.Context) error {
	r.logger.Info("starting SlimRMM Agent (Windows Service)", "version", version.Get().Version)

	// Initialize platform-specific permissions
	remotedesktop.InitializePermissions(r.logger)

	// Ensure osquery is installed (auto-install if not present)
	go func() {
		osqCtx, osqCancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer osqCancel()

		if err := osquery.EnsureInstalled(osqCtx, r.logger); err != nil {
			r.logger.Warn("osquery auto-installation failed",
				"error", err,
				"note", "osquery features may be unavailable")
		}
	}()

	// Load configuration
	cfg, err := config.Load(r.paths.ConfigFile)
	if err != nil {
		if err == config.ErrConfigNotFound {
			r.logger.Error("agent not configured - run 'slimrmm-agent install' first")
			return err
		}
		r.logger.Error("failed to load config", "error", err)
		return err
	}
	r.cfg = cfg

	// Setup mTLS
	certPaths := &mtls.CertPaths{
		CACert:     r.paths.CACert,
		ClientCert: r.paths.ClientCert,
		ClientKey:  r.paths.ClientKey,
	}

	var tlsConfig *tls.Config
	if cfg.IsMTLSEnabled() && mtls.CertificatesExist(*certPaths) {
		tlsConfig, err = mtls.NewTLSConfig(certPaths, nil)
		if err != nil {
			r.logger.Error("failed to create TLS config", "error", err)
			return err
		}
		r.logger.Info("mTLS enabled")
	} else {
		tlsConfig, err = mtls.NewTLSConfig(nil, nil)
		if err != nil {
			r.logger.Error("failed to create TLS config", "error", err)
			return err
		}
		r.logger.Warn("mTLS not enabled or certificates not found")
	}

	// Create handler
	r.handler = handler.New(cfg, r.paths, tlsConfig, r.logger)

	// Create and start self-healing watchdog
	r.watchdog = selfhealing.New(selfhealing.DefaultConfig(), r.logger)
	r.handler.SetSelfHealingWatchdog(r.watchdog)
	r.watchdog.Start(ctx)
	defer r.watchdog.Stop()

	// Run the agent loop with panic recovery
	var exitCode int
	r.watchdog.RecoverFromPanic("agent_loop", func() {
		exitCode = runAgentLoop(ctx, r.handler, cfg, r.logger)
	})
	if exitCode != 0 {
		return fmt.Errorf("agent exited with code %d", exitCode)
	}
	return nil
}

// Stop signals the agent to stop
func (r *agentRunner) Stop() {
	r.logger.Info("stop requested")
	if r.handler != nil {
		r.handler.Close()
	}
}

// cmdRunAsWindowsService runs the agent as a Windows Service
func cmdRunAsWindowsService(paths config.Paths, logger *slog.Logger) int {
	logger.Info("starting as Windows Service")

	runner := &agentRunner{
		paths:  paths,
		logger: logger,
	}

	if err := service.RunAsService(runner, logger); err != nil {
		logger.Error("Windows service failed", "error", err)
		return 1
	}

	return 0
}
