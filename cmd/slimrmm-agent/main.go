// SlimRMM Agent - Remote Monitoring & Management Agent
// Copyright (c) 2025 Kiefer Networks
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/config"
	"github.com/slimrmm/slimrmm-agent/internal/handler"
	"github.com/slimrmm/slimrmm-agent/internal/installer"
	"github.com/slimrmm/slimrmm-agent/internal/logging"
	"github.com/slimrmm/slimrmm-agent/internal/remotedesktop"
	"github.com/slimrmm/slimrmm-agent/internal/security/mtls"
	"github.com/slimrmm/slimrmm-agent/internal/service"
	"github.com/slimrmm/slimrmm-agent/internal/updater"
	"github.com/slimrmm/slimrmm-agent/pkg/version"
)

func main() {
	// Parse command line flags
	var (
		showVersion    = flag.Bool("version", false, "Show version information")
		showInfo       = flag.Bool("info", false, "Show detailed agent information")
		doUpdate       = flag.Bool("update", false, "Check for and install updates")
		uninstall      = flag.Bool("uninstall", false, "Uninstall the agent")
		installService = flag.Bool("install-service", false, "Install as system service")
		debug          = flag.Bool("debug", false, "Enable debug logging")
	)
	flag.Parse()

	// Show version
	if *showVersion {
		fmt.Println(version.Get().String())
		os.Exit(0)
	}

	// Show detailed info
	if *showInfo {
		runShowInfo()
		os.Exit(0)
	}

	// Run update
	if *doUpdate {
		runUpdate()
		os.Exit(0)
	}

	// Get paths first (needed for log directory)
	paths := config.DefaultPaths()

	// Setup logging to both file and stdout
	logger, logCleanup, err := logging.SetupWithDefaults(paths.LogDir, *debug)
	if err != nil {
		// Fallback to simple stdout logging
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
		logCleanup = func() {}
	}
	defer logCleanup()
	slog.SetDefault(logger)

	// Handle service installation
	if *installService {
		if err := runInstallService(paths, logger); err != nil {
			logger.Error("service installation failed", "error", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Handle uninstall
	if *uninstall {
		if err := runUninstall(paths, logger); err != nil {
			logger.Error("uninstallation failed", "error", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Run the agent (with auto-install if needed)
	if err := run(paths, logger); err != nil {
		logger.Error("agent failed", "error", err)
		os.Exit(1)
	}
}

func run(paths config.Paths, logger *slog.Logger) error {
	logger.Info("starting SlimRMM Agent", "version", version.Get().Version)

	// Initialize platform-specific permissions (e.g., macOS screen recording)
	remotedesktop.InitializePermissions(logger)

	// Load configuration - or auto-install if ENV vars are set
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		if err == config.ErrConfigNotFound {
			// Config doesn't exist - check for auto-install via ENV
			serverURL := os.Getenv("SLIMRMM_SERVER")
			if serverURL != "" {
				logger.Info("no config found, auto-registering with server", "url", serverURL)
				cfg, err = autoInstall(serverURL, paths, logger)
				if err != nil {
					return fmt.Errorf("auto-install failed: %w", err)
				}
			} else {
				return fmt.Errorf("no config found and SLIMRMM_SERVER not set - run with SLIMRMM_SERVER=https://your-server.com")
			}
		} else {
			return fmt.Errorf("loading config: %w", err)
		}
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
			return fmt.Errorf("creating TLS config: %w", err)
		}
		logger.Info("mTLS enabled")
	} else {
		tlsConfig, err = mtls.NewTLSConfig(nil, nil)
		if err != nil {
			return fmt.Errorf("creating TLS config: %w", err)
		}
		logger.Warn("mTLS not enabled or certificates not found")
	}

	// Create handler
	h := handler.New(cfg, paths, tlsConfig, logger)

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	// Connection loop with exponential backoff (matches Python agent)
	const (
		initialReconnectDelay = 5 * time.Second
		maxReconnectDelay     = 5 * time.Minute // 300 seconds like Python
		backoffMultiplier     = 2.0
	)

	reconnectDelay := initialReconnectDelay

	for {
		select {
		case <-ctx.Done():
			logger.Info("shutting down")
			return h.Close()
		default:
		}

		if err := h.Connect(ctx); err != nil {
			logger.Error("connection failed", "error", err, "retry_in", reconnectDelay)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(reconnectDelay):
				// Exponential backoff
				reconnectDelay = time.Duration(float64(reconnectDelay) * backoffMultiplier)
				if reconnectDelay > maxReconnectDelay {
					reconnectDelay = maxReconnectDelay
				}
				continue
			}
		}

		// Reset delay on successful connection
		reconnectDelay = initialReconnectDelay
		logger.Info("connected successfully, resetting reconnect delay")

		// Update last connection time
		cfg.SetLastConnection(time.Now().UTC().Format(time.RFC3339))
		cfg.Save()

		if err := h.Run(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			logger.Error("handler error", "error", err, "retry_in", reconnectDelay)
			h.Close()

			select {
			case <-ctx.Done():
				return nil
			case <-time.After(reconnectDelay):
				// Exponential backoff
				reconnectDelay = time.Duration(float64(reconnectDelay) * backoffMultiplier)
				if reconnectDelay > maxReconnectDelay {
					reconnectDelay = maxReconnectDelay
				}
				continue
			}
		}
	}
}

// autoInstall registers the agent if no config exists.
// This is called automatically when SLIMRMM_SERVER is set.
func autoInstall(serverURL string, paths config.Paths, logger *slog.Logger) (*config.Config, error) {
	// Create directories
	if err := config.EnsureDirectories(paths); err != nil {
		return nil, fmt.Errorf("creating directories: %w", err)
	}

	// Check for enrollment token
	enrollmentToken := os.Getenv("SLIMRMM_TOKEN")
	if enrollmentToken != "" {
		logger.Info("enrollment token provided for auto-approval")
	}

	// Register with server and get UUID + certificates
	logger.Info("registering with server", "url", serverURL)
	cfg, err := installer.Register(serverURL, enrollmentToken, paths)
	if err != nil {
		return nil, fmt.Errorf("registration failed: %w", err)
	}

	logger.Info("registration successful", "uuid", cfg.GetUUID())
	return cfg, nil
}

// runInstallService installs the agent as a system service.
// This should be called after the binary is placed in the correct location.
func runInstallService(paths config.Paths, logger *slog.Logger) error {
	logger.Info("installing SlimRMM Agent as system service")

	// Check if already installed
	if installer.IsServiceInstalled() {
		logger.Info("service already installed, updating...")
	}

	// Check for server URL and enrollment token
	serverURL := os.Getenv("SLIMRMM_SERVER")
	enrollmentToken := os.Getenv("SLIMRMM_TOKEN")
	var existingUUID string

	if enrollmentToken != "" {
		logger.Info("enrollment token provided for auto-approval")
	}

	if serverURL == "" {
		// Try to load existing config
		cfg, err := config.Load(paths.ConfigFile)
		if err != nil {
			return fmt.Errorf("SLIMRMM_SERVER not set and no existing config found")
		}
		serverURL = cfg.GetServer()
		existingUUID = cfg.GetUUID()
		logger.Info("using server from existing config", "url", serverURL, "uuid", existingUUID)
	} else {
		// Server URL provided, but check for existing UUID to re-use
		cfg, err := config.Load(paths.ConfigFile)
		if err == nil && cfg.GetUUID() != "" {
			existingUUID = cfg.GetUUID()
			logger.Info("found existing UUID for re-registration", "uuid", existingUUID)
		}
	}

	// Create directories
	if err := config.EnsureDirectories(paths); err != nil {
		return fmt.Errorf("creating directories: %w", err)
	}

	// Check if we need to register (no existing config or UUID)
	cfg, err := config.Load(paths.ConfigFile)
	if err == config.ErrConfigNotFound || (err == nil && cfg.GetUUID() == "") {
		logger.Info("registering with server", "url", serverURL)
		cfg, err = installer.Register(serverURL, enrollmentToken, paths)
		if err != nil {
			return fmt.Errorf("registration failed: %w", err)
		}
		logger.Info("registration successful", "uuid", cfg.GetUUID())
	} else if err != nil {
		return fmt.Errorf("loading config: %w", err)
	} else {
		// Agent already has a UUID - re-register to get new certificates
		// This is needed when the agent is reinstalled or updated
		if existingUUID != "" {
			logger.Info("re-registering with existing UUID to obtain new certificates", "uuid", existingUUID)
			cfg, err = installer.RegisterWithExistingUUID(serverURL, enrollmentToken, paths, existingUUID)
			if err != nil {
				return fmt.Errorf("re-registration failed: %w", err)
			}
			logger.Info("re-registration successful", "uuid", cfg.GetUUID())
		} else {
			logger.Info("using existing registration", "uuid", cfg.GetUUID())
		}
	}

	// Install and start service
	if err := installer.InstallService(); err != nil {
		return fmt.Errorf("installing service: %w", err)
	}

	logger.Info("service installed and started successfully")
	return nil
}

func runUninstall(paths config.Paths, logger *slog.Logger) error {
	logger.Info("uninstalling SlimRMM Agent")

	// Stop and remove service
	if installer.IsServiceInstalled() {
		logger.Info("removing service...")
		if err := installer.UninstallService(); err != nil {
			logger.Warn("failed to remove service", "error", err)
		}
	}

	// Remove configuration and certificates
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

	logger.Info("uninstallation complete")
	return nil
}

func runShowInfo() {
	paths := config.DefaultPaths()

	// Try to load configuration
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		// Show version info even if config is missing
		v := version.Get()
		fmt.Println("SlimRMM Agent Information")
		fmt.Println("=========================")
		fmt.Printf("Version:         %s\n", v.Version)
		fmt.Printf("Git Commit:      %s\n", v.GitCommit)
		fmt.Printf("Build Date:      %s\n", v.BuildDate)
		fmt.Println()
		fmt.Printf("Config Status:   Not installed or config not found\n")
		fmt.Printf("Config Path:     %s\n", paths.ConfigFile)
		return
	}

	// Get and print full info
	info := service.GetAgentInfo(cfg)
	info.PrintInfo()
}

func runUpdate() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	u := updater.New(logger)
	ctx := context.Background()

	fmt.Println("Checking for updates...")
	info, err := u.CheckForUpdate(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to check for updates: %v\n", err)
		os.Exit(1)
	}

	if info == nil {
		fmt.Printf("Already running the latest version (%s)\n", version.Get().Version)
		return
	}

	fmt.Printf("Update available: %s -> %s\n", version.Get().Version, info.Version)
	fmt.Println("Downloading and installing update...")

	result, err := u.PerformUpdate(ctx, info)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Update failed: %v\n", err)
		os.Exit(1)
	}

	if result.Success {
		fmt.Println("Update completed successfully!")
		if result.RestartNeeded {
			fmt.Println("Service restart required.")
		}
	} else {
		fmt.Fprintf(os.Stderr, "Update failed: %s\n", result.Error)
		os.Exit(1)
	}
}
