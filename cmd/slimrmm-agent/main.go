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
	"github.com/slimrmm/slimrmm-agent/internal/security/mtls"
	"github.com/slimrmm/slimrmm-agent/internal/service"
	"github.com/slimrmm/slimrmm-agent/internal/updater"
	"github.com/slimrmm/slimrmm-agent/pkg/version"
)

func main() {
	// Parse command line flags
	var (
		showVersion = flag.Bool("version", false, "Show version information")
		showInfo    = flag.Bool("info", false, "Show detailed agent information")
		doUpdate    = flag.Bool("update", false, "Check for and install updates")
		install     = flag.Bool("install", false, "Install the agent")
		uninstall   = flag.Bool("uninstall", false, "Uninstall the agent")
		serverURL   = flag.String("server", "", "Server URL for registration")
		regKey      = flag.String("key", "", "Registration key")
		debug       = flag.Bool("debug", false, "Enable debug logging")
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

	// Setup logging
	logLevel := slog.LevelInfo
	if *debug {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	// Get paths
	paths := config.DefaultPaths()

	// Handle install/uninstall
	if *install {
		if err := runInstall(*serverURL, *regKey, paths, logger); err != nil {
			logger.Error("installation failed", "error", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *uninstall {
		if err := runUninstall(paths, logger); err != nil {
			logger.Error("uninstallation failed", "error", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Run the agent
	if err := run(paths, logger); err != nil {
		logger.Error("agent failed", "error", err)
		os.Exit(1)
	}
}

func run(paths config.Paths, logger *slog.Logger) error {
	logger.Info("starting SlimRMM Agent", "version", version.Get().Version)

	// Load configuration
	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
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

	// Connection loop with reconnection
	for {
		select {
		case <-ctx.Done():
			logger.Info("shutting down")
			return h.Close()
		default:
		}

		if err := h.Connect(ctx); err != nil {
			logger.Error("connection failed", "error", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(10 * time.Second):
				continue
			}
		}

		if err := h.Run(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			logger.Error("handler error", "error", err)
			h.Close()

			select {
			case <-ctx.Done():
				return nil
			case <-time.After(5 * time.Second):
				continue
			}
		}
	}
}

func runInstall(serverURL, regKey string, paths config.Paths, logger *slog.Logger) error {
	logger.Info("installing SlimRMM Agent")

	// Check for required parameters
	if serverURL == "" {
		// Try environment variable
		serverURL = os.Getenv("SLIMRMM_SERVER")
	}
	if regKey == "" {
		regKey = os.Getenv("SLIMRMM_KEY")
	}

	if serverURL == "" {
		return fmt.Errorf("server URL is required (use --server or SLIMRMM_SERVER)")
	}

	// Create directories
	if err := config.EnsureDirectories(paths); err != nil {
		return fmt.Errorf("creating directories: %w", err)
	}

	// Register with server and get UUID + certificates
	logger.Info("registering with server", "url", serverURL)
	cfg, err := installer.Register(serverURL, regKey, paths)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	logger.Info("registration successful", "uuid", cfg.GetUUID())
	logger.Info("installation complete", "config", paths.ConfigFile)
	return nil
}

func runUninstall(paths config.Paths, logger *slog.Logger) error {
	logger.Info("uninstalling SlimRMM Agent")

	// TODO: Stop and remove service

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
