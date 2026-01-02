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

	"github.com/kiefernetworks/slimrmm-agent/internal/config"
	"github.com/kiefernetworks/slimrmm-agent/internal/handler"
	"github.com/kiefernetworks/slimrmm-agent/internal/security/mtls"
	"github.com/kiefernetworks/slimrmm-agent/pkg/version"
)

func main() {
	// Parse command line flags
	var (
		showVersion = flag.Bool("version", false, "Show version information")
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

	// Create configuration
	cfg := config.New(serverURL, paths)

	// TODO: Register with server and get UUID + certificates
	// This will be implemented in the registration module

	// Save configuration
	if err := cfg.Save(); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	// TODO: Install service (systemd/launchd/windows service)

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
