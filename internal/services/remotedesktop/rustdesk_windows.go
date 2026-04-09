//go:build windows

package remotedesktop

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	agenthttp "github.com/slimrmm/slimrmm-agent/internal/http"
)

const (
	// rustdeskConfigFileName is the name of the RustDesk configuration file.
	rustdeskConfigFileName = "RustDesk2.toml"
)

// Install downloads, installs, and configures RustDesk on Windows.
func (s *Service) Install(ctx context.Context, cfg Config) error {
	if cfg.IDServer == "" {
		return fmt.Errorf("id_server is required")
	}

	s.logger.Info("starting rustdesk installation", "os", "windows")

	// Download the MSI installer.
	installerPath, err := s.downloadInstaller(ctx)
	if err != nil {
		return fmt.Errorf("downloading rustdesk installer: %w", err)
	}
	defer os.Remove(installerPath)

	// Install via msiexec.
	s.logger.Info("installing rustdesk via msiexec", "path", installerPath)
	msiCmd := exec.CommandContext(ctx, "msiexec", "/i", installerPath, "/qn", "/norestart")
	if output, err := msiCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("msiexec installation failed: %w, output: %s", err, string(output))
	}

	// Configure with relay server info.
	if err := s.Configure(cfg); err != nil {
		return fmt.Errorf("configuring rustdesk: %w", err)
	}

	// Set password if provided.
	if cfg.Password != "" {
		if err := s.SetPassword(cfg.Password); err != nil {
			return fmt.Errorf("setting rustdesk password: %w", err)
		}
	}

	// Start the service.
	startCmd := exec.CommandContext(ctx, "sc", "start", "rustdesk")
	if output, err := startCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("starting rustdesk service: %w, output: %s", err, string(output))
	}

	s.logger.Info("rustdesk installation completed successfully")
	return nil
}

// downloadInstaller downloads the RustDesk MSI installer for Windows and
// returns the path to the downloaded file.
func (s *Service) downloadInstaller(ctx context.Context) (string, error) {
	downloadURL := "https://github.com/rustdesk/rustdesk/releases/latest/download/rustdesk-x86_64.msi"

	tmpDir := os.TempDir()
	destPath := filepath.Join(tmpDir, "rustdesk-installer.msi")

	s.logger.Info("downloading rustdesk", "url", downloadURL, "dest", destPath)

	client := agenthttp.NewClient(s.logger)
	if err := client.DownloadToFile(ctx, downloadURL, destPath,
		agenthttp.WithDownloadTimeout(10*time.Minute),
	); err != nil {
		return "", fmt.Errorf("downloading %s: %w", downloadURL, err)
	}

	return destPath, nil
}

// Configure writes the RustDesk configuration file with the provided
// server settings.
func (s *Service) Configure(cfg Config) error {
	configDir, err := rustdeskConfigDir()
	if err != nil {
		return fmt.Errorf("determining config directory: %w", err)
	}

	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	configPath := filepath.Join(configDir, rustdeskConfigFileName)

	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("rendezvous_server = '%s'\n", cfg.IDServer))
	if cfg.RelayServer != "" {
		builder.WriteString(fmt.Sprintf("relay-server = '%s'\n", cfg.RelayServer))
	}
	if cfg.PublicKey != "" {
		builder.WriteString(fmt.Sprintf("key = '%s'\n", cfg.PublicKey))
	}

	if err := os.WriteFile(configPath, []byte(builder.String()), 0600); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}

	s.logger.Info("rustdesk configured", "config_path", configPath)
	return nil
}

// GetID retrieves the RustDesk client ID.
func (s *Service) GetID() (string, error) {
	rustdeskPath := rustdeskExePath()

	cmd := exec.Command(rustdeskPath, "--get-id")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("getting rustdesk id: %w", err)
	}

	id := strings.TrimSpace(string(output))
	if id == "" {
		return "", fmt.Errorf("rustdesk returned empty id")
	}

	return id, nil
}

// GetVersion returns the installed RustDesk version string.
func (s *Service) GetVersion() (string, error) {
	rustdeskPath := rustdeskExePath()

	cmd := exec.Command(rustdeskPath, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("getting rustdesk version: %w", err)
	}

	version := strings.TrimSpace(string(output))
	if version == "" {
		return "", fmt.Errorf("rustdesk returned empty version")
	}

	return version, nil
}

// IsRunning checks whether the RustDesk Windows service is running.
func (s *Service) IsRunning() bool {
	cmd := exec.Command("sc", "query", "rustdesk")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "RUNNING")
}

// SetPassword sets the permanent access password for RustDesk.
func (s *Service) SetPassword(password string) error {
	if password == "" {
		return fmt.Errorf("password must not be empty")
	}

	rustdeskPath := rustdeskExePath()

	cmd := exec.Command(rustdeskPath, "--password", password)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("setting rustdesk password: %w, output: %s", err, string(output))
	}

	s.logger.Info("rustdesk password configured")
	return nil
}

// Uninstall removes the RustDesk installation on Windows.
func (s *Service) Uninstall(ctx context.Context) error {
	s.logger.Info("uninstalling rustdesk", "os", "windows")

	// Stop the service first.
	stopCmd := exec.CommandContext(ctx, "sc", "stop", "rustdesk")
	if output, err := stopCmd.CombinedOutput(); err != nil {
		s.logger.Warn("failed to stop rustdesk service", "error", err, "output", string(output))
	}

	// Uninstall via msiexec.
	uninstallCmd := exec.CommandContext(ctx, "msiexec", "/x", "rustdesk", "/qn", "/norestart")
	if output, err := uninstallCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("msiexec uninstall failed: %w, output: %s", err, string(output))
	}

	s.logger.Info("rustdesk uninstalled from windows")
	return nil
}

// rustdeskConfigDir returns the Windows RustDesk configuration directory.
func rustdeskConfigDir() (string, error) {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		return "", fmt.Errorf("APPDATA environment variable not set")
	}
	return filepath.Join(appData, "RustDesk", "config"), nil
}

// rustdeskExePath returns the expected RustDesk executable path on Windows.
func rustdeskExePath() string {
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	return filepath.Join(programFiles, "RustDesk", "rustdesk.exe")
}
