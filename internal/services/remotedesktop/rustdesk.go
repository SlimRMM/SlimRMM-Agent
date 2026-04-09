//go:build linux || darwin

package remotedesktop

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	agenthttp "github.com/slimrmm/slimrmm-agent/internal/http"
)

const (
	// rustdeskConfigFileName is the name of the RustDesk configuration file.
	rustdeskConfigFileName = "RustDesk2.toml"
)

// Install downloads, installs, and configures RustDesk.
func (s *Service) Install(ctx context.Context, cfg Config) error {
	if cfg.IDServer == "" {
		return fmt.Errorf("id_server is required")
	}

	s.logger.Info("starting rustdesk installation", "os", runtime.GOOS)

	// Download the installer.
	installerPath, err := s.downloadInstaller(ctx)
	if err != nil {
		return fmt.Errorf("downloading rustdesk installer: %w", err)
	}
	defer os.Remove(installerPath)

	// Install the package.
	if err := s.installPackage(ctx, installerPath); err != nil {
		return fmt.Errorf("installing rustdesk: %w", err)
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
	if err := s.startService(ctx); err != nil {
		return fmt.Errorf("starting rustdesk service: %w", err)
	}

	s.logger.Info("rustdesk installation completed successfully")
	return nil
}

// downloadInstaller downloads the appropriate RustDesk installer for the
// current platform and returns the path to the downloaded file.
func (s *Service) downloadInstaller(ctx context.Context) (string, error) {
	var (
		ext      string
		archPart string
	)

	arch := runtime.GOARCH
	if arch == "amd64" {
		archPart = "x86_64"
	} else if arch == "arm64" {
		archPart = "aarch64"
	} else {
		return "", fmt.Errorf("unsupported architecture: %s", arch)
	}

	switch runtime.GOOS {
	case "linux":
		if isDebianBased() {
			ext = fmt.Sprintf("%s.deb", archPart)
		} else {
			ext = fmt.Sprintf("%s.rpm", archPart)
		}
	case "darwin":
		ext = fmt.Sprintf("%s.dmg", archPart)
	default:
		return "", fmt.Errorf("unsupported os: %s", runtime.GOOS)
	}

	// Build download URL from latest release.
	// The actual URL will follow redirects from the GitHub releases page.
	downloadURL := fmt.Sprintf("https://github.com/rustdesk/rustdesk/releases/latest/download/rustdesk-%s", ext)

	tmpDir := os.TempDir()
	destPath := filepath.Join(tmpDir, "rustdesk-installer-"+ext)

	s.logger.Info("downloading rustdesk", "url", downloadURL, "dest", destPath)

	client := agenthttp.NewClient(s.logger)
	if err := client.DownloadToFile(ctx, downloadURL, destPath,
		agenthttp.WithDownloadTimeout(10*time.Minute),
	); err != nil {
		return "", fmt.Errorf("downloading %s: %w", downloadURL, err)
	}

	return destPath, nil
}

// installPackage installs the RustDesk package from the given path.
func (s *Service) installPackage(ctx context.Context, path string) error {
	switch runtime.GOOS {
	case "linux":
		return s.installLinux(ctx, path)
	case "darwin":
		return s.installMacOS(ctx, path)
	default:
		return fmt.Errorf("unsupported os: %s", runtime.GOOS)
	}
}

// installLinux installs RustDesk from a .deb or .rpm file.
func (s *Service) installLinux(ctx context.Context, path string) error {
	var cmd *exec.Cmd

	if strings.HasSuffix(path, ".deb") {
		s.logger.Info("installing rustdesk via dpkg", "path", path)
		cmd = exec.CommandContext(ctx, "dpkg", "-i", path)
	} else if strings.HasSuffix(path, ".rpm") {
		s.logger.Info("installing rustdesk via rpm", "path", path)
		cmd = exec.CommandContext(ctx, "rpm", "-i", path)
	} else {
		return fmt.Errorf("unsupported package format: %s", path)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("package installation failed: %w, output: %s", err, string(output))
	}

	return nil
}

// installMacOS installs RustDesk from a .dmg file by mounting it and
// copying the app bundle to /Applications.
func (s *Service) installMacOS(ctx context.Context, path string) error {
	mountPoint := filepath.Join(os.TempDir(), "rustdesk-mount")

	s.logger.Info("mounting dmg", "path", path, "mount_point", mountPoint)

	// Create mount point.
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		return fmt.Errorf("creating mount point: %w", err)
	}
	defer os.RemoveAll(mountPoint)

	// Mount the DMG.
	mountCmd := exec.CommandContext(ctx, "hdiutil", "attach", path,
		"-mountpoint", mountPoint, "-nobrowse", "-quiet")
	if output, err := mountCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("mounting dmg: %w, output: %s", err, string(output))
	}
	defer func() {
		detach := exec.CommandContext(ctx, "hdiutil", "detach", mountPoint, "-quiet")
		if err := detach.Run(); err != nil {
			s.logger.Warn("failed to detach dmg", "error", err)
		}
	}()

	// Copy the app bundle to /Applications.
	appSrc := filepath.Join(mountPoint, "RustDesk.app")
	appDst := "/Applications/RustDesk.app"

	// Remove existing installation if present.
	if _, err := os.Stat(appDst); err == nil {
		if err := os.RemoveAll(appDst); err != nil {
			return fmt.Errorf("removing existing installation: %w", err)
		}
	}

	cpCmd := exec.CommandContext(ctx, "cp", "-R", appSrc, appDst)
	if output, err := cpCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("copying app bundle: %w, output: %s", err, string(output))
	}

	s.logger.Info("rustdesk installed to /Applications")
	return nil
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
	cmd := exec.Command("rustdesk", "--get-id")
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
	cmd := exec.Command("rustdesk", "--version")
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

// IsRunning checks whether the RustDesk service or process is currently active.
func (s *Service) IsRunning() bool {
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("systemctl", "is-active", "rustdesk")
		output, err := cmd.Output()
		if err != nil {
			return false
		}
		return strings.TrimSpace(string(output)) == "active"
	case "darwin":
		cmd := exec.Command("pgrep", "-x", "rustdesk")
		return cmd.Run() == nil
	default:
		return false
	}
}

// SetPassword sets the permanent access password for RustDesk.
func (s *Service) SetPassword(password string) error {
	if password == "" {
		return fmt.Errorf("password must not be empty")
	}

	cmd := exec.Command("rustdesk", "--password", password)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("setting rustdesk password: %w, output: %s", err, string(output))
	}

	s.logger.Info("rustdesk password configured")
	return nil
}

// Uninstall removes the RustDesk installation.
func (s *Service) Uninstall(ctx context.Context) error {
	s.logger.Info("uninstalling rustdesk", "os", runtime.GOOS)

	switch runtime.GOOS {
	case "linux":
		return s.uninstallLinux(ctx)
	case "darwin":
		return s.uninstallMacOS(ctx)
	default:
		return fmt.Errorf("unsupported os: %s", runtime.GOOS)
	}
}

// uninstallLinux removes RustDesk via the system package manager.
func (s *Service) uninstallLinux(ctx context.Context) error {
	// Try dpkg first, fall back to rpm.
	dpkg := exec.CommandContext(ctx, "dpkg", "-r", "rustdesk")
	if output, err := dpkg.CombinedOutput(); err != nil {
		s.logger.Debug("dpkg removal failed, trying rpm", "error", err)

		rpm := exec.CommandContext(ctx, "rpm", "-e", "rustdesk")
		if rpmOutput, rpmErr := rpm.CombinedOutput(); rpmErr != nil {
			return fmt.Errorf("uninstall failed (dpkg: %s, rpm: %s)", string(output), string(rpmOutput))
		}
	}

	s.logger.Info("rustdesk uninstalled from linux")
	return nil
}

// uninstallMacOS removes the RustDesk app bundle from /Applications.
func (s *Service) uninstallMacOS(ctx context.Context) error {
	appPath := "/Applications/RustDesk.app"

	if _, err := os.Stat(appPath); os.IsNotExist(err) {
		return fmt.Errorf("rustdesk is not installed at %s", appPath)
	}

	if err := os.RemoveAll(appPath); err != nil {
		return fmt.Errorf("removing rustdesk app: %w", err)
	}

	s.logger.Info("rustdesk uninstalled from macos")
	return nil
}

// startService starts the RustDesk background service.
func (s *Service) startService(ctx context.Context) error {
	switch runtime.GOOS {
	case "linux":
		cmd := exec.CommandContext(ctx, "systemctl", "enable", "--now", "rustdesk")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("enabling rustdesk service: %w, output: %s", err, string(output))
		}
	case "darwin":
		cmd := exec.CommandContext(ctx, "open", "-a", "RustDesk", "--args", "--service")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("starting rustdesk: %w, output: %s", err, string(output))
		}
	default:
		return fmt.Errorf("unsupported os: %s", runtime.GOOS)
	}

	s.logger.Info("rustdesk service started")
	return nil
}

// rustdeskConfigDir returns the platform-specific RustDesk configuration
// directory.
func rustdeskConfigDir() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return "/root/.config/rustdesk", nil
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("determining home directory: %w", err)
		}
		return filepath.Join(home, "Library", "Preferences", "RustDesk"), nil
	default:
		return "", fmt.Errorf("unsupported os: %s", runtime.GOOS)
	}
}

// isDebianBased checks whether the current Linux system uses dpkg (Debian,
// Ubuntu, etc.) by looking for the dpkg binary.
func isDebianBased() bool {
	_, err := exec.LookPath("dpkg")
	return err == nil
}
