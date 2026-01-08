// Package osquery provides osquery integration for system queries.
package osquery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	DefaultTimeout = 30 * time.Second

	// GitHub API constants
	githubReleasesURL  = "https://api.github.com/repos/osquery/osquery/releases/latest"
	rateLimitRetryWait = 5 * time.Minute

	// Fallback version if GitHub API fails
	fallbackVersion = "5.15.0"
)

// GitHubRelease represents the GitHub API response for a release.
type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

var (
	// Cached latest version to avoid repeated API calls
	cachedVersion     string
	cachedVersionTime time.Time
	versionCacheMu    sync.RWMutex
	versionCacheTTL   = 1 * time.Hour
)

// QueryResult contains the result of an osquery query.
type QueryResult struct {
	Query    string          `json:"query"`
	Rows     []map[string]string `json:"rows"`
	Count    int             `json:"count"`
	Duration int64           `json:"duration_ms"`
	Error    string          `json:"error,omitempty"`
}

// Client provides osquery functionality.
type Client struct {
	binaryPath string
}

// New creates a new osquery client.
func New() *Client {
	return &Client{
		binaryPath: findOsqueryBinary(),
	}
}

// NewWithPath creates a new osquery client with a specific binary path.
func NewWithPath(path string) *Client {
	return &Client{
		binaryPath: path,
	}
}

// IsAvailable checks if osquery is available.
func (c *Client) IsAvailable() bool {
	if c.binaryPath == "" {
		return false
	}
	_, err := os.Stat(c.binaryPath)
	return err == nil
}

// GetBinaryPath returns the path to the osquery binary.
func (c *Client) GetBinaryPath() string {
	return c.binaryPath
}

// GetVersion returns the installed osquery version.
func (c *Client) GetVersion() string {
	if !c.IsAvailable() {
		return ""
	}

	cmd := exec.Command(c.binaryPath, "--version")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// Output format: "osqueryi version 5.15.0" or "osquery version 5.15.0"
	line := strings.TrimSpace(string(output))
	parts := strings.Fields(line)
	if len(parts) >= 3 && parts[1] == "version" {
		return parts[2]
	}

	// Try alternate parsing for different formats
	if strings.Contains(line, "version") {
		for _, part := range parts {
			// Look for version-like string (x.y.z)
			if strings.Count(part, ".") >= 1 && part[0] >= '0' && part[0] <= '9' {
				return part
			}
		}
	}

	return ""
}

// Query executes an osquery query and returns the results.
func (c *Client) Query(ctx context.Context, query string) (*QueryResult, error) {
	if !c.IsAvailable() {
		return nil, fmt.Errorf("osquery not available")
	}

	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	start := time.Now()

	cmd := exec.CommandContext(ctx, c.binaryPath, "--json", query)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	result := &QueryResult{
		Query:    query,
		Duration: time.Since(start).Milliseconds(),
		Rows:     make([]map[string]string, 0),
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.Error = "query timed out"
		} else {
			result.Error = fmt.Sprintf("%s: %s", err.Error(), stderr.String())
		}
		return result, nil
	}

	// Parse JSON output
	if stdout.Len() > 0 {
		if err := json.Unmarshal(stdout.Bytes(), &result.Rows); err != nil {
			result.Error = fmt.Sprintf("failed to parse output: %v", err)
			return result, nil
		}
	}

	result.Count = len(result.Rows)
	return result, nil
}

// QueryWithTimeout executes a query with a custom timeout.
func (c *Client) QueryWithTimeout(ctx context.Context, query string, timeout time.Duration) (*QueryResult, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return c.Query(ctx, query)
}

// findOsqueryBinary searches for the osquery binary in official installation paths.
// We explicitly check known paths first to avoid finding osquery bundled with other software.
func findOsqueryBinary() string {
	// Common osquery binary names
	names := []string{"osqueryi", "osqueryd"}

	// Official osquery installation paths only
	var paths []string

	switch runtime.GOOS {
	case "darwin":
		paths = []string{
			"/opt/osquery/bin",        // Official PKG installation
			"/usr/local/bin",          // Homebrew installation
			"/opt/homebrew/bin",       // Homebrew on Apple Silicon
		}
	case "linux":
		paths = []string{
			"/usr/bin",               // Package manager installation
			"/usr/local/bin",         // Manual installation
			"/opt/osquery/bin",       // Alternative installation
		}
	case "windows":
		// Only check official osquery installation paths
		// Do NOT use exec.LookPath as other software (Level, etc.) may bundle osquery
		paths = []string{
			`C:\Program Files\osquery`,  // Official MSI installation
			`C:\ProgramData\osquery`,    // Alternative location
		}
		names = []string{"osqueryi.exe", "osqueryd.exe"}
	}

	// On Windows, only check known paths - don't use LookPath to avoid
	// finding osquery bundled with other software (Level, etc.)
	if runtime.GOOS == "windows" {
		for _, name := range names {
			for _, dir := range paths {
				path := filepath.Join(dir, name)
				if _, err := os.Stat(path); err == nil {
					return path
				}
			}
		}
		return ""
	}

	// On Unix, check known paths first, then fall back to PATH
	for _, name := range names {
		// Check known paths first
		for _, dir := range paths {
			path := filepath.Join(dir, name)
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}

		// Fall back to PATH for Unix systems
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}

	return ""
}

// Common queries

// GetSystemInfo returns basic system information.
func (c *Client) GetSystemInfo(ctx context.Context) (*QueryResult, error) {
	return c.Query(ctx, "SELECT * FROM system_info")
}

// GetOSVersion returns OS version information.
func (c *Client) GetOSVersion(ctx context.Context) (*QueryResult, error) {
	return c.Query(ctx, "SELECT * FROM os_version")
}

// GetUsers returns user accounts.
func (c *Client) GetUsers(ctx context.Context) (*QueryResult, error) {
	return c.Query(ctx, "SELECT uid, gid, username, description, directory, shell FROM users")
}

// GetProcesses returns running processes.
func (c *Client) GetProcesses(ctx context.Context) (*QueryResult, error) {
	return c.Query(ctx, "SELECT pid, name, path, cmdline, state, uid FROM processes")
}

// GetListeningPorts returns listening network ports.
func (c *Client) GetListeningPorts(ctx context.Context) (*QueryResult, error) {
	return c.Query(ctx, "SELECT pid, port, protocol, address FROM listening_ports")
}

// GetInstalledPrograms returns installed programs.
func (c *Client) GetInstalledPrograms(ctx context.Context) (*QueryResult, error) {
	switch runtime.GOOS {
	case "darwin":
		return c.Query(ctx, "SELECT name, bundle_identifier, bundle_version FROM apps")
	case "linux":
		return c.Query(ctx, "SELECT name, version, source FROM deb_packages UNION SELECT name, version, source FROM rpm_packages")
	case "windows":
		return c.Query(ctx, "SELECT name, version, publisher FROM programs")
	default:
		return nil, fmt.Errorf("unsupported OS")
	}
}

// GetStartupItems returns startup items.
func (c *Client) GetStartupItems(ctx context.Context) (*QueryResult, error) {
	switch runtime.GOOS {
	case "darwin":
		return c.Query(ctx, "SELECT name, path, type FROM launchd")
	case "linux":
		return c.Query(ctx, "SELECT name, path, status FROM systemd_units WHERE type='service'")
	case "windows":
		return c.Query(ctx, "SELECT name, path, status FROM startup_items")
	default:
		return nil, fmt.Errorf("unsupported OS")
	}
}

// ErrArchLinux is returned when running on Arch Linux which requires manual installation.
var ErrArchLinux = fmt.Errorf("arch Linux detected: please install osquery manually using 'yay -S osquery' or from AUR")

// GetLatestVersion fetches the latest osquery version from GitHub releases.
// It handles rate limiting by waiting 5 minutes and retrying.
// Returns cached version if available and not expired.
func GetLatestVersion(ctx context.Context) (string, error) {
	// Check cache first
	versionCacheMu.RLock()
	if cachedVersion != "" && time.Since(cachedVersionTime) < versionCacheTTL {
		v := cachedVersion
		versionCacheMu.RUnlock()
		return v, nil
	}
	versionCacheMu.RUnlock()

	return fetchLatestVersionWithRetry(ctx)
}

// fetchLatestVersionWithRetry fetches version from GitHub with rate limit handling.
func fetchLatestVersionWithRetry(ctx context.Context) (string, error) {
	maxRetries := 3

	for attempt := 0; attempt < maxRetries; attempt++ {
		version, rateLimited, err := fetchLatestVersion(ctx)
		if err == nil {
			// Cache the version
			versionCacheMu.Lock()
			cachedVersion = version
			cachedVersionTime = time.Now()
			versionCacheMu.Unlock()
			return version, nil
		}

		if rateLimited {
			slog.Warn("GitHub API rate limited, waiting before retry",
				"wait", rateLimitRetryWait, "attempt", attempt+1)

			select {
			case <-ctx.Done():
				return fallbackVersion, ctx.Err()
			case <-time.After(rateLimitRetryWait):
				continue
			}
		}

		// Non-rate-limit error, don't retry
		slog.Warn("failed to fetch osquery version from GitHub, using fallback",
			"error", err, "fallback", fallbackVersion)
		return fallbackVersion, nil
	}

	return fallbackVersion, nil
}

// fetchLatestVersion makes a single request to GitHub API.
// Returns (version, rateLimited, error).
func fetchLatestVersion(ctx context.Context) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", githubReleasesURL, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "SlimRMM-Agent")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	// Check for rate limiting
	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		return "", true, fmt.Errorf("rate limited")
	}

	if resp.StatusCode != 200 {
		return "", false, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, err
	}

	var release GitHubRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return "", false, err
	}

	// Tag name is like "5.15.0" or "v5.15.0"
	version := strings.TrimPrefix(release.TagName, "v")
	if version == "" {
		return "", false, fmt.Errorf("empty version in release")
	}

	return version, false, nil
}

// isArchLinux detects if we're running on Arch Linux.
func isArchLinux() bool {
	if runtime.GOOS != "linux" {
		return false
	}

	// Check /etc/os-release
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return false
	}

	content := strings.ToLower(string(data))
	return strings.Contains(content, "arch") || strings.Contains(content, "manjaro") ||
		strings.Contains(content, "endeavouros") || strings.Contains(content, "garuda")
}

// EnsureInstalled checks if osquery is installed and installs it if not.
// This is designed to be called at agent startup.
func EnsureInstalled(ctx context.Context, logger *slog.Logger) error {
	client := New()
	if client.IsAvailable() {
		logger.Info("osquery is already installed", "path", client.GetBinaryPath())
		return nil
	}

	logger.Info("osquery not found, attempting auto-installation")

	// Check for Arch Linux
	if isArchLinux() {
		logger.Warn("Arch Linux detected - osquery must be installed manually",
			"instruction", "Install from AUR: yay -S osquery")
		return ErrArchLinux
	}

	if err := Install(ctx); err != nil {
		logger.Error("failed to install osquery", "error", err)
		return err
	}

	// Verify installation
	client = New()
	if !client.IsAvailable() {
		return fmt.Errorf("osquery installation completed but binary not found")
	}

	logger.Info("osquery installed successfully", "path", client.GetBinaryPath())
	return nil
}

// Install installs osquery on the system.
func Install(ctx context.Context) error {
	// Get latest version
	version, err := GetLatestVersion(ctx)
	if err != nil {
		slog.Warn("failed to get latest version, using fallback", "error", err, "fallback", fallbackVersion)
		version = fallbackVersion
	}

	slog.Info("installing osquery", "version", version)

	switch runtime.GOOS {
	case "linux":
		return installLinux(ctx, version)
	case "darwin":
		return installMacOS(ctx, version)
	case "windows":
		return installWindows(ctx, version)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// installLinux installs osquery on Linux.
func installLinux(ctx context.Context, version string) error {
	// Check for Arch Linux first
	if isArchLinux() {
		return ErrArchLinux
	}

	// Determine package manager
	var installCmd *exec.Cmd

	if _, err := exec.LookPath("apt-get"); err == nil {
		// Debian/Ubuntu - use apt repository for latest version
		slog.Info("detected Debian/Ubuntu, using apt repository")

		// Add osquery repository
		keyCmd := exec.CommandContext(ctx, "bash", "-c",
			"curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg | gpg --dearmor -o /usr/share/keyrings/osquery-keyring.gpg 2>/dev/null || true")
		if err := keyCmd.Run(); err != nil {
			slog.Warn("adding osquery GPG key failed, trying alternate method", "error", err)
			// Try alternate method
			keyCmd2 := exec.CommandContext(ctx, "bash", "-c",
				"curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg | apt-key add -")
			if err := keyCmd2.Run(); err != nil {
				return fmt.Errorf("adding osquery key: %w", err)
			}
		}

		// Detect architecture
		arch := runtime.GOARCH
		if arch == "amd64" {
			arch = "amd64"
		} else if arch == "arm64" {
			arch = "arm64"
		}

		repoCmd := exec.CommandContext(ctx, "bash", "-c",
			fmt.Sprintf("echo 'deb [arch=%s signed-by=/usr/share/keyrings/osquery-keyring.gpg] https://pkg.osquery.io/deb deb main' > /etc/apt/sources.list.d/osquery.list", arch))
		if err := repoCmd.Run(); err != nil {
			return fmt.Errorf("adding osquery repo: %w", err)
		}

		updateCmd := exec.CommandContext(ctx, "apt-get", "update")
		updateCmd.Stderr = nil // Suppress warnings
		if err := updateCmd.Run(); err != nil {
			slog.Warn("apt-get update had issues, continuing", "error", err)
		}

		installCmd = exec.CommandContext(ctx, "apt-get", "install", "-y", "osquery")

	} else if _, err := exec.LookPath("dnf"); err == nil {
		// Fedora/RHEL 8+ - use direct RPM download with dynamic version
		slog.Info("detected Fedora/RHEL 8+, using dnf")
		rpmURL := fmt.Sprintf("https://pkg.osquery.io/rpm/osquery-%s-1.linux.x86_64.rpm", version)
		installCmd = exec.CommandContext(ctx, "dnf", "install", "-y", rpmURL)

	} else if _, err := exec.LookPath("yum"); err == nil {
		// RHEL/CentOS 7 - use direct RPM download with dynamic version
		slog.Info("detected RHEL/CentOS 7, using yum")
		rpmURL := fmt.Sprintf("https://pkg.osquery.io/rpm/osquery-%s-1.linux.x86_64.rpm", version)
		installCmd = exec.CommandContext(ctx, "yum", "install", "-y", rpmURL)

	} else if _, err := exec.LookPath("pacman"); err == nil {
		// Arch-based (shouldn't reach here due to earlier check, but just in case)
		return ErrArchLinux

	} else {
		return fmt.Errorf("no supported package manager found (apt-get, dnf, yum)")
	}

	var stderr bytes.Buffer
	installCmd.Stderr = &stderr

	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("installing osquery: %w (%s)", err, stderr.String())
	}

	return nil
}

// installMacOS installs osquery on macOS.
func installMacOS(ctx context.Context, version string) error {
	slog.Info("installing osquery on macOS", "version", version)

	// Check if brew is available - use it as it handles updates well
	if _, err := exec.LookPath("brew"); err == nil {
		slog.Info("using Homebrew to install osquery")
		installCmd := exec.CommandContext(ctx, "brew", "install", "osquery")
		var stderr bytes.Buffer
		installCmd.Stderr = &stderr

		if err := installCmd.Run(); err != nil {
			slog.Warn("brew install failed, falling back to PKG", "error", err)
			// Fall through to PKG installation
		} else {
			return nil
		}
	}

	// Download and install PKG directly with dynamic version
	pkgURL := fmt.Sprintf("https://pkg.osquery.io/darwin/osquery-%s.pkg", version)
	tmpPkg := "/tmp/osquery.pkg"

	slog.Info("downloading osquery PKG", "url", pkgURL)

	downloadCmd := exec.CommandContext(ctx, "curl", "-fsSL", "-o", tmpPkg, pkgURL)
	var dlStderr bytes.Buffer
	downloadCmd.Stderr = &dlStderr
	if err := downloadCmd.Run(); err != nil {
		return fmt.Errorf("downloading osquery pkg: %w (%s)", err, dlStderr.String())
	}

	slog.Info("installing osquery PKG")

	installCmd := exec.CommandContext(ctx, "installer", "-pkg", tmpPkg, "-target", "/")
	var stderr bytes.Buffer
	installCmd.Stderr = &stderr

	if err := installCmd.Run(); err != nil {
		os.Remove(tmpPkg) // Cleanup on failure
		return fmt.Errorf("installing osquery pkg: %w (%s)", err, stderr.String())
	}

	// Cleanup
	os.Remove(tmpPkg)

	return nil
}

// installWindows installs osquery on Windows.
func installWindows(ctx context.Context, version string) error {
	slog.Info("installing osquery on Windows", "version", version)

	// Download MSI from osquery's official package server
	msiURL := fmt.Sprintf("https://pkg.osquery.io/windows/osquery-%s.msi", version)
	tmpMSI := filepath.Join(os.TempDir(), "osquery.msi")

	slog.Info("downloading osquery MSI", "url", msiURL)

	// Use PowerShell with ExecutionPolicy Bypass and full path for reliability
	// This works better when running as LocalSystem service account
	psScript := fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		$ProgressPreference = 'SilentlyContinue'
		Invoke-WebRequest -Uri '%s' -OutFile '%s' -UseBasicParsing
	`, msiURL, tmpMSI)

	downloadCmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", psScript)
	var dlStdout, dlStderr bytes.Buffer
	downloadCmd.Stdout = &dlStdout
	downloadCmd.Stderr = &dlStderr

	if err := downloadCmd.Run(); err != nil {
		slog.Error("failed to download osquery MSI",
			"error", err,
			"stdout", dlStdout.String(),
			"stderr", dlStderr.String())
		return fmt.Errorf("downloading osquery msi: %w", err)
	}

	// Verify download succeeded
	if fi, err := os.Stat(tmpMSI); err != nil || fi.Size() < 1000 {
		slog.Error("osquery MSI download appears incomplete",
			"path", tmpMSI,
			"error", err)
		os.Remove(tmpMSI)
		return fmt.Errorf("osquery MSI download incomplete or failed")
	}

	slog.Info("installing osquery MSI silently", "path", tmpMSI)

	// Install with msiexec - use /log for debugging if needed
	installCmd := exec.CommandContext(ctx, "msiexec.exe",
		"/i", tmpMSI, "/quiet", "/qn", "/norestart",
		"/log", filepath.Join(os.TempDir(), "osquery-install.log"))
	var stderr bytes.Buffer
	installCmd.Stderr = &stderr

	if err := installCmd.Run(); err != nil {
		slog.Error("failed to install osquery MSI",
			"error", err,
			"stderr", stderr.String())
		// Don't remove MSI yet - might be useful for debugging
		return fmt.Errorf("installing osquery msi: %w", err)
	}

	// Cleanup
	os.Remove(tmpMSI)

	slog.Info("osquery MSI installation completed")
	return nil
}
