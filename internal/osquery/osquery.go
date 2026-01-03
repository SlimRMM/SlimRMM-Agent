// Package osquery provides osquery integration for system queries.
package osquery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

const (
	DefaultTimeout = 30 * time.Second
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

// findOsqueryBinary searches for the osquery binary.
func findOsqueryBinary() string {
	// Common osquery binary names
	names := []string{"osqueryi", "osqueryd"}

	// Common installation paths
	var paths []string

	switch runtime.GOOS {
	case "darwin":
		paths = []string{
			"/usr/local/bin",
			"/opt/osquery/bin",
			"/var/lib/slimrmm",
		}
	case "linux":
		paths = []string{
			"/usr/bin",
			"/usr/local/bin",
			"/opt/osquery/bin",
			"/var/lib/slimrmm",
		}
	case "windows":
		paths = []string{
			`C:\Program Files\osquery`,
			`C:\ProgramData\osquery`,
			`C:\Program Files\SlimRMM`,
		}
		names = []string{"osqueryi.exe", "osqueryd.exe"}
	}

	// Search for binary
	for _, name := range names {
		// Check PATH first
		if path, err := exec.LookPath(name); err == nil {
			return path
		}

		// Check common paths
		for _, dir := range paths {
			path := filepath.Join(dir, name)
			if _, err := os.Stat(path); err == nil {
				return path
			}
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

// Install installs osquery on the system.
func Install(ctx context.Context) error {
	switch runtime.GOOS {
	case "linux":
		return installLinux(ctx)
	case "darwin":
		return installMacOS(ctx)
	case "windows":
		return installWindows(ctx)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// installLinux installs osquery on Linux.
func installLinux(ctx context.Context) error {
	// Determine package manager
	var installCmd *exec.Cmd

	if _, err := exec.LookPath("apt-get"); err == nil {
		// Debian/Ubuntu
		// Add osquery repository
		keyCmd := exec.CommandContext(ctx, "bash", "-c",
			"curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg | sudo gpg --dearmor -o /usr/share/keyrings/osquery-keyring.gpg")
		if err := keyCmd.Run(); err != nil {
			return fmt.Errorf("adding osquery key: %w", err)
		}

		repoCmd := exec.CommandContext(ctx, "bash", "-c",
			"echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/osquery-keyring.gpg] https://pkg.osquery.io/deb deb main' | sudo tee /etc/apt/sources.list.d/osquery.list")
		if err := repoCmd.Run(); err != nil {
			return fmt.Errorf("adding osquery repo: %w", err)
		}

		updateCmd := exec.CommandContext(ctx, "apt-get", "update")
		if err := updateCmd.Run(); err != nil {
			return fmt.Errorf("updating apt: %w", err)
		}

		installCmd = exec.CommandContext(ctx, "apt-get", "install", "-y", "osquery")
	} else if _, err := exec.LookPath("dnf"); err == nil {
		// Fedora/RHEL 8+
		installCmd = exec.CommandContext(ctx, "dnf", "install", "-y",
			"https://pkg.osquery.io/rpm/osquery-5.10.2-1.linux.x86_64.rpm")
	} else if _, err := exec.LookPath("yum"); err == nil {
		// RHEL/CentOS 7
		installCmd = exec.CommandContext(ctx, "yum", "install", "-y",
			"https://pkg.osquery.io/rpm/osquery-5.10.2-1.linux.x86_64.rpm")
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
func installMacOS(ctx context.Context) error {
	// Check if brew is available
	if _, err := exec.LookPath("brew"); err == nil {
		installCmd := exec.CommandContext(ctx, "brew", "install", "osquery")
		var stderr bytes.Buffer
		installCmd.Stderr = &stderr

		if err := installCmd.Run(); err != nil {
			return fmt.Errorf("brew install osquery: %w (%s)", err, stderr.String())
		}
		return nil
	}

	// Download and install pkg directly
	pkgURL := "https://pkg.osquery.io/darwin/osquery-5.10.2.pkg"
	tmpPkg := "/tmp/osquery.pkg"

	downloadCmd := exec.CommandContext(ctx, "curl", "-fsSL", "-o", tmpPkg, pkgURL)
	if err := downloadCmd.Run(); err != nil {
		return fmt.Errorf("downloading osquery pkg: %w", err)
	}

	installCmd := exec.CommandContext(ctx, "installer", "-pkg", tmpPkg, "-target", "/")
	var stderr bytes.Buffer
	installCmd.Stderr = &stderr

	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("installing osquery pkg: %w (%s)", err, stderr.String())
	}

	// Cleanup
	os.Remove(tmpPkg)

	return nil
}

// installWindows installs osquery on Windows.
func installWindows(ctx context.Context) error {
	// Check if winget is available
	if _, err := exec.LookPath("winget"); err == nil {
		installCmd := exec.CommandContext(ctx, "winget", "install", "--id", "osquery.osquery", "-e", "--silent")
		var stderr bytes.Buffer
		installCmd.Stderr = &stderr

		if err := installCmd.Run(); err != nil {
			return fmt.Errorf("winget install osquery: %w (%s)", err, stderr.String())
		}
		return nil
	}

	// Check if choco is available
	if _, err := exec.LookPath("choco"); err == nil {
		installCmd := exec.CommandContext(ctx, "choco", "install", "osquery", "-y")
		var stderr bytes.Buffer
		installCmd.Stderr = &stderr

		if err := installCmd.Run(); err != nil {
			return fmt.Errorf("choco install osquery: %w (%s)", err, stderr.String())
		}
		return nil
	}

	// Download and install MSI directly
	msiURL := "https://pkg.osquery.io/windows/osquery-5.10.2.msi"
	tmpMSI := filepath.Join(os.TempDir(), "osquery.msi")

	downloadCmd := exec.CommandContext(ctx, "powershell", "-Command",
		fmt.Sprintf("Invoke-WebRequest -Uri '%s' -OutFile '%s'", msiURL, tmpMSI))
	if err := downloadCmd.Run(); err != nil {
		return fmt.Errorf("downloading osquery msi: %w", err)
	}

	installCmd := exec.CommandContext(ctx, "msiexec", "/i", tmpMSI, "/quiet", "/qn")
	var stderr bytes.Buffer
	installCmd.Stderr = &stderr

	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("installing osquery msi: %w (%s)", err, stderr.String())
	}

	// Cleanup
	os.Remove(tmpMSI)

	return nil
}
