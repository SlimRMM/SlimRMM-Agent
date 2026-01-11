// Package actions provides software inventory and update handlers.
package actions

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Software represents an installed software package.
type Software struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher,omitempty"`
	InstallDate string `json:"install_date,omitempty"`
	Size        int64  `json:"size,omitempty"`
	Source      string `json:"source"` // apt, rpm, brew, etc.
}

// Update represents an available system update.
type Update struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	CurrentVer string `json:"current_version,omitempty"`
	Category   string `json:"category"` // security, kernel, standard
	Size       int64  `json:"size,omitempty"`
	Source     string `json:"source"`
}

// SoftwareInventory contains the list of installed software.
type SoftwareInventory struct {
	Packages []Software `json:"packages"`
	Count    int        `json:"count"`
	Source   string     `json:"source"`
}

// UpdateList contains available updates.
type UpdateList struct {
	Updates []Update `json:"updates"`
	Count   int      `json:"count"`
	Source  string   `json:"source"`
}

// GetSoftwareInventory returns the list of installed software.
func GetSoftwareInventory(ctx context.Context) (*SoftwareInventory, error) {
	switch runtime.GOOS {
	case "linux":
		return getLinuxSoftware(ctx)
	case "darwin":
		return getMacOSSoftware(ctx)
	case "windows":
		return getWindowsSoftware(ctx)
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// GetAvailableUpdates returns the list of available updates.
func GetAvailableUpdates(ctx context.Context) (*UpdateList, error) {
	switch runtime.GOOS {
	case "linux":
		return getLinuxUpdates(ctx)
	case "darwin":
		return getMacOSUpdates(ctx)
	case "windows":
		return getWindowsUpdates(ctx)
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// Linux software inventory
func getLinuxSoftware(ctx context.Context) (*SoftwareInventory, error) {
	// Try dpkg first (Debian/Ubuntu)
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		return getDpkgSoftware(ctx)
	}

	// Try rpm (RHEL/CentOS/Fedora)
	if _, err := exec.LookPath("rpm"); err == nil {
		return getRpmSoftware(ctx)
	}

	// Try pacman (Arch Linux)
	if _, err := exec.LookPath("pacman"); err == nil {
		return getPacmanSoftware(ctx)
	}

	return nil, fmt.Errorf("no supported package manager found")
}

func getDpkgSoftware(ctx context.Context) (*SoftwareInventory, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Package}\t${Version}\t${Installed-Size}\n")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	inventory := &SoftwareInventory{
		Packages: make([]Software, 0),
		Source:   "dpkg",
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) >= 2 {
			pkg := Software{
				Name:    parts[0],
				Version: parts[1],
				Source:  "dpkg",
			}
			if len(parts) >= 3 {
				fmt.Sscanf(parts[2], "%d", &pkg.Size)
				pkg.Size *= 1024 // Convert KB to bytes
			}
			inventory.Packages = append(inventory.Packages, pkg)
		}
	}

	inventory.Count = len(inventory.Packages)
	return inventory, nil
}

func getRpmSoftware(ctx context.Context) (*SoftwareInventory, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{SIZE}\t%{VENDOR}\n")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	inventory := &SoftwareInventory{
		Packages: make([]Software, 0),
		Source:   "rpm",
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) >= 2 {
			pkg := Software{
				Name:    parts[0],
				Version: parts[1],
				Source:  "rpm",
			}
			if len(parts) >= 3 {
				fmt.Sscanf(parts[2], "%d", &pkg.Size)
			}
			if len(parts) >= 4 {
				pkg.Publisher = parts[3]
			}
			inventory.Packages = append(inventory.Packages, pkg)
		}
	}

	inventory.Count = len(inventory.Packages)
	return inventory, nil
}

func getPacmanSoftware(ctx context.Context) (*SoftwareInventory, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "pacman", "-Q")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	inventory := &SoftwareInventory{
		Packages: make([]Software, 0),
		Source:   "pacman",
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) >= 2 {
			inventory.Packages = append(inventory.Packages, Software{
				Name:    parts[0],
				Version: parts[1],
				Source:  "pacman",
			})
		}
	}

	inventory.Count = len(inventory.Packages)
	return inventory, nil
}

// macOS software inventory
func getMacOSSoftware(ctx context.Context) (*SoftwareInventory, error) {
	inventory := &SoftwareInventory{
		Packages: make([]Software, 0),
		Source:   "brew",
	}

	// Get Homebrew packages
	if _, err := exec.LookPath("brew"); err == nil {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "brew", "list", "--versions")
		output, err := cmd.Output()
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(output))
			for scanner.Scan() {
				parts := strings.Fields(scanner.Text())
				if len(parts) >= 2 {
					inventory.Packages = append(inventory.Packages, Software{
						Name:    parts[0],
						Version: parts[len(parts)-1],
						Source:  "brew",
					})
				}
			}
		}
	}

	inventory.Count = len(inventory.Packages)
	return inventory, nil
}

// Windows software inventory
func getWindowsSoftware(ctx context.Context) (*SoftwareInventory, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	script := `Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName } |
Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, EstimatedSize |
ConvertTo-Json`

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Parse JSON output (simplified)
	inventory := &SoftwareInventory{
		Packages: make([]Software, 0),
		Source:   "registry",
	}

	// Basic parsing - in production would use proper JSON parsing
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "DisplayName") {
			// Extract values - simplified
			inventory.Packages = append(inventory.Packages, Software{
				Source: "registry",
			})
		}
	}

	inventory.Count = len(inventory.Packages)
	return inventory, nil
}

// Linux updates
func getLinuxUpdates(ctx context.Context) (*UpdateList, error) {
	// Try apt first
	if _, err := exec.LookPath("apt"); err == nil {
		return getAptUpdates(ctx)
	}

	// Try dnf
	if _, err := exec.LookPath("dnf"); err == nil {
		return getDnfUpdates(ctx)
	}

	// Try yum
	if _, err := exec.LookPath("yum"); err == nil {
		return getYumUpdates(ctx)
	}

	// Try pacman (Arch Linux)
	if _, err := exec.LookPath("pacman"); err == nil {
		return getPacmanUpdates(ctx)
	}

	return nil, fmt.Errorf("no supported package manager found")
}

func getAptUpdates(ctx context.Context) (*UpdateList, error) {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	updates := &UpdateList{
		Updates: make([]Update, 0),
		Source:  "apt",
	}

	// Try apt-get upgrade simulation first (more reliable)
	cmd := exec.CommandContext(ctx, "apt-get", "-s", "upgrade")
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C")
	output, err := cmd.Output()
	if err == nil {
		// Parse output: Inst package (version ...)
		instRe := regexp.MustCompile(`^Inst (\S+) \[([^\]]*)\] \((\S+)`)
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			line := scanner.Text()
			matches := instRe.FindStringSubmatch(line)
			if len(matches) >= 4 {
				update := Update{
					Name:       matches[1],
					CurrentVer: matches[2],
					Version:    matches[3],
					Source:     "apt",
				}

				// Categorize
				if strings.Contains(strings.ToLower(line), "security") {
					update.Category = "security"
				} else if strings.HasPrefix(matches[1], "linux-") {
					update.Category = "kernel"
				} else {
					update.Category = "standard"
				}

				updates.Updates = append(updates.Updates, update)
			}
		}

		if len(updates.Updates) > 0 {
			updates.Count = len(updates.Updates)
			return updates, nil
		}
	}

	// Fallback to apt list --upgradable
	cmd = exec.CommandContext(ctx, "apt", "list", "--upgradable", "-qq")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	output, err = cmd.CombinedOutput()
	if err != nil {
		// Try one more fallback
		cmd = exec.CommandContext(ctx, "apt-get", "-s", "dist-upgrade")
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C")
		output, _ = cmd.Output()
	}

	// Parse output: package/source version arch [upgradable from: old_version]
	// Example: curl/jammy-updates,jammy-security 7.81.0-1ubuntu1.16 amd64 [upgradable from: 7.81.0-1ubuntu1.15]
	listRe := regexp.MustCompile(`^([^/\s]+)/\S+\s+(\S+)`)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		// Skip header lines
		if strings.HasPrefix(line, "Listing") || strings.HasPrefix(line, "WARNING") || line == "" {
			continue
		}

		matches := listRe.FindStringSubmatch(line)
		if len(matches) >= 3 {
			update := Update{
				Name:    matches[1],
				Version: matches[2],
				Source:  "apt",
			}

			// Extract current version if present
			if idx := strings.Index(line, "upgradable from:"); idx > 0 {
				rest := line[idx+16:]
				rest = strings.TrimPrefix(rest, " ")
				rest = strings.TrimSuffix(rest, "]")
				update.CurrentVer = rest
			}

			// Categorize
			if strings.Contains(strings.ToLower(line), "security") {
				update.Category = "security"
			} else if strings.HasPrefix(matches[1], "linux-") {
				update.Category = "kernel"
			} else {
				update.Category = "standard"
			}

			updates.Updates = append(updates.Updates, update)
		}
	}

	updates.Count = len(updates.Updates)
	return updates, nil
}

func getDnfUpdates(ctx context.Context) (*UpdateList, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dnf", "check-update", "-q")
	output, _ := cmd.Output() // dnf returns exit code 100 when updates available

	updates := &UpdateList{
		Updates: make([]Update, 0),
		Source:  "dnf",
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) >= 2 {
			updates.Updates = append(updates.Updates, Update{
				Name:     parts[0],
				Version:  parts[1],
				Category: "standard",
				Source:   "dnf",
			})
		}
	}

	updates.Count = len(updates.Updates)
	return updates, nil
}

func getYumUpdates(ctx context.Context) (*UpdateList, error) {
	return getDnfUpdates(ctx) // Same format
}

func getPacmanUpdates(ctx context.Context) (*UpdateList, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Sync database first
	exec.CommandContext(ctx, "pacman", "-Sy").Run()

	// Check for updates
	cmd := exec.CommandContext(ctx, "pacman", "-Qu")
	output, _ := cmd.Output() // pacman returns exit code 1 when no updates

	updates := &UpdateList{
		Updates: make([]Update, 0),
		Source:  "pacman",
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) >= 4 {
			// Format: package current_version -> new_version
			update := Update{
				Name:       parts[0],
				CurrentVer: parts[1],
				Version:    parts[3],
				Category:   "standard",
				Source:     "pacman",
			}

			// Check for kernel updates
			if strings.HasPrefix(parts[0], "linux") {
				update.Category = "kernel"
			}

			updates.Updates = append(updates.Updates, update)
		} else if len(parts) >= 2 {
			// Fallback for simple format: package version
			updates.Updates = append(updates.Updates, Update{
				Name:     parts[0],
				Version:  parts[1],
				Category: "standard",
				Source:   "pacman",
			})
		}
	}

	updates.Count = len(updates.Updates)
	return updates, nil
}

// macOS updates
func getMacOSUpdates(ctx context.Context) (*UpdateList, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "softwareupdate", "-l")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	updates := &UpdateList{
		Updates: make([]Update, 0),
		Source:  "softwareupdate",
	}

	re := regexp.MustCompile(`\* Label: (.+)`)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		matches := re.FindStringSubmatch(scanner.Text())
		if len(matches) >= 2 {
			updates.Updates = append(updates.Updates, Update{
				Name:     matches[1],
				Category: "standard",
				Source:   "softwareupdate",
			})
		}
	}

	updates.Count = len(updates.Updates)
	return updates, nil
}

// Windows updates using PSWindowsUpdate module
func getWindowsUpdates(ctx context.Context) (*UpdateList, error) {
	slog.Info("starting Windows updates scan using PSWindowsUpdate")
	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()

	// PowerShell script to install PSWindowsUpdate if needed and get updates
	script := `
$ErrorActionPreference = 'SilentlyContinue'

# Check if PSWindowsUpdate module is installed
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    try {
        # Install NuGet provider if needed
        if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers | Out-Null
        }
        # Install PSWindowsUpdate module
        Install-Module -Name PSWindowsUpdate -Force -Scope AllUsers -AllowClobber | Out-Null
    } catch {
        # Fall back to COM object method if module installation fails
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        $SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software'")
        $Updates = @()
        foreach ($Update in $SearchResult.Updates) {
            $Category = "standard"
            foreach ($Cat in $Update.Categories) {
                if ($Cat.Name -match "Security|Critical") { $Category = "security"; break }
            }
            $Updates += @{
                Title = $Update.Title
                KB = ""
                Size = $Update.MaxDownloadSize
                Category = $Category
            }
        }
        $Updates | ConvertTo-Json -Depth 3 -Compress
        exit
    }
}

# Import module and get updates
Import-Module PSWindowsUpdate -Force
$Updates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot 2>$null | ForEach-Object {
    $Category = "standard"
    if ($_.Title -match "Security|Critical") { $Category = "security" }
    if ($_.Title -match "Cumulative|Feature") { $Category = "feature" }
    @{
        Title = $_.Title
        KB = $_.KB
        Size = $_.Size
        Category = $Category
    }
}

if ($Updates) {
    $Updates | ConvertTo-Json -Depth 3 -Compress
} else {
    Write-Output "[]"
}
`

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	slog.Info("executing PowerShell for Windows updates")
	output, err := cmd.CombinedOutput()
	if err != nil {
		slog.Error("PowerShell Windows updates failed", "error", err, "output", string(output))
		return &UpdateList{
			Updates: make([]Update, 0),
			Source:  "pswindowsupdate",
		}, nil
	}
	slog.Info("PowerShell Windows updates completed", "output_len", len(output))

	updates := &UpdateList{
		Updates: make([]Update, 0),
		Source:  "pswindowsupdate",
	}

	outputStr := strings.TrimSpace(string(output))
	if outputStr == "" || outputStr == "[]" || outputStr == "null" {
		updates.Count = 0
		return updates, nil
	}

	var rawUpdates []map[string]interface{}
	if err := parseWindowsUpdateJSON(outputStr, &rawUpdates); err != nil {
		var singleUpdate map[string]interface{}
		if err := parseWindowsUpdateJSON(outputStr, &singleUpdate); err == nil {
			rawUpdates = append(rawUpdates, singleUpdate)
		}
	}

	for _, raw := range rawUpdates {
		update := Update{
			Source: "pswindowsupdate",
		}

		if title, ok := raw["Title"].(string); ok {
			update.Name = title
		}
		if kb, ok := raw["KB"].(string); ok && kb != "" {
			update.Version = kb
		}
		if category, ok := raw["Category"].(string); ok {
			update.Category = category
		}
		if size, ok := raw["Size"].(float64); ok {
			update.Size = int64(size)
		}

		if update.Name != "" {
			updates.Updates = append(updates.Updates, update)
		}
	}

	updates.Count = len(updates.Updates)
	return updates, nil
}

// parseWindowsUpdateJSON is a helper to parse JSON from PowerShell output.
func parseWindowsUpdateJSON(data string, v interface{}) error {
	// Remove BOM if present
	data = strings.TrimPrefix(data, "\xef\xbb\xbf")
	data = strings.TrimSpace(data)

	return json.Unmarshal([]byte(data), v)
}
