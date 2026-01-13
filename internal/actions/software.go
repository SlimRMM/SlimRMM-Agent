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
	KB         string `json:"kb,omitempty"`       // KB article number for Windows updates
	Category   string `json:"category"`           // security, kernel, standard
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
	slog.Info("starting Linux updates scan")

	// Try apt first
	if _, err := exec.LookPath("apt"); err == nil {
		slog.Info("using apt for updates scan")
		return getAptUpdates(ctx)
	}

	// Try dnf
	if _, err := exec.LookPath("dnf"); err == nil {
		slog.Info("using dnf for updates scan")
		return getDnfUpdates(ctx)
	}

	// Try yum
	if _, err := exec.LookPath("yum"); err == nil {
		slog.Info("using yum for updates scan")
		return getYumUpdates(ctx)
	}

	// Try pacman (Arch Linux)
	if _, err := exec.LookPath("pacman"); err == nil {
		slog.Info("using pacman for updates scan")
		return getPacmanUpdates(ctx)
	}

	slog.Error("no supported package manager found for updates scan")
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
	slog.Info("running apt-get -s upgrade")
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
	slog.Info("apt updates scan completed", "count", updates.Count)
	return updates, nil
}

func getDnfUpdates(ctx context.Context) (*UpdateList, error) {
	slog.Info("running dnf check-update")
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
	slog.Info("dnf updates scan completed", "count", updates.Count)
	return updates, nil
}

func getYumUpdates(ctx context.Context) (*UpdateList, error) {
	slog.Info("running yum check-update (via dnf)")
	return getDnfUpdates(ctx) // Same format
}

func getPacmanUpdates(ctx context.Context) (*UpdateList, error) {
	slog.Info("running pacman updates scan")
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	updates := &UpdateList{
		Updates: make([]Update, 0),
		Source:  "pacman",
	}

	// Sync database first
	slog.Info("syncing pacman database")
	exec.CommandContext(ctx, "pacman", "-Sy").Run()

	// Check for official repo updates
	slog.Info("running pacman -Qu")
	cmd := exec.CommandContext(ctx, "pacman", "-Qu")
	output, _ := cmd.Output() // pacman returns exit code 1 when no updates

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

	// Check for AUR updates using available AUR helpers
	aurUpdates := getAURUpdates(ctx)
	updates.Updates = append(updates.Updates, aurUpdates...)

	updates.Count = len(updates.Updates)
	slog.Info("pacman updates scan completed", "count", updates.Count)
	return updates, nil
}

// getAURUpdates checks for AUR package updates using available AUR helpers
func getAURUpdates(ctx context.Context) []Update {
	// AUR helpers to try in order of preference
	aurHelpers := []struct {
		name string
		args []string
	}{
		{"yay", []string{"-Qua"}},        // yay -Qua shows AUR updates
		{"paru", []string{"-Qua"}},       // paru (similar to yay)
		{"pikaur", []string{"-Qua"}},     // pikaur
		{"trizen", []string{"-Qua"}},     // trizen
		{"pacaur", []string{"-k", "-a"}}, // pacaur -k -a for AUR updates
		{"aurman", []string{"-Qua"}},     // aurman
	}

	for _, helper := range aurHelpers {
		if _, err := exec.LookPath(helper.name); err == nil {
			slog.Info("checking AUR updates", "helper", helper.name)
			cmd := exec.CommandContext(ctx, helper.name, helper.args...)
			output, err := cmd.Output()
			if err != nil {
				slog.Warn("AUR helper failed", "helper", helper.name, "error", err)
				continue
			}

			var aurUpdates []Update
			scanner := bufio.NewScanner(bytes.NewReader(output))
			for scanner.Scan() {
				line := scanner.Text()
				parts := strings.Fields(line)
				if len(parts) >= 4 {
					// Format: package current_version -> new_version
					aurUpdates = append(aurUpdates, Update{
						Name:       parts[0],
						CurrentVer: parts[1],
						Version:    parts[3],
						Category:   "aur",
						Source:     helper.name,
					})
				} else if len(parts) >= 2 {
					aurUpdates = append(aurUpdates, Update{
						Name:     parts[0],
						Version:  parts[1],
						Category: "aur",
						Source:   helper.name,
					})
				}
			}

			slog.Info("AUR updates found", "helper", helper.name, "count", len(aurUpdates))
			return aurUpdates
		}
	}

	slog.Info("no AUR helper found, skipping AUR updates")
	return nil
}

// macOS updates
func getMacOSUpdates(ctx context.Context) (*UpdateList, error) {
	slog.Info("starting macOS updates scan using softwareupdate")
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "softwareupdate", "-l")
	output, err := cmd.CombinedOutput()
	if err != nil {
		slog.Error("softwareupdate failed", "error", err, "output", string(output))
		return nil, err
	}
	slog.Info("softwareupdate completed", "output", string(output))

	updates := &UpdateList{
		Updates: make([]Update, 0),
		Source:  "softwareupdate",
	}

	// Parse both old and new format
	// Old: * Label: <name>
	// New: * <name>
	//        Version: <version>
	labelRe := regexp.MustCompile(`\* Label: (.+)`)
	newFormatRe := regexp.MustCompile(`^\s*\*\s+(.+)$`)
	versionRe := regexp.MustCompile(`^\s+Version:\s+(.+)$`)

	lines := strings.Split(string(output), "\n")
	var currentName string
	for _, line := range lines {
		// Try old format first
		if matches := labelRe.FindStringSubmatch(line); len(matches) >= 2 {
			updates.Updates = append(updates.Updates, Update{
				Name:     matches[1],
				Category: "standard",
				Source:   "softwareupdate",
			})
			continue
		}

		// Try new format
		if matches := newFormatRe.FindStringSubmatch(line); len(matches) >= 2 {
			currentName = matches[1]
		} else if matches := versionRe.FindStringSubmatch(line); len(matches) >= 2 && currentName != "" {
			updates.Updates = append(updates.Updates, Update{
				Name:     currentName,
				Version:  matches[1],
				Category: "standard",
				Source:   "softwareupdate",
			})
			currentName = ""
		}
	}

	updates.Count = len(updates.Updates)
	slog.Info("macOS updates scan completed", "count", updates.Count)
	return updates, nil
}

// Windows updates using PSWindowsUpdate module
func getWindowsUpdates(ctx context.Context) (*UpdateList, error) {
	slog.Info("starting Windows updates scan using PSWindowsUpdate")
	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()

	// PowerShell script to install PSWindowsUpdate if needed and get updates
	script := `
$ErrorActionPreference = 'Stop'

# Set execution policy for this process to allow module installation
try {
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
} catch {
    # Ignore if we can't change it (already set or restricted by GPO)
}

# Check if PSWindowsUpdate module is installed
$moduleInstalled = Get-Module -ListAvailable -Name PSWindowsUpdate
if (-not $moduleInstalled) {
    Write-Host "PSWindowsUpdate module not found, installing..."
    try {
        # Set PSGallery as trusted
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue

        # Install NuGet provider if needed
        $nuget = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue
        if (-not $nuget -or $nuget.Version -lt [Version]"2.8.5.201") {
            Write-Host "Installing NuGet provider..."
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers | Out-Null
        }

        # Install PSWindowsUpdate module
        Write-Host "Installing PSWindowsUpdate module..."
        Install-Module -Name PSWindowsUpdate -Force -Scope AllUsers -AllowClobber -SkipPublisherCheck | Out-Null
        Write-Host "PSWindowsUpdate module installed successfully"
    } catch {
        Write-Host "Module installation failed: $($_.Exception.Message)"
        # Fall back to COM object method if module installation fails
        Write-Host "Using COM object fallback..."
        try {
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
        } catch {
            Write-Host "COM fallback failed: $($_.Exception.Message)"
            Write-Output "[]"
        }
        exit
    }
}

# Import module and get updates
Write-Host "Importing PSWindowsUpdate module..."
Import-Module PSWindowsUpdate -Force -ErrorAction Stop

Write-Host "Running Get-WindowsUpdate..."
$RawUpdates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot 2>$null

# Build array of update objects explicitly (avoid PowerShell pipeline grouping issues)
$UpdatesArray = @()
foreach ($Update in $RawUpdates) {
    $Category = "standard"
    if ($Update.Title -match "Security|Critical") { $Category = "security" }
    if ($Update.Title -match "Cumulative|Feature") { $Category = "feature" }
    $UpdatesArray += [PSCustomObject]@{
        Title = $Update.Title
        KB = $Update.KB
        Size = $Update.Size
        Category = $Category
    }
}

Write-Host "Found $($UpdatesArray.Count) updates"
if ($UpdatesArray.Count -gt 0) {
    # Output as JSON array - use @() to ensure array even with single item
    ConvertTo-Json -InputObject @($UpdatesArray) -Depth 3 -Compress
} else {
    Write-Output "[]"
}
`

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	slog.Info("executing PowerShell for Windows updates")
	output, err := cmd.CombinedOutput()
	outputStr := string(output)
	if err != nil {
		slog.Error("PowerShell Windows updates failed", "error", err, "output", outputStr)
		return &UpdateList{
			Updates: make([]Update, 0),
			Source:  "pswindowsupdate",
		}, nil
	}
	slog.Info("PowerShell Windows updates completed", "output", outputStr)

	updates := &UpdateList{
		Updates: make([]Update, 0),
		Source:  "pswindowsupdate",
	}

	// Find JSON in output (last line that starts with [ or {)
	jsonData := ""
	lines := strings.Split(outputStr, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "[") || strings.HasPrefix(line, "{") {
			jsonData = line
			break
		}
	}

	if jsonData == "" || jsonData == "[]" || jsonData == "null" {
		updates.Count = 0
		return updates, nil
	}

	var rawUpdates []map[string]interface{}
	if err := parseWindowsUpdateJSON(jsonData, &rawUpdates); err != nil {
		slog.Warn("failed to parse updates JSON as array", "error", err, "json", jsonData)
		var singleUpdate map[string]interface{}
		if err := parseWindowsUpdateJSON(jsonData, &singleUpdate); err == nil {
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
			update.KB = kb
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
