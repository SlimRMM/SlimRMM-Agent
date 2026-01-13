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
	"strconv"
	"strings"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/helper"
	"github.com/slimrmm/slimrmm-agent/internal/winget"
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
		return getWindowsUpdatesWithWinget(ctx)
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// getWindowsUpdatesWithWinget gets both Windows system updates and winget updates.
func getWindowsUpdatesWithWinget(ctx context.Context) (*UpdateList, error) {
	slog.Info("starting Windows combined update scan")

	// Get Windows system updates (PSWindowsUpdate)
	systemUpdates, err := getWindowsUpdates(ctx)
	if err != nil {
		slog.Warn("Windows system updates scan failed", "error", err)
		systemUpdates = &UpdateList{Updates: make([]Update, 0), Source: "System"}
	}

	// Get winget updates - only if winget is detected
	wingetUpdates, err := getWingetUpdates(ctx)
	if err != nil {
		slog.Warn("winget updates scan failed", "error", err)
		wingetUpdates = &UpdateList{Updates: make([]Update, 0), Source: "winget"}
	}

	// Combine both update lists
	combined := &UpdateList{
		Updates: make([]Update, 0, len(systemUpdates.Updates)+len(wingetUpdates.Updates)),
		Source:  "combined",
	}
	combined.Updates = append(combined.Updates, systemUpdates.Updates...)
	combined.Updates = append(combined.Updates, wingetUpdates.Updates...)
	combined.Count = len(combined.Updates)

	slog.Info("Windows update scan completed",
		"system_updates", len(systemUpdates.Updates),
		"winget_updates", len(wingetUpdates.Updates),
		"total", combined.Count,
	)

	return combined, nil
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

	script := `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
Where-Object { $_.DisplayName } |
Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, EstimatedSize |
ConvertTo-Json -Compress`

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.Output()
	if err != nil {
		slog.Debug("PowerShell software inventory failed", "error", err)
		return nil, err
	}

	inventory := &SoftwareInventory{
		Packages: make([]Software, 0),
		Source:   "registry",
	}

	// Parse JSON output
	outputStr := strings.TrimSpace(string(output))
	outputStr = strings.TrimPrefix(outputStr, "\xef\xbb\xbf") // Remove BOM if present

	if outputStr == "" || outputStr == "null" {
		return inventory, nil
	}

	// Try parsing as array first
	var rawItems []map[string]interface{}
	if err := json.Unmarshal([]byte(outputStr), &rawItems); err != nil {
		// Try as single object (PowerShell returns object if only one result)
		var singleItem map[string]interface{}
		if err := json.Unmarshal([]byte(outputStr), &singleItem); err != nil {
			slog.Debug("failed to parse software inventory JSON", "error", err)
			return inventory, nil
		}
		rawItems = []map[string]interface{}{singleItem}
	}

	for _, item := range rawItems {
		pkg := Software{Source: "registry"}

		if name, ok := item["DisplayName"].(string); ok {
			pkg.Name = name
		}
		if version, ok := item["DisplayVersion"].(string); ok {
			pkg.Version = version
		}
		if publisher, ok := item["Publisher"].(string); ok {
			pkg.Publisher = publisher
		}
		if installDate, ok := item["InstallDate"].(string); ok {
			pkg.InstallDate = installDate
		}
		if size, ok := item["EstimatedSize"].(float64); ok {
			pkg.Size = int64(size) * 1024 // KB to bytes
		}

		if pkg.Name != "" {
			inventory.Packages = append(inventory.Packages, pkg)
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

# Force UTF-8 output encoding to handle German/Unicode characters correctly
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

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
	output, err := cmd.CombinedOutput()
	outputStr := string(output)
	if err != nil {
		slog.Debug("PowerShell Windows updates failed", "error", err)
		return &UpdateList{
			Updates: make([]Update, 0),
			Source:  "System",
		}, nil
	}

	updates := &UpdateList{
		Updates: make([]Update, 0),
		Source:  "System",
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
			Source: "System",
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
		// Size can be either a number (bytes) or a string like "80MB", "2GB"
		if size, ok := raw["Size"].(float64); ok {
			update.Size = int64(size)
		} else if sizeStr, ok := raw["Size"].(string); ok {
			update.Size = parseSizeString(sizeStr)
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

// parseSizeString parses a human-readable size string like "80MB", "2GB", "518KB" into bytes.
func parseSizeString(s string) int64 {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0
	}

	// Extract numeric part and unit
	var numStr string
	var unit string
	for i, c := range s {
		if (c >= '0' && c <= '9') || c == '.' || c == ',' {
			numStr += string(c)
		} else {
			unit = s[i:]
			break
		}
	}

	// Handle European decimal separator
	numStr = strings.ReplaceAll(numStr, ",", ".")

	num, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0
	}

	// Convert based on unit
	unit = strings.TrimSpace(unit)
	switch {
	case strings.HasPrefix(unit, "GB"):
		return int64(num * 1024 * 1024 * 1024)
	case strings.HasPrefix(unit, "MB"):
		return int64(num * 1024 * 1024)
	case strings.HasPrefix(unit, "KB"):
		return int64(num * 1024)
	case strings.HasPrefix(unit, "B"):
		return int64(num)
	default:
		// Assume bytes if no unit
		return int64(num)
	}
}

// GetWingetUpdates returns available winget package updates on Windows.
func GetWingetUpdates(ctx context.Context) (*UpdateList, error) {
	if runtime.GOOS != "windows" {
		slog.Debug("winget updates scan skipped - not running on Windows")
		return &UpdateList{Updates: make([]Update, 0), Source: "winget"}, nil
	}
	return getWingetUpdates(ctx)
}

// getWingetUpdates scans for available winget package updates.
// It scans both user context (via helper) and system context (direct) to catch all packages.
func getWingetUpdates(ctx context.Context) (*UpdateList, error) {
	updates := &UpdateList{
		Updates: make([]Update, 0),
		Source:  "winget",
	}

	// Track seen package IDs to avoid duplicates
	seenIDs := make(map[string]bool)

	// First try to scan via helper (user context) to catch user-installed packages
	userUpdates := scanWingetViaHelper()
	for _, u := range userUpdates {
		if u.KB != "" && !seenIDs[u.KB] {
			seenIDs[u.KB] = true
			updates.Updates = append(updates.Updates, u)
		}
	}

	// Then scan in system context (as SYSTEM service) to catch system-wide packages
	systemUpdates := scanWingetDirect(ctx)
	for _, u := range systemUpdates {
		if u.KB != "" && !seenIDs[u.KB] {
			seenIDs[u.KB] = true
			updates.Updates = append(updates.Updates, u)
		}
	}

	updates.Count = len(updates.Updates)
	slog.Info("winget scan completed", "user_updates", len(userUpdates), "system_updates", len(systemUpdates), "total_unique", updates.Count)

	return updates, nil
}

// scanWingetViaHelper scans for winget updates using the helper in user context.
func scanWingetViaHelper() []Update {
	updates := make([]Update, 0)

	// Get winget path from the agent's detection (it knows where winget is)
	wingetClient := winget.GetDefault()
	wingetPath := ""
	if wingetClient.IsAvailable() {
		wingetPath = wingetClient.GetBinaryPath()
	}

	// Start helper client
	client := helper.NewClient()
	if err := client.Start(); err != nil {
		slog.Debug("failed to start helper for winget scan", "error", err)
		return updates
	}
	defer client.Stop()

	slog.Info("scanning winget updates via helper (user context)", "winget_path", wingetPath)

	result, err := client.ScanWingetUpdates(wingetPath)
	if err != nil {
		slog.Debug("helper winget scan failed", "error", err)
		return updates
	}

	// Log raw output for debugging
	if result.RawOutput != "" {
		slog.Info("helper winget raw output", "output", result.RawOutput)
	}

	if result.Error != "" {
		slog.Debug("helper winget scan returned error", "error", result.Error)
		return updates
	}

	// Convert helper updates to our Update type
	for _, u := range result.Updates {
		updates = append(updates, Update{
			Name:       u.Name,
			Version:    u.Available, // Available version is the target
			CurrentVer: u.Version,
			Category:   "standard",
			Source:     "winget",
			KB:         u.ID, // Store package ID in KB field
		})
	}

	slog.Info("helper winget scan completed", "updates_found", len(updates))
	return updates
}

// scanWingetDirect scans for winget updates directly (system context).
func scanWingetDirect(ctx context.Context) []Update {
	updates := make([]Update, 0)

	wingetClient := winget.GetDefault()
	if !wingetClient.IsAvailable() {
		slog.Debug("winget not available in system context")
		return updates
	}

	wingetPath := wingetClient.GetBinaryPath()
	if wingetPath == "" {
		return updates
	}

	slog.Info("scanning winget updates directly (system context)", "binary", wingetPath)

	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, wingetPath, "upgrade",
		"--accept-source-agreements",
		"--disable-interactivity",
		"--include-unknown",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		slog.Debug("winget direct scan failed", "error", err)
		return updates
	}

	// Parse output
	lines := strings.Split(string(output), "\n")
	headerFound := false
	separatorFound := false

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" {
			continue
		}

		if strings.Contains(trimmedLine, "█") || strings.Contains(trimmedLine, "▒") {
			continue
		}

		if strings.HasPrefix(trimmedLine, "---") || strings.HasPrefix(trimmedLine, "───") {
			separatorFound = true
			continue
		}

		// Detect header (case-insensitive for localization support)
		lowerLine := strings.ToLower(trimmedLine)
		if strings.HasPrefix(lowerLine, "name") && (strings.Contains(lowerLine, "id") || strings.Contains(lowerLine, "version")) {
			headerFound = true
			continue
		}

		// Skip summary lines (English and German)
		if strings.Contains(trimmedLine, "upgrades available") || strings.Contains(trimmedLine, "upgrade available") ||
			strings.Contains(trimmedLine, "No installed package") || strings.Contains(trimmedLine, "Keine installierten") ||
			strings.Contains(trimmedLine, "Aktualisierungen verfügbar") || strings.Contains(trimmedLine, "Aktualisierung verfügbar") {
			continue
		}

		if headerFound && separatorFound {
			if update := parseWingetLine(trimmedLine); update != nil {
				updates = append(updates, *update)
			}
		}
	}

	slog.Info("winget direct scan completed", "updates_found", len(updates))
	return updates
}

// parseWingetLine parses a single line of winget upgrade output.
func parseWingetLine(line string) *Update {
	// Winget output is tricky because columns are variable width and names can contain spaces
	// The format is roughly: Name | Id | Version | Available | Source
	// But columns are space-padded, not tab-separated
	//
	// Strategy: work from the right side where values are more predictable
	// Source is usually "winget" or "msstore"
	// Version numbers follow patterns like "1.2.3" or "1.2.3.4"

	fields := strings.Fields(line)
	if len(fields) < 4 {
		return nil
	}

	// Last field is usually the source
	source := fields[len(fields)-1]
	if source != "winget" && source != "msstore" && !strings.Contains(source, "store") {
		// Might not have source column, could be version
		source = "winget"
		// Adjust fields
	}

	// Work backwards: source, available version, current version, id, name
	// This is complex because the Name can contain multiple words

	// Simplified approach: if we have at least 5 fields, try to parse
	// [name parts...] [id] [current] [available] [source]
	if len(fields) >= 5 && (fields[len(fields)-1] == "winget" || fields[len(fields)-1] == "msstore") {
		availableVer := fields[len(fields)-2]
		currentVer := fields[len(fields)-3]
		pkgID := fields[len(fields)-4]

		// Name is everything before the ID
		nameEndIdx := len(fields) - 4
		name := strings.Join(fields[:nameEndIdx], " ")

		// Validate that versions look like versions (contain digits)
		if !containsDigit(currentVer) || !containsDigit(availableVer) {
			return nil
		}

		return &Update{
			Name:       name,
			Version:    availableVer, // Available version is what we want to update to
			CurrentVer: currentVer,
			Category:   "standard",
			Source:     "winget",
			KB:         pkgID, // Store package ID in KB field for reference
		}
	}

	// Fallback: try with 4 fields (no source column)
	if len(fields) >= 4 {
		availableVer := fields[len(fields)-1]
		currentVer := fields[len(fields)-2]
		pkgID := fields[len(fields)-3]
		nameEndIdx := len(fields) - 3
		name := strings.Join(fields[:nameEndIdx], " ")

		if containsDigit(currentVer) && containsDigit(availableVer) && nameEndIdx > 0 {
			return &Update{
				Name:       name,
				Version:    availableVer,
				CurrentVer: currentVer,
				Category:   "standard",
				Source:     "winget",
				KB:         pkgID,
			}
		}
	}

	return nil
}

// containsDigit checks if a string contains at least one digit.
func containsDigit(s string) bool {
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}
