// Package actions provides software inventory and update handlers.
package actions

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
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
	Name        string `json:"name"`
	Version     string `json:"version"`
	CurrentVer  string `json:"current_version,omitempty"`
	Category    string `json:"category"` // security, kernel, standard
	Size        int64  `json:"size,omitempty"`
	Source      string `json:"source"`
}

// SoftwareInventory contains the list of installed software.
type SoftwareInventory struct {
	Packages []Software `json:"packages"`
	Count    int        `json:"count"`
	Source   string     `json:"source"`
}

// UpdateList contains available updates.
type UpdateList struct {
	Updates  []Update `json:"updates"`
	Count    int      `json:"count"`
	Source   string   `json:"source"`
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

	// Try rpm (RHEL/CentOS)
	if _, err := exec.LookPath("rpm"); err == nil {
		return getRpmSoftware(ctx)
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

	return nil, fmt.Errorf("no supported package manager found")
}

func getAptUpdates(ctx context.Context) (*UpdateList, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Update package list first
	exec.CommandContext(ctx, "apt", "update", "-qq").Run()

	cmd := exec.CommandContext(ctx, "apt", "list", "--upgradable")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	updates := &UpdateList{
		Updates: make([]Update, 0),
		Source:  "apt",
	}

	// Parse output: package/source version [arch]
	re := regexp.MustCompile(`^([^/]+)/\S+\s+(\S+)\s+`)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Listing") {
			continue
		}

		matches := re.FindStringSubmatch(line)
		if len(matches) >= 3 {
			update := Update{
				Name:    matches[1],
				Version: matches[2],
				Source:  "apt",
			}

			// Categorize
			if strings.Contains(strings.ToLower(line), "security") {
				update.Category = "security"
			} else if strings.Contains(matches[1], "linux-") {
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

// Windows updates
func getWindowsUpdates(ctx context.Context) (*UpdateList, error) {
	// Windows Update API is complex, return empty for now
	return &UpdateList{
		Updates: make([]Update, 0),
		Source:  "windows_update",
	}, nil
}
