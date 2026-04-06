// Package actions provides system control actions.
package actions

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// RestartSystem restarts the system.
func RestartSystem(ctx context.Context, force bool, delay int) error {
	if delay <= 0 {
		delay = 5
	}

	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		if force {
			cmd = exec.CommandContext(ctx, "shutdown", "-r", "now")
		} else {
			cmd = exec.CommandContext(ctx, "shutdown", "-r", fmt.Sprintf("+%d", delay/60))
		}
	case "darwin":
		if force {
			cmd = exec.CommandContext(ctx, "shutdown", "-r", "now")
		} else {
			cmd = exec.CommandContext(ctx, "shutdown", "-r", fmt.Sprintf("+%d", delay/60))
		}
	case "windows":
		if force {
			cmd = exec.CommandContext(ctx, "shutdown", "/r", "/f", "/t", "0")
		} else {
			cmd = exec.CommandContext(ctx, "shutdown", "/r", "/t", fmt.Sprintf("%d", delay))
		}
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	return cmd.Start()
}

// ShutdownSystem shuts down the system.
func ShutdownSystem(ctx context.Context, force bool, delay int) error {
	if delay <= 0 {
		delay = 5
	}

	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		if force {
			cmd = exec.CommandContext(ctx, "shutdown", "-h", "now")
		} else {
			cmd = exec.CommandContext(ctx, "shutdown", "-h", fmt.Sprintf("+%d", delay/60))
		}
	case "darwin":
		if force {
			cmd = exec.CommandContext(ctx, "shutdown", "-h", "now")
		} else {
			cmd = exec.CommandContext(ctx, "shutdown", "-h", fmt.Sprintf("+%d", delay/60))
		}
	case "windows":
		if force {
			cmd = exec.CommandContext(ctx, "shutdown", "/s", "/f", "/t", "0")
		} else {
			cmd = exec.CommandContext(ctx, "shutdown", "/s", "/t", fmt.Sprintf("%d", delay))
		}
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	return cmd.Start()
}

// CancelShutdown cancels a pending shutdown.
func CancelShutdown(ctx context.Context) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux", "darwin":
		cmd = exec.CommandContext(ctx, "shutdown", "-c")
	case "windows":
		cmd = exec.CommandContext(ctx, "shutdown", "/a")
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	return cmd.Run()
}

// ExecutePatches installs system updates.
func ExecutePatches(ctx context.Context, categories []string, reboot bool) (*CommandResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	var cmd *exec.Cmd
	var preCmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		// Detect package manager
		if _, err := exec.LookPath("apt-get"); err == nil {
			// Update package list first
			preCmd = exec.CommandContext(ctx, "apt-get", "update", "-qq")
			cmd = exec.CommandContext(ctx, "apt-get", "upgrade", "-y")
		} else if _, err := exec.LookPath("dnf"); err == nil {
			cmd = exec.CommandContext(ctx, "dnf", "upgrade", "-y")
		} else if _, err := exec.LookPath("yum"); err == nil {
			cmd = exec.CommandContext(ctx, "yum", "update", "-y")
		} else if _, err := exec.LookPath("pacman"); err == nil {
			// Arch Linux: sync and upgrade
			cmd = exec.CommandContext(ctx, "pacman", "-Syu", "--noconfirm")
		} else {
			return nil, fmt.Errorf("no supported package manager found")
		}
	case "darwin":
		cmd = exec.CommandContext(ctx, "softwareupdate", "-i", "-a", "--agree-to-license")
	case "windows":
		// Use PSWindowsUpdate module for installing updates
		script := `
$ErrorActionPreference = 'Stop'

# Ensure PSWindowsUpdate is installed
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers | Out-Null
    }
    Install-Module -Name PSWindowsUpdate -Force -Scope AllUsers -AllowClobber | Out-Null
}

Import-Module PSWindowsUpdate -Force

# Install all available updates
$Results = Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -Verbose 4>&1

# Output results
$Results | ForEach-Object { Write-Output $_ }

# Return success
Write-Output "Windows Update completed successfully"
`
		cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	// Run pre-command if set (e.g., apt-get update)
	if preCmd != nil {
		if err := preCmd.Run(); err != nil {
			slog.Warn("pre-command failed", "error", err)
		}
	}

	start := time.Now()
	output, err := cmd.CombinedOutput()

	result := &CommandResult{
		Command:  "execute_patches",
		Stdout:   truncateOutput(string(output)),
		Duration: time.Since(start).Milliseconds(),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
		result.Stderr = err.Error()
	}

	// Schedule reboot if requested and patches were actually installed successfully
	patchesInstalled := err == nil && result.ExitCode == 0 && strings.TrimSpace(result.Stdout) != ""
	if reboot && err == nil && patchesInstalled {
		slog.Info("scheduling reboot after successful patch installation",
			"patches_installed", patchesInstalled,
			"delay", "60s")
		go func() {
			time.Sleep(60 * time.Second)
			slog.Info("executing scheduled post-patch reboot")
			RestartSystem(context.Background(), false, 0)
		}()
	}

	return result, nil
}

// UninstallSoftware removes a software package.
func UninstallSoftware(ctx context.Context, packageName string) (*CommandResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("apt-get"); err == nil {
			cmd = exec.CommandContext(ctx, "apt-get", "remove", "-y", packageName)
		} else if _, err := exec.LookPath("dnf"); err == nil {
			cmd = exec.CommandContext(ctx, "dnf", "remove", "-y", packageName)
		} else if _, err := exec.LookPath("yum"); err == nil {
			cmd = exec.CommandContext(ctx, "yum", "remove", "-y", packageName)
		} else if _, err := exec.LookPath("pacman"); err == nil {
			cmd = exec.CommandContext(ctx, "pacman", "-R", "--noconfirm", packageName)
		} else {
			return nil, fmt.Errorf("no supported package manager found")
		}
	case "darwin":
		if _, err := exec.LookPath("brew"); err == nil {
			cmd = exec.CommandContext(ctx, "brew", "uninstall", packageName)
		} else {
			return nil, fmt.Errorf("homebrew not found")
		}
	case "windows":
		// Try winget first, then fall back to msiexec
		cmd = exec.CommandContext(ctx, "winget", "uninstall", "--id", packageName, "-e", "--silent")
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	start := time.Now()
	output, err := cmd.CombinedOutput()

	result := &CommandResult{
		Command:  fmt.Sprintf("uninstall %s", packageName),
		Stdout:   truncateOutput(string(output)),
		Duration: time.Since(start).Milliseconds(),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
		result.Stderr = err.Error()
	}

	return result, nil
}

// PatchDetail holds information about an individual patch that was processed.
type PatchDetail struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	KB      string `json:"kb,omitempty"`
	Status  string `json:"status"`
}

// ParsePatchOutput parses command output to extract individual patch results.
// It detects the OS and package manager format automatically.
func ParsePatchOutput(output string) (installed []PatchDetail, failed []PatchDetail) {
	switch runtime.GOOS {
	case "linux":
		installed, failed = parseLinuxPatchOutput(output)
	case "windows":
		installed, failed = parseWindowsPatchOutput(output)
	case "darwin":
		installed, failed = parseDarwinPatchOutput(output)
	default:
		// Unsupported OS, return empty
	}
	return installed, failed
}

// parseLinuxPatchOutput parses apt, dnf, and yum output for patch details.
func parseLinuxPatchOutput(output string) (installed []PatchDetail, failed []PatchDetail) {
	scanner := bufio.NewScanner(strings.NewReader(output))

	// apt-get: "Setting up <package> (<version>) ..."
	aptPattern := regexp.MustCompile(`^Setting up ([^\s]+)\s+\(([^)]+)\)`)
	// dnf/yum: "Updated: <package>-<version>.<arch>" or "Installed: <package>-<version>.<arch>"
	dnfUpdatedPattern := regexp.MustCompile(`^\s*(Updated|Installed):\s+(\S+)`)
	// dnf/yum upgrade listing: "Upgrading:"
	dnfUpgradingPattern := regexp.MustCompile(`^Upgrading:\s*$`)
	// pacman: "upgrading <package>..." or "installing <package>..."
	pacmanPattern := regexp.MustCompile(`^(upgrading|installing)\s+([^\s.]+)`)
	// Error patterns
	aptFailPattern := regexp.MustCompile(`^E:\s+.*failed.*?([^\s]+)`)

	inDnfUpgrading := false

	for scanner.Scan() {
		line := scanner.Text()

		// apt-get output
		if m := aptPattern.FindStringSubmatch(line); m != nil {
			installed = append(installed, PatchDetail{
				Name:    m[1],
				Version: m[2],
				Status:  "installed",
			})
			continue
		}

		// apt-get failure
		if m := aptFailPattern.FindStringSubmatch(line); m != nil {
			failed = append(failed, PatchDetail{
				Name:   m[1],
				Status: "failed",
			})
			continue
		}

		// dnf/yum "Updated:" or "Installed:" summary lines
		if m := dnfUpdatedPattern.FindStringSubmatch(line); m != nil {
			pkg := m[2]
			// Split package-version if present (e.g., "curl-7.88.1-1.el9.x86_64")
			name, ver := splitRPMName(pkg)
			installed = append(installed, PatchDetail{
				Name:    name,
				Version: ver,
				Status:  "installed",
			})
			continue
		}

		// Track dnf "Upgrading:" section
		if dnfUpgradingPattern.MatchString(line) {
			inDnfUpgrading = true
			continue
		}
		if inDnfUpgrading && strings.TrimSpace(line) == "" {
			inDnfUpgrading = false
			continue
		}

		// pacman output
		if m := pacmanPattern.FindStringSubmatch(line); m != nil {
			installed = append(installed, PatchDetail{
				Name:   m[2],
				Status: "installed",
			})
			continue
		}
	}

	return installed, failed
}

// parseWindowsPatchOutput parses PSWindowsUpdate output for individual KB results.
func parseWindowsPatchOutput(output string) (installed []PatchDetail, failed []PatchDetail) {
	scanner := bufio.NewScanner(strings.NewReader(output))

	// PSWindowsUpdate verbose output patterns
	kbPattern := regexp.MustCompile(`(KB\d+)`)
	installedPattern := regexp.MustCompile(`(?i)(installed|accepted)\s+.*?(KB\d+)\s+(.*)`)
	failedPattern := regexp.MustCompile(`(?i)(failed|rejected)\s+.*?(KB\d+)\s+(.*)`)
	verboseInstall := regexp.MustCompile(`(?i)VERBOSE:\s+Installing update:\s+(.*?)\s*\((KB\d+)\)`)
	verboseInstalled := regexp.MustCompile(`(?i)VERBOSE:\s+Installed:\s+(.*?)\s*\((KB\d+)\)`)

	// Track KBs we've already seen to avoid duplicates
	seen := make(map[string]bool)

	for scanner.Scan() {
		line := scanner.Text()

		// Check verbose "Installing update" lines
		if m := verboseInstall.FindStringSubmatch(line); m != nil {
			kb := m[2]
			if !seen[kb] {
				seen[kb] = true
				installed = append(installed, PatchDetail{
					Name:   strings.TrimSpace(m[1]),
					KB:     kb,
					Status: "installing",
				})
			}
			continue
		}

		// Check verbose "Installed" lines (final status)
		if m := verboseInstalled.FindStringSubmatch(line); m != nil {
			kb := m[2]
			if !seen[kb] {
				seen[kb] = true
			}
			// Update status to installed for any previously seen entry
			for i := range installed {
				if installed[i].KB == kb {
					installed[i].Status = "installed"
				}
			}
			continue
		}

		// Check tabular installed status
		if m := installedPattern.FindStringSubmatch(line); m != nil {
			kb := m[2]
			if !seen[kb] {
				seen[kb] = true
				installed = append(installed, PatchDetail{
					Name:   strings.TrimSpace(m[3]),
					KB:     kb,
					Status: "installed",
				})
			}
			continue
		}

		// Check tabular failed status
		if m := failedPattern.FindStringSubmatch(line); m != nil {
			kb := m[2]
			if !seen[kb] {
				seen[kb] = true
				failed = append(failed, PatchDetail{
					Name:   strings.TrimSpace(m[3]),
					KB:     kb,
					Status: "failed",
				})
			}
			continue
		}

		// Fallback: any line with a KB number that looks like a result
		if kbs := kbPattern.FindAllString(line, -1); len(kbs) > 0 {
			for _, kb := range kbs {
				if !seen[kb] && strings.Contains(strings.ToLower(line), "install") {
					seen[kb] = true
					installed = append(installed, PatchDetail{
						Name:   kb,
						KB:     kb,
						Status: "installed",
					})
				}
			}
		}
	}

	// Mark any "installing" entries that never got an "installed" confirmation as installed
	for i := range installed {
		if installed[i].Status == "installing" {
			installed[i].Status = "installed"
		}
	}

	return installed, failed
}

// parseDarwinPatchOutput parses macOS softwareupdate output.
func parseDarwinPatchOutput(output string) (installed []PatchDetail, failed []PatchDetail) {
	scanner := bufio.NewScanner(strings.NewReader(output))

	// softwareupdate output: "Installing <name>..." and "Done with <name>."
	installingPattern := regexp.MustCompile(`^Installing\s+(.+)\.\.\.$`)
	donePattern := regexp.MustCompile(`^Done with\s+(.+)\.$`)

	pending := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if m := installingPattern.FindStringSubmatch(line); m != nil {
			pending[m[1]] = true
			continue
		}

		if m := donePattern.FindStringSubmatch(line); m != nil {
			name := m[1]
			delete(pending, name)
			installed = append(installed, PatchDetail{
				Name:   name,
				Status: "installed",
			})
			continue
		}
	}

	// Anything still pending is considered failed
	for name := range pending {
		failed = append(failed, PatchDetail{
			Name:   name,
			Status: "failed",
		})
	}

	return installed, failed
}

// splitRPMName splits an RPM package string like "curl-7.88.1-1.el9.x86_64" into name and version.
func splitRPMName(pkg string) (name, version string) {
	// Remove architecture suffix if present
	for _, arch := range []string{".x86_64", ".noarch", ".i686", ".aarch64", ".armv7hl"} {
		pkg = strings.TrimSuffix(pkg, arch)
	}

	// RPM names: name-version-release, find the second-to-last dash
	parts := strings.Split(pkg, "-")
	if len(parts) >= 3 {
		name = strings.Join(parts[:len(parts)-2], "-")
		version = strings.Join(parts[len(parts)-2:], "-")
	} else if len(parts) == 2 {
		name = parts[0]
		version = parts[1]
	} else {
		name = pkg
	}
	return name, version
}

// HasKernelUpdate checks if any of the installed patches are kernel-related.
func HasKernelUpdate(output string) bool {
	lower := strings.ToLower(output)
	kernelIndicators := []string{
		"linux-image",
		"linux-headers",
		"kernel-core",
		"kernel-modules",
		"kernel-devel",
		"kernel-default",
		"linux-firmware",
		"setting up linux-image",
		"updated: kernel",
		"upgrading linux",
	}
	for _, indicator := range kernelIndicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
}

// SystemRequiresReboot checks if the system has flagged a pending reboot.
func SystemRequiresReboot() bool {
	switch runtime.GOOS {
	case "linux":
		return linuxRequiresReboot()
	case "windows":
		return windowsRequiresReboot()
	default:
		return false
	}
}

// linuxRequiresReboot checks common Linux reboot-required indicators.
func linuxRequiresReboot() bool {
	// Check /var/run/reboot-required (Debian/Ubuntu)
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		return true
	}

	// Check via needs-restarting command (RHEL/Fedora)
	cmd := exec.Command("needs-restarting", "-r")
	if err := cmd.Run(); err != nil {
		// Exit code 1 means reboot is needed
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return true
		}
	}

	return false
}

// windowsRequiresReboot checks Windows registry keys for pending reboot.
func windowsRequiresReboot() bool {
	script := `
$rebootRequired = $false
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
    $rebootRequired = $true
}
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
    $rebootRequired = $true
}
$pfro = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
if ($pfro) {
    $rebootRequired = $true
}
if ($rebootRequired) { exit 1 } else { exit 0 }
`
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return true
		}
	}

	return false
}
