// Package actions provides system control actions.
package actions

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
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
		preCmd.Run()
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

	// Schedule reboot if requested
	if reboot && err == nil {
		go func() {
			time.Sleep(60 * time.Second)
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
