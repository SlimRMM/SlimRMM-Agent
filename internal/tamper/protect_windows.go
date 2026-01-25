//go:build windows

package tamper

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// protectFilePlatform sets the read-only and system attributes on a file.
func (p *Protection) protectFilePlatform(path string) error {
	// Get current attributes
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	attrs, err := syscall.GetFileAttributes(pathPtr)
	if err != nil {
		return err
	}

	// Add read-only and system attributes
	newAttrs := attrs | syscall.FILE_ATTRIBUTE_READONLY | syscall.FILE_ATTRIBUTE_SYSTEM

	return syscall.SetFileAttributes(pathPtr, newAttrs)
}

// unprotectFilePlatform removes read-only and system attributes from a file.
func (p *Protection) unprotectFilePlatform(path string) error {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	attrs, err := syscall.GetFileAttributes(pathPtr)
	if err != nil {
		return err
	}

	// Remove read-only and system attributes
	newAttrs := attrs &^ (syscall.FILE_ATTRIBUTE_READONLY | syscall.FILE_ATTRIBUTE_SYSTEM)

	return syscall.SetFileAttributes(pathPtr, newAttrs)
}

// InstallWatchdog installs a Windows service that monitors the agent.
func InstallWatchdog() error {
	// Create a PowerShell-based watchdog script with proper error handling
	// and timeout-aware service restart capabilities
	watchdogScript := `
# SlimRMM Agent Watchdog Script
# Monitors the agent service and restarts it if stopped

$ErrorActionPreference = 'SilentlyContinue'
$ServiceName = 'SlimRMMAgent'
$CheckInterval = 10

while ($true) {
    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -ne 'Running') {
                # Log restart attempt
                $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                $logPath = Join-Path $env:ProgramData 'SlimRMM\log\watchdog.log'
                $logDir = Split-Path $logPath -Parent
                if (-not (Test-Path $logDir)) {
                    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
                }
                Add-Content -Path $logPath -Value "[$timestamp] Service status: $($svc.Status), attempting restart"

                # Attempt to start the service with timeout
                Start-Service -Name $ServiceName -ErrorAction Stop
                $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))

                $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                Add-Content -Path $logPath -Value "[$timestamp] Service restarted successfully"
            }
        }
    } catch {
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $logPath = Join-Path $env:ProgramData 'SlimRMM\log\watchdog.log'
        Add-Content -Path $logPath -Value "[$timestamp] Error: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds $CheckInterval
}
`

	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}

	slimrmmDir := filepath.Join(programFiles, "SlimRMM")
	watchdogPath := filepath.Join(slimrmmDir, "watchdog.ps1")

	// Write watchdog script with restrictive permissions
	if err := os.WriteFile(watchdogPath, []byte(watchdogScript), 0600); err != nil {
		return fmt.Errorf("failed to write watchdog script: %w", err)
	}

	// Use PowerShell to create the watchdog service
	psCreateService := fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		try {
			# Remove existing service if present
			$existing = Get-Service -Name 'slimrmm-watchdog' -ErrorAction SilentlyContinue
			if ($existing) {
				Stop-Service -Name 'slimrmm-watchdog' -Force -ErrorAction SilentlyContinue
				if (Get-Command Remove-Service -ErrorAction SilentlyContinue) {
					Remove-Service -Name 'slimrmm-watchdog'
				} else {
					& sc.exe delete 'slimrmm-watchdog' | Out-Null
				}
				Start-Sleep -Seconds 2
			}

			# Create new service with PowerShell execution
			$binPath = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%s"'
			New-Service -Name 'slimrmm-watchdog' -BinaryPathName $binPath -DisplayName 'SlimRMM Agent Watchdog' -StartupType Automatic -Description 'Monitors and restarts SlimRMM Agent if stopped unexpectedly' | Out-Null

			# Configure failure recovery
			& sc.exe failure 'slimrmm-watchdog' reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

			# Start the service
			Start-Service -Name 'slimrmm-watchdog' -ErrorAction Stop
			Write-Output 'SUCCESS'
		} catch {
			Write-Error $_.Exception.Message
			exit 1
		}
	`, watchdogPath)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCreateService)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create watchdog service: %s", string(output))
	}

	return nil
}

// UninstallWatchdog removes the watchdog service.
func UninstallWatchdog() error {
	// Use PowerShell for reliable service removal with force stop
	psUninstall := `
		$ErrorActionPreference = 'SilentlyContinue'
		$svc = Get-Service -Name 'slimrmm-watchdog' -ErrorAction SilentlyContinue
		if ($svc) {
			Stop-Service -Name 'slimrmm-watchdog' -Force -ErrorAction SilentlyContinue
			$svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) 2>$null
			if (Get-Command Remove-Service -ErrorAction SilentlyContinue) {
				Remove-Service -Name 'slimrmm-watchdog' -ErrorAction SilentlyContinue
			} else {
				& sc.exe delete 'slimrmm-watchdog' 2>&1 | Out-Null
			}
		}
		Write-Output 'SUCCESS'
	`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psUninstall)
	cmd.Run() // Ignore errors - service may not exist

	// Remove watchdog script (both .bat legacy and .ps1 new)
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	slimrmmDir := filepath.Join(programFiles, "SlimRMM")
	os.Remove(filepath.Join(slimrmmDir, "watchdog.bat")) // Remove legacy batch file
	os.Remove(filepath.Join(slimrmmDir, "watchdog.ps1")) // Remove PowerShell script
	return nil
}

// ProtectServiceFile configures Windows service recovery options.
func ProtectServiceFile() error {
	// Use PowerShell to configure service with better error handling
	// sc.exe is still used for failure recovery and SDDL as there are no
	// native PowerShell equivalents for these operations
	psProtect := `
		$ErrorActionPreference = 'Stop'
		try {
			# Configure service to restart on failure
			$result = & sc.exe failure 'SlimRMMAgent' reset= 86400 actions= restart/5000/restart/10000/restart/30000 2>&1
			if ($LASTEXITCODE -ne 0) {
				throw "Failed to set service recovery: $result"
			}

			# Deny INTERACTIVE group stop permission
			# This prevents regular users from stopping the service
			# SDDL breakdown:
			# SY = LocalSystem (full control)
			# BA = Builtin Administrators (full control)
			# IU = Interactive Users (limited - no stop/pause)
			# SU = Service Users (limited - no stop/pause)
			$sddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'
			$result = & sc.exe sdset 'SlimRMMAgent' $sddl 2>&1
			if ($LASTEXITCODE -ne 0) {
				throw "Failed to set service permissions: $result"
			}

			Write-Output 'SUCCESS'
		} catch {
			Write-Error $_.Exception.Message
			exit 1
		}
	`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psProtect)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to protect service: %s", string(output))
	}
	return nil
}

// UnprotectServiceFile restores default service permissions.
func UnprotectServiceFile() error {
	// Reset to default service permissions using PowerShell wrapper
	psUnprotect := `
		$ErrorActionPreference = 'SilentlyContinue'
		# Reset to default service permissions (adds WD = World/Everyone read permission)
		$sddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RP;;;WD)'
		& sc.exe sdset 'SlimRMMAgent' $sddl 2>&1 | Out-Null
		Write-Output 'SUCCESS'
	`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psUnprotect)
	cmd.Run() // Ignore errors
	return nil
}

// ProtectRegistryKeys protects the agent's registry keys.
func ProtectRegistryKeys() error {
	// Use icacls to set restrictive permissions on the agent's registry
	// This is a placeholder - actual implementation would use Windows Registry API
	return nil
}
