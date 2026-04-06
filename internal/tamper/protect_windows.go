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

// InstallWatchdog installs a scheduled task that monitors the agent service.
// Uses Task Scheduler instead of a Windows service because PowerShell scripts
// cannot implement the Service Control Manager (SCM) interface required by
// Windows services, causing "service cannot start" errors in production.
func InstallWatchdog() error {
	// Create the watchdog PowerShell script
	scriptPath := filepath.Join(os.Getenv("ProgramFiles"), "SlimRMM", "watchdog.ps1")
	script := `
$serviceName = "SlimRMMAgent"
$logFile = "C:\ProgramData\SlimRMM\log\watchdog.log"

$status = (Get-Service -Name $serviceName -ErrorAction SilentlyContinue).Status
if ($status -ne "Running") {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "$timestamp - Service not running (status: $status), restarting..."
    Start-Service -Name $serviceName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
    $newStatus = (Get-Service -Name $serviceName -ErrorAction SilentlyContinue).Status
    Add-Content -Path $logFile -Value "$timestamp - Restart result: $newStatus"
}
`
	if err := os.WriteFile(scriptPath, []byte(script), 0644); err != nil {
		return fmt.Errorf("failed to write watchdog script: %w", err)
	}

	// Create scheduled task instead of service
	taskName := "SlimRMM-Watchdog"

	// Remove existing task
	exec.Command("schtasks", "/Delete", "/TN", taskName, "/F").Run()

	// Create task that runs every 1 minute
	cmd := exec.Command("schtasks", "/Create",
		"/TN", taskName,
		"/TR", fmt.Sprintf(`powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%s"`, scriptPath),
		"/SC", "MINUTE",
		"/MO", "1",
		"/RU", "SYSTEM",
		"/RL", "HIGHEST",
		"/F",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create scheduled task: %w (output: %s)", err, string(output))
	}

	// Protect the scheduled task from non-admin modification
	// Hide the task and set ACL so only SYSTEM and Administrators can modify it
	psProtectTask := fmt.Sprintf(`
		$ErrorActionPreference = 'SilentlyContinue'
		# Set restrictive ACL on the scheduled task XML definition
		$taskPath = Join-Path $env:SystemRoot 'System32\Tasks\%s'
		if (Test-Path $taskPath) {
			$acl = Get-Acl $taskPath
			$acl.SetAccessRuleProtection($true, $false)
			$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators', 'FullControl', 'Allow')
			$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule('NT AUTHORITY\SYSTEM', 'FullControl', 'Allow')
			$acl.AddAccessRule($adminRule)
			$acl.AddAccessRule($systemRule)
			Set-Acl -Path $taskPath -AclObject $acl
		}

		# Also protect the watchdog script file with restrictive ACL
		$scriptPath = '%s'
		if (Test-Path $scriptPath) {
			$acl = Get-Acl $scriptPath
			$acl.SetAccessRuleProtection($true, $false)
			$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators', 'FullControl', 'Allow')
			$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule('NT AUTHORITY\SYSTEM', 'FullControl', 'Allow')
			$acl.AddAccessRule($adminRule)
			$acl.AddAccessRule($systemRule)
			Set-Acl -Path $scriptPath -AclObject $acl
		}
	`, taskName, scriptPath)

	aclCmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psProtectTask)
	aclCmd.Run() // Best-effort ACL protection

	return nil
}

// UninstallWatchdog removes the watchdog scheduled task.
func UninstallWatchdog() error {
	// Remove scheduled task
	exec.Command("schtasks", "/Delete", "/TN", "SlimRMM-Watchdog", "/F").Run()

	// Also remove old service if exists (backward compat)
	exec.Command("sc", "stop", "slimrmm-watchdog").Run()
	exec.Command("sc", "delete", "slimrmm-watchdog").Run()

	// Remove script
	scriptPath := filepath.Join(os.Getenv("ProgramFiles"), "SlimRMM", "watchdog.ps1")
	os.Remove(scriptPath)

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
