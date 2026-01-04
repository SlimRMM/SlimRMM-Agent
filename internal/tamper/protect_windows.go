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
	// Create a simple watchdog script
	watchdogScript := `
@echo off
:loop
sc query slimrmm-agent | find "RUNNING" > nul
if errorlevel 1 (
    net start slimrmm-agent
)
timeout /t 10 /nobreak > nul
goto loop
`

	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}

	slimrmmDir := filepath.Join(programFiles, "SlimRMM")
	watchdogPath := filepath.Join(slimrmmDir, "watchdog.bat")

	// Write watchdog script
	if err := os.WriteFile(watchdogPath, []byte(watchdogScript), 0644); err != nil {
		return fmt.Errorf("failed to write watchdog script: %w", err)
	}

	// Create Windows service for watchdog using sc
	cmd := exec.Command("sc", "create", "slimrmm-watchdog",
		"binPath=", fmt.Sprintf(`cmd.exe /c "%s"`, watchdogPath),
		"start=", "auto",
		"DisplayName=", "SlimRMM Agent Watchdog",
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create watchdog service: %w", err)
	}

	// Set service description
	_ = exec.Command("sc", "description", "slimrmm-watchdog",
		"Monitors and restarts SlimRMM Agent if stopped unexpectedly").Run()

	// Set recovery options - restart on failure
	_ = exec.Command("sc", "failure", "slimrmm-watchdog",
		"reset=", "86400", "actions=", "restart/5000/restart/10000/restart/30000").Run()

	// Start the service
	return exec.Command("sc", "start", "slimrmm-watchdog").Run()
}

// UninstallWatchdog removes the watchdog service.
func UninstallWatchdog() error {
	// Stop and delete watchdog service
	_ = exec.Command("sc", "stop", "slimrmm-watchdog").Run()
	_ = exec.Command("sc", "delete", "slimrmm-watchdog").Run()

	// Remove watchdog script
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	watchdogPath := filepath.Join(programFiles, "SlimRMM", "watchdog.bat")
	return os.Remove(watchdogPath)
}

// ProtectServiceFile configures Windows service recovery options.
func ProtectServiceFile() error {
	// Configure service to restart on failure
	cmd := exec.Command("sc", "failure", "slimrmm-agent",
		"reset=", "86400",
		"actions=", "restart/5000/restart/10000/restart/30000",
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set service recovery: %w", err)
	}

	// Deny INTERACTIVE group stop permission
	// This prevents regular users from stopping the service
	cmd = exec.Command("sc", "sdset", "slimrmm-agent",
		"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)")
	return cmd.Run()
}

// UnprotectServiceFile restores default service permissions.
func UnprotectServiceFile() error {
	// Reset to default service permissions
	return exec.Command("sc", "sdset", "slimrmm-agent",
		"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RP;;;WD)").Run()
}

// ProtectRegistryKeys protects the agent's registry keys.
func ProtectRegistryKeys() error {
	// Use icacls to set restrictive permissions on the agent's registry
	// This is a placeholder - actual implementation would use Windows Registry API
	return nil
}
