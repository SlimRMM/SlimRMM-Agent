//go:build windows
// +build windows

// Package service provides Windows service management.
package service

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const (
	// defaultServiceTimeout is the default timeout for service operations.
	defaultServiceTimeout = 30 * time.Second
)

// WindowsManager manages Windows services.
type WindowsManager struct{}

// newWindowsManager creates a new Windows service manager.
func newWindowsManager() Manager {
	return &WindowsManager{}
}

// Install installs a Windows service.
func (m *WindowsManager) Install(name, displayName, description, execPath string) error {
	if m.IsInstalled(name) {
		return ErrServiceExists
	}

	// Use PowerShell New-Service for better error handling
	psScript := fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		try {
			New-Service -Name '%s' -BinaryPathName '%s' -DisplayName '%s' -StartupType Automatic -Description '%s' | Out-Null
			# Configure failure recovery using sc.exe (no PowerShell equivalent)
			& sc.exe failure '%s' reset= 86400 actions= restart/10000/restart/10000/restart/10000 | Out-Null
			Write-Output 'SUCCESS'
		} catch {
			Write-Error $_.Exception.Message
			exit 1
		}
	`, name, execPath, displayName, description, name)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("creating service: %s", strings.TrimSpace(string(output)))
	}

	return nil
}

// Uninstall removes a Windows service.
func (m *WindowsManager) Uninstall(name string) error {
	// Stop service first with force
	m.StopWithTimeout(name, defaultServiceTimeout)

	// Use PowerShell Remove-Service (Windows 10 1903+) with sc.exe fallback
	psScript := fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		try {
			if (Get-Command Remove-Service -ErrorAction SilentlyContinue) {
				Remove-Service -Name '%s' -ErrorAction Stop
			} else {
				$result = & sc.exe delete '%s' 2>&1
				if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1060) {
					throw "sc delete failed: $result"
				}
			}
			Write-Output 'SUCCESS'
		} catch {
			if ($_.Exception.Message -notmatch 'does not exist') {
				Write-Error $_.Exception.Message
				exit 1
			}
		}
	`, name, name)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	if output, err := cmd.CombinedOutput(); err != nil {
		outputStr := strings.TrimSpace(string(output))
		// Ignore "service does not exist" errors
		if !strings.Contains(strings.ToLower(outputStr), "does not exist") {
			return fmt.Errorf("deleting service: %s", outputStr)
		}
	}

	return nil
}

// Start starts a Windows service.
func (m *WindowsManager) Start(name string) error {
	return m.StartWithTimeout(name, defaultServiceTimeout)
}

// StartWithTimeout starts a Windows service with a specified timeout.
func (m *WindowsManager) StartWithTimeout(name string, timeout time.Duration) error {
	timeoutSec := int(timeout.Seconds())

	psScript := fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		try {
			$svc = Get-Service -Name '%s' -ErrorAction Stop
			if ($svc.Status -eq 'Running') {
				Write-Output 'ALREADY_RUNNING'
				exit 0
			}
			Start-Service -Name '%s' -ErrorAction Stop
			$svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(%d))
			Write-Output 'SUCCESS'
		} catch [System.ServiceProcess.TimeoutException] {
			Write-Error "Timeout waiting for service to start"
			exit 2
		} catch {
			Write-Error $_.Exception.Message
			exit 1
		}
	`, name, name, timeoutSec)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("starting service: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

// Stop stops a Windows service.
func (m *WindowsManager) Stop(name string) error {
	return m.StopWithTimeout(name, defaultServiceTimeout)
}

// StopWithTimeout stops a Windows service with a specified timeout and force option.
func (m *WindowsManager) StopWithTimeout(name string, timeout time.Duration) error {
	timeoutSec := int(timeout.Seconds())

	// Use PowerShell Stop-Service with -Force flag for reliable stopping
	// -Force stops dependent services as well and handles more edge cases
	psScript := fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		try {
			$svc = Get-Service -Name '%s' -ErrorAction SilentlyContinue
			if (-not $svc) {
				Write-Output 'NOT_FOUND'
				exit 0
			}
			if ($svc.Status -eq 'Stopped') {
				Write-Output 'ALREADY_STOPPED'
				exit 0
			}
			Stop-Service -Name '%s' -Force -NoWait -ErrorAction Stop
			$svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(%d))
			Write-Output 'SUCCESS'
		} catch [System.ServiceProcess.TimeoutException] {
			# Force kill the process if timeout occurs
			try {
				$proc = Get-CimInstance Win32_Service -Filter "Name='%s'" | Select-Object -ExpandProperty ProcessId
				if ($proc -and $proc -ne 0) {
					Stop-Process -Id $proc -Force -ErrorAction SilentlyContinue
					Start-Sleep -Seconds 2
				}
			} catch {}
			Write-Output 'FORCE_KILLED'
		} catch {
			if ($_.Exception.Message -notmatch 'not started|already stopped') {
				Write-Error $_.Exception.Message
				exit 1
			}
			Write-Output 'ALREADY_STOPPED'
		}
	`, name, name, timeoutSec, name)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	if output, err := cmd.CombinedOutput(); err != nil {
		outputStr := strings.TrimSpace(string(output))
		// Ignore "not started" errors
		if !strings.Contains(strings.ToLower(outputStr), "not started") &&
			!strings.Contains(strings.ToLower(outputStr), "already stopped") {
			return fmt.Errorf("stopping service: %s", outputStr)
		}
	}
	return nil
}

// Status returns the status of a Windows service.
func (m *WindowsManager) Status(name string) (ServiceStatus, error) {
	psScript := fmt.Sprintf(`
		$svc = Get-Service -Name '%s' -ErrorAction SilentlyContinue
		if (-not $svc) {
			Write-Output 'NOT_FOUND'
			exit 1
		}
		Write-Output $svc.Status
	`, name)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		return StatusUnknown, ErrServiceNotFound
	}

	outputStr := strings.TrimSpace(string(output))
	switch outputStr {
	case "Running":
		return StatusRunning, nil
	case "Stopped":
		return StatusStopped, nil
	case "NOT_FOUND":
		return StatusUnknown, ErrServiceNotFound
	default:
		return StatusUnknown, nil
	}
}

// IsInstalled checks if a Windows service is installed.
func (m *WindowsManager) IsInstalled(name string) bool {
	psScript := fmt.Sprintf(`
		$svc = Get-Service -Name '%s' -ErrorAction SilentlyContinue
		if ($svc) { exit 0 } else { exit 1 }
	`, name)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	err := cmd.Run()
	return err == nil
}

// Restart restarts a Windows service.
// For self-restart (slimrmm-agent), uses PowerShell to schedule restart externally
// since stopping the service terminates the process before Start can be called.
func (m *WindowsManager) Restart(name string) error {
	// Check if this is a self-restart
	isSelf := strings.EqualFold(name, "SlimRMMAgent") || strings.EqualFold(name, "slimrmm-agent")

	if isSelf {
		// Use PowerShell to stop and start in background
		// This allows the current process to respond before being killed
		psScript := fmt.Sprintf(`
			Start-Job -ScriptBlock {
				Stop-Service -Name '%s' -Force -ErrorAction SilentlyContinue
				Start-Sleep -Seconds 2
				Start-Service -Name '%s' -ErrorAction SilentlyContinue
			} | Out-Null
		`, name, name)
		cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("scheduling restart: %w", err)
		}
		// Don't wait for the command - let it run in background
		return nil
	}

	return m.RestartWithTimeout(name, defaultServiceTimeout)
}

// RestartWithTimeout restarts a Windows service with a specified timeout.
func (m *WindowsManager) RestartWithTimeout(name string, timeout time.Duration) error {
	timeoutSec := int(timeout.Seconds())

	// Use Restart-Service with -Force for atomic restart operation
	psScript := fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		try {
			$svc = Get-Service -Name '%s' -ErrorAction Stop
			Restart-Service -Name '%s' -Force -ErrorAction Stop
			$svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(%d))
			Write-Output 'SUCCESS'
		} catch [System.ServiceProcess.TimeoutException] {
			Write-Error "Timeout waiting for service to restart"
			exit 2
		} catch {
			Write-Error $_.Exception.Message
			exit 1
		}
	`, name, name, timeoutSec)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("restarting service: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

// List lists all Windows services.
func (m *WindowsManager) List() ([]ServiceInfo, error) {
	// Use PowerShell to get service information
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Get-Service | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json`)
	output, err := cmd.Output()
	if err != nil {
		// Fall back to sc query
		return m.listWithSc()
	}

	// Parse JSON output
	var psServices []struct {
		Name        string `json:"Name"`
		DisplayName string `json:"DisplayName"`
		Status      int    `json:"Status"`
		StartType   int    `json:"StartType"`
	}

	if err := json.Unmarshal(output, &psServices); err != nil {
		return m.listWithSc()
	}

	var services []ServiceInfo
	for _, s := range psServices {
		status := StatusStopped
		if s.Status == 4 { // Running
			status = StatusRunning
		}

		startType := "manual"
		enabled := false
		switch s.StartType {
		case 2: // Automatic
			startType = "auto"
			enabled = true
		case 3: // Manual
			startType = "manual"
		case 4: // Disabled
			startType = "disabled"
		}

		services = append(services, ServiceInfo{
			Name:        s.Name,
			DisplayName: s.DisplayName,
			Status:      status,
			Enabled:     enabled,
			StartType:   startType,
		})
	}

	return services, nil
}

// SetStartType changes the startup type of a Windows service.
func (m *WindowsManager) SetStartType(name string, startType string) error {
	var scStartType string
	switch startType {
	case "auto", "automatic":
		scStartType = "auto"
	case "manual":
		scStartType = "demand"
	case "disabled":
		scStartType = "disabled"
	default:
		return fmt.Errorf("invalid start type: %s (valid: auto, manual, disabled)", startType)
	}

	cmd := exec.Command("sc", "config", name, "start=", scStartType)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("changing startup type: %s", string(output))
	}
	return nil
}

// listWithSc lists services using sc.exe as fallback.
func (m *WindowsManager) listWithSc() ([]ServiceInfo, error) {
	cmd := exec.Command("sc", "query", "state=", "all")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("listing services: %w", err)
	}

	var services []ServiceInfo
	lines := strings.Split(string(output), "\n")

	var currentService *ServiceInfo
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "SERVICE_NAME:") {
			if currentService != nil {
				services = append(services, *currentService)
			}
			name := strings.TrimPrefix(line, "SERVICE_NAME:")
			name = strings.TrimSpace(name)
			currentService = &ServiceInfo{
				Name:      name,
				Status:    StatusUnknown,
				StartType: "manual",
			}
		} else if currentService != nil {
			if strings.HasPrefix(line, "DISPLAY_NAME:") {
				currentService.DisplayName = strings.TrimSpace(strings.TrimPrefix(line, "DISPLAY_NAME:"))
			} else if strings.Contains(line, "STATE") {
				if strings.Contains(line, "RUNNING") {
					currentService.Status = StatusRunning
				} else if strings.Contains(line, "STOPPED") {
					currentService.Status = StatusStopped
				}
			}
		}
	}

	if currentService != nil {
		services = append(services, *currentService)
	}

	return services, nil
}
