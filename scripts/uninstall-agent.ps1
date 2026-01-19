#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Complete uninstallation of the SlimRMM Agent from Windows.

.DESCRIPTION
    This script completely removes the SlimRMM Agent:
    - Stops and removes the Agent service
    - Stops and removes the Watchdog service
    - Terminates the Helper process
    - Deletes all program files
    - Deletes configuration data
    - Removes Scheduled Tasks
    - Cleans up Registry entries

.PARAMETER Force
    Skips the confirmation prompt.

.EXAMPLE
    .\uninstall-agent.ps1
    .\uninstall-agent.ps1 -Force
#>

param(
    [switch]$Force
)

$ErrorActionPreference = 'SilentlyContinue'

# Configuration
$ServiceName = "SlimRMMAgent"
$WatchdogServiceName = "slimrmm-watchdog"
$HelperProcessName = "slimrmm-helper"
$AgentProcessName = "slimrmm-agent"
$InstallDir = "C:\Program Files\SlimRMM"
$DataDir = "C:\ProgramData\SlimRMM"
$ScheduledTaskPrefix = "SlimRMM"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  SlimRMM Agent - Complete Uninstallation" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Confirmation
if (-not $Force) {
    Write-Host "WARNING: This will completely remove the SlimRMM Agent!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "The following will be deleted:" -ForegroundColor Yellow
    Write-Host "  - Service: $ServiceName" -ForegroundColor Gray
    Write-Host "  - Watchdog: $WatchdogServiceName" -ForegroundColor Gray
    Write-Host "  - Directory: $InstallDir" -ForegroundColor Gray
    Write-Host "  - Data: $DataDir" -ForegroundColor Gray
    Write-Host ""
    $confirm = Read-Host "Continue? (y/n)"
    if ($confirm -notmatch '^[yY]') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        exit 0
    }
}

Write-Host ""

# 1. Stop and remove Watchdog service
Write-Host "[1/8] Stopping Watchdog service..." -ForegroundColor Cyan
$watchdog = Get-Service -Name $WatchdogServiceName -ErrorAction SilentlyContinue
if ($watchdog) {
    Stop-Service -Name $WatchdogServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    # Remove service
    Write-Host "      Removing Watchdog service..." -ForegroundColor Gray
    if (Get-Command Remove-Service -ErrorAction SilentlyContinue) {
        Remove-Service -Name $WatchdogServiceName -ErrorAction SilentlyContinue
    } else {
        & sc.exe delete $WatchdogServiceName 2>&1 | Out-Null
    }
    Write-Host "      OK" -ForegroundColor Green
} else {
    Write-Host "      Not present" -ForegroundColor Gray
}

# 2. Stop and remove Agent service
Write-Host "[2/8] Stopping Agent service..." -ForegroundColor Cyan
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    # If service is still running, terminate process
    $agentProc = Get-Process -Name $AgentProcessName -ErrorAction SilentlyContinue
    if ($agentProc) {
        Write-Host "      Terminating process..." -ForegroundColor Gray
        Stop-Process -Name $AgentProcessName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }

    # Remove service
    Write-Host "      Removing Agent service..." -ForegroundColor Gray
    if (Get-Command Remove-Service -ErrorAction SilentlyContinue) {
        Remove-Service -Name $ServiceName -ErrorAction SilentlyContinue
    } else {
        & sc.exe delete $ServiceName 2>&1 | Out-Null
    }
    Write-Host "      OK" -ForegroundColor Green
} else {
    Write-Host "      Not present" -ForegroundColor Gray
}

# 3. Terminate Helper process
Write-Host "[3/8] Terminating Helper process..." -ForegroundColor Cyan
$helper = Get-Process -Name $HelperProcessName -ErrorAction SilentlyContinue
if ($helper) {
    Stop-Process -Name $HelperProcessName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Write-Host "      OK" -ForegroundColor Green
} else {
    Write-Host "      Not present" -ForegroundColor Gray
}

# 4. Force terminate remaining processes
Write-Host "[4/8] Terminating remaining processes..." -ForegroundColor Cyan
& taskkill /F /IM "$AgentProcessName.exe" 2>&1 | Out-Null
& taskkill /F /IM "$HelperProcessName.exe" 2>&1 | Out-Null
Start-Sleep -Seconds 1
Write-Host "      OK" -ForegroundColor Green

# 5. Remove Scheduled Tasks
Write-Host "[5/8] Removing Scheduled Tasks..." -ForegroundColor Cyan
$tasks = Get-ScheduledTask -TaskName "$ScheduledTaskPrefix*" -ErrorAction SilentlyContinue
if ($tasks) {
    foreach ($task in $tasks) {
        Write-Host "      Removing: $($task.TaskName)" -ForegroundColor Gray
        Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    Write-Host "      OK" -ForegroundColor Green
} else {
    Write-Host "      None found" -ForegroundColor Gray
}

# Also remove winget-related tasks
$wingetTasks = Get-ScheduledTask -TaskName "*winget*slimrmm*" -ErrorAction SilentlyContinue
if ($wingetTasks) {
    foreach ($task in $wingetTasks) {
        Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}

# 6. Delete installation directory
Write-Host "[6/8] Deleting installation directory..." -ForegroundColor Cyan
if (Test-Path $InstallDir) {
    # Unlock files
    Get-ChildItem -Path $InstallDir -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $_.Attributes = 'Normal'
        } catch {}
    }

    # Delete directory
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue

    if (Test-Path $InstallDir) {
        Write-Host "      Could not fully delete (will be removed after reboot)" -ForegroundColor Yellow
        # Mark for deletion on reboot
        cmd /c "rd /s /q `"$InstallDir`"" 2>&1 | Out-Null
    } else {
        Write-Host "      OK" -ForegroundColor Green
    }
} else {
    Write-Host "      Not present" -ForegroundColor Gray
}

# 7. Delete data directory
Write-Host "[7/8] Deleting data directory..." -ForegroundColor Cyan
if (Test-Path $DataDir) {
    Remove-Item -Path $DataDir -Recurse -Force -ErrorAction SilentlyContinue

    if (Test-Path $DataDir) {
        Write-Host "      Could not fully delete" -ForegroundColor Yellow
    } else {
        Write-Host "      OK" -ForegroundColor Green
    }
} else {
    Write-Host "      Not present" -ForegroundColor Gray
}

# 8. Clean up Registry
Write-Host "[8/8] Cleaning up Registry..." -ForegroundColor Cyan
$regPaths = @(
    "HKLM:\SOFTWARE\SlimRMM",
    "HKLM:\SOFTWARE\WOW6432Node\SlimRMM",
    "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName",
    "HKLM:\SYSTEM\CurrentControlSet\Services\$WatchdogServiceName"
)

$cleaned = $false
foreach ($regPath in $regPaths) {
    if (Test-Path $regPath) {
        Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
        $cleaned = $true
    }
}

if ($cleaned) {
    Write-Host "      OK" -ForegroundColor Green
} else {
    Write-Host "      No entries found" -ForegroundColor Gray
}

# Summary
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Uninstallation complete" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check if reboot is recommended
$needsReboot = $false
if (Test-Path $InstallDir) {
    $needsReboot = $true
}

# Check services
$remainingServices = @()
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    $remainingServices += $ServiceName
}
if (Get-Service -Name $WatchdogServiceName -ErrorAction SilentlyContinue) {
    $remainingServices += $WatchdogServiceName
}

if ($remainingServices.Count -gt 0) {
    $needsReboot = $true
    Write-Host "NOTE: The following services will be removed after reboot:" -ForegroundColor Yellow
    foreach ($svc in $remainingServices) {
        Write-Host "  - $svc" -ForegroundColor Gray
    }
    Write-Host ""
}

if ($needsReboot) {
    Write-Host "A reboot is recommended to complete the uninstallation." -ForegroundColor Yellow
    Write-Host ""
    if (-not $Force) {
        $reboot = Read-Host "Reboot now? (y/n)"
        if ($reboot -match '^[yY]') {
            Write-Host "Rebooting in 5 seconds..." -ForegroundColor Yellow
            Start-Sleep -Seconds 5
            Restart-Computer -Force
        }
    }
} else {
    Write-Host "SlimRMM Agent has been completely removed." -ForegroundColor Green
}
