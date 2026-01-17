#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Vollständige Deinstallation des SlimRMM Agent von Windows.

.DESCRIPTION
    Dieses Script entfernt den SlimRMM Agent komplett:
    - Stoppt und entfernt den Agent-Service
    - Stoppt und entfernt den Watchdog-Service
    - Beendet den Helper-Prozess
    - Löscht alle Programmdateien
    - Löscht Konfigurationsdaten
    - Entfernt Scheduled Tasks
    - Bereinigt Registry-Einträge

.PARAMETER Force
    Überspringt die Bestätigungsabfrage.

.EXAMPLE
    .\uninstall-agent.ps1
    .\uninstall-agent.ps1 -Force
#>

param(
    [switch]$Force
)

$ErrorActionPreference = 'SilentlyContinue'

# Konfiguration
$ServiceName = "SlimRMMAgent"
$WatchdogServiceName = "slimrmm-watchdog"
$HelperProcessName = "slimrmm-helper"
$AgentProcessName = "slimrmm-agent"
$InstallDir = "C:\Program Files\SlimRMM"
$DataDir = "C:\ProgramData\SlimRMM"
$ScheduledTaskPrefix = "SlimRMM"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  SlimRMM Agent - Vollständige Deinstallation" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Bestätigung
if (-not $Force) {
    Write-Host "WARNUNG: Dies entfernt den SlimRMM Agent vollständig!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Folgendes wird gelöscht:" -ForegroundColor Yellow
    Write-Host "  - Service: $ServiceName" -ForegroundColor Gray
    Write-Host "  - Watchdog: $WatchdogServiceName" -ForegroundColor Gray
    Write-Host "  - Verzeichnis: $InstallDir" -ForegroundColor Gray
    Write-Host "  - Daten: $DataDir" -ForegroundColor Gray
    Write-Host ""
    $confirm = Read-Host "Fortfahren? (j/n)"
    if ($confirm -notmatch '^[jJyY]') {
        Write-Host "Abgebrochen." -ForegroundColor Yellow
        exit 0
    }
}

Write-Host ""

# 1. Watchdog-Service stoppen und entfernen
Write-Host "[1/8] Watchdog-Service stoppen..." -ForegroundColor Cyan
$watchdog = Get-Service -Name $WatchdogServiceName -ErrorAction SilentlyContinue
if ($watchdog) {
    Stop-Service -Name $WatchdogServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    # Service entfernen
    Write-Host "      Watchdog-Service entfernen..." -ForegroundColor Gray
    if (Get-Command Remove-Service -ErrorAction SilentlyContinue) {
        Remove-Service -Name $WatchdogServiceName -ErrorAction SilentlyContinue
    } else {
        & sc.exe delete $WatchdogServiceName 2>&1 | Out-Null
    }
    Write-Host "      OK" -ForegroundColor Green
} else {
    Write-Host "      Nicht vorhanden" -ForegroundColor Gray
}

# 2. Agent-Service stoppen und entfernen
Write-Host "[2/8] Agent-Service stoppen..." -ForegroundColor Cyan
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    # Falls Service noch läuft, Prozess beenden
    $agentProc = Get-Process -Name $AgentProcessName -ErrorAction SilentlyContinue
    if ($agentProc) {
        Write-Host "      Prozess beenden..." -ForegroundColor Gray
        Stop-Process -Name $AgentProcessName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }

    # Service entfernen
    Write-Host "      Agent-Service entfernen..." -ForegroundColor Gray
    if (Get-Command Remove-Service -ErrorAction SilentlyContinue) {
        Remove-Service -Name $ServiceName -ErrorAction SilentlyContinue
    } else {
        & sc.exe delete $ServiceName 2>&1 | Out-Null
    }
    Write-Host "      OK" -ForegroundColor Green
} else {
    Write-Host "      Nicht vorhanden" -ForegroundColor Gray
}

# 3. Helper-Prozess beenden
Write-Host "[3/8] Helper-Prozess beenden..." -ForegroundColor Cyan
$helper = Get-Process -Name $HelperProcessName -ErrorAction SilentlyContinue
if ($helper) {
    Stop-Process -Name $HelperProcessName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Write-Host "      OK" -ForegroundColor Green
} else {
    Write-Host "      Nicht vorhanden" -ForegroundColor Gray
}

# 4. Verbleibende Prozesse hart beenden
Write-Host "[4/8] Verbleibende Prozesse beenden..." -ForegroundColor Cyan
& taskkill /F /IM "$AgentProcessName.exe" 2>&1 | Out-Null
& taskkill /F /IM "$HelperProcessName.exe" 2>&1 | Out-Null
Start-Sleep -Seconds 1
Write-Host "      OK" -ForegroundColor Green

# 5. Scheduled Tasks entfernen
Write-Host "[5/8] Scheduled Tasks entfernen..." -ForegroundColor Cyan
$tasks = Get-ScheduledTask -TaskName "$ScheduledTaskPrefix*" -ErrorAction SilentlyContinue
if ($tasks) {
    foreach ($task in $tasks) {
        Write-Host "      Entferne: $($task.TaskName)" -ForegroundColor Gray
        Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    Write-Host "      OK" -ForegroundColor Green
} else {
    Write-Host "      Keine gefunden" -ForegroundColor Gray
}

# Auch winget-related Tasks entfernen
$wingetTasks = Get-ScheduledTask -TaskName "*winget*slimrmm*" -ErrorAction SilentlyContinue
if ($wingetTasks) {
    foreach ($task in $wingetTasks) {
        Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}

# 6. Installationsverzeichnis löschen
Write-Host "[6/8] Installationsverzeichnis löschen..." -ForegroundColor Cyan
if (Test-Path $InstallDir) {
    # Dateien entsperren
    Get-ChildItem -Path $InstallDir -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $_.Attributes = 'Normal'
        } catch {}
    }

    # Verzeichnis löschen
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue

    if (Test-Path $InstallDir) {
        Write-Host "      Konnte nicht vollständig gelöscht werden (wird nach Neustart entfernt)" -ForegroundColor Yellow
        # Für Neustart markieren
        cmd /c "rd /s /q `"$InstallDir`"" 2>&1 | Out-Null
    } else {
        Write-Host "      OK" -ForegroundColor Green
    }
} else {
    Write-Host "      Nicht vorhanden" -ForegroundColor Gray
}

# 7. Datenverzeichnis löschen
Write-Host "[7/8] Datenverzeichnis löschen..." -ForegroundColor Cyan
if (Test-Path $DataDir) {
    Remove-Item -Path $DataDir -Recurse -Force -ErrorAction SilentlyContinue

    if (Test-Path $DataDir) {
        Write-Host "      Konnte nicht vollständig gelöscht werden" -ForegroundColor Yellow
    } else {
        Write-Host "      OK" -ForegroundColor Green
    }
} else {
    Write-Host "      Nicht vorhanden" -ForegroundColor Gray
}

# 8. Registry bereinigen
Write-Host "[8/8] Registry bereinigen..." -ForegroundColor Cyan
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
    Write-Host "      Keine Einträge gefunden" -ForegroundColor Gray
}

# Zusammenfassung
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Deinstallation abgeschlossen" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Prüfen ob Neustart empfohlen
$needsReboot = $false
if (Test-Path $InstallDir) {
    $needsReboot = $true
}

# Services prüfen
$remainingServices = @()
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    $remainingServices += $ServiceName
}
if (Get-Service -Name $WatchdogServiceName -ErrorAction SilentlyContinue) {
    $remainingServices += $WatchdogServiceName
}

if ($remainingServices.Count -gt 0) {
    $needsReboot = $true
    Write-Host "HINWEIS: Folgende Services werden nach Neustart entfernt:" -ForegroundColor Yellow
    foreach ($svc in $remainingServices) {
        Write-Host "  - $svc" -ForegroundColor Gray
    }
    Write-Host ""
}

if ($needsReboot) {
    Write-Host "Ein Neustart wird empfohlen, um die Deinstallation abzuschließen." -ForegroundColor Yellow
    Write-Host ""
    if (-not $Force) {
        $reboot = Read-Host "Jetzt neustarten? (j/n)"
        if ($reboot -match '^[jJyY]') {
            Write-Host "Neustart in 5 Sekunden..." -ForegroundColor Yellow
            Start-Sleep -Seconds 5
            Restart-Computer -Force
        }
    }
} else {
    Write-Host "SlimRMM Agent wurde vollständig entfernt." -ForegroundColor Green
}
