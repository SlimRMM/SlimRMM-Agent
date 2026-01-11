//go:build windows
// +build windows

package winget

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Windows-specific paths for winget detection.
// We specifically check system-level paths to ensure winget is available
// when running as a SYSTEM service.
var wingetSearchPaths = []string{
	// Primary location for App Installer
	`C:\Program Files\WindowsApps`,
	// Alternative locations
	`C:\Windows\System32`,
}

// findWingetBinary searches for winget.exe in system-level locations.
func findWingetBinary() string {
	// First, try to find winget in WindowsApps (system-level App Installer)
	windowsAppsPath := `C:\Program Files\WindowsApps`
	if entries, err := os.ReadDir(windowsAppsPath); err == nil {
		for _, entry := range entries {
			if entry.IsDir() && strings.HasPrefix(entry.Name(), "Microsoft.DesktopAppInstaller_") {
				wingetPath := filepath.Join(windowsAppsPath, entry.Name(), "winget.exe")
				if _, err := os.Stat(wingetPath); err == nil {
					// Verify it's actually executable by SYSTEM
					if canExecuteAsSystem(wingetPath) {
						return wingetPath
					}
				}
			}
		}
	}

	// Try direct path lookup (might work if PATH is set correctly for SYSTEM)
	if path, err := exec.LookPath("winget.exe"); err == nil {
		if canExecuteAsSystem(path) {
			return path
		}
	}

	// Check common alternative locations
	alternativePaths := []string{
		`C:\Windows\System32\winget.exe`,
		filepath.Join(os.Getenv("LOCALAPPDATA"), `Microsoft\WindowsApps\winget.exe`),
	}

	for _, path := range alternativePaths {
		if _, err := os.Stat(path); err == nil {
			if canExecuteAsSystem(path) {
				return path
			}
		}
	}

	return ""
}

// canExecuteAsSystem verifies that the binary can be executed in SYSTEM context.
func canExecuteAsSystem(path string) bool {
	// Try to execute winget --version to verify it works
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, "--version")
	// Set environment to avoid user-specific issues
	cmd.Env = append(os.Environ(),
		"WINGET_DISABLE_INTERACTIVITY=1",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		slog.Debug("winget execution check failed",
			"path", path,
			"error", err,
			"output", string(output),
		)
		return false
	}
	return true
}

// getWingetVersion extracts the version from winget --version output.
func getWingetVersion(binaryPath string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath, "--version")
	cmd.Env = append(os.Environ(), "WINGET_DISABLE_INTERACTIVITY=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		slog.Debug("failed to get winget version", "error", err)
		return ""
	}

	// Parse version from output like "v1.7.11261" or "Windows Package Manager v1.7.11261"
	outputStr := strings.TrimSpace(string(output))
	versionRegex := regexp.MustCompile(`v?(\d+\.\d+\.\d+)`)
	matches := versionRegex.FindStringSubmatch(outputStr)
	if len(matches) >= 2 {
		return matches[1]
	}

	// Return raw output if parsing fails
	return outputStr
}

// isSystemLevelInstall checks if winget is installed system-wide.
func isSystemLevelInstall(binaryPath string) bool {
	// If the path is in Program Files\WindowsApps, it's system-level
	return strings.Contains(strings.ToLower(binaryPath), `program files\windowsapps`)
}

// install performs winget installation on Windows.
func (c *Client) install(ctx context.Context) error {
	slog.Info("starting winget installation")

	// Try multiple installation methods in order of preference
	installMethods := []struct {
		name string
		fn   func(context.Context) error
	}{
		{"MSIX Bundle from GitHub", installFromGitHub},
		{"Add-AppxProvisionedPackage", installViaProvisioning},
		{"Add-AppxPackage", installViaAppxPackage},
	}

	var lastErr error
	for _, method := range installMethods {
		slog.Info("attempting winget installation", "method", method.name)
		if err := method.fn(ctx); err != nil {
			slog.Warn("installation method failed",
				"method", method.name,
				"error", err,
			)
			lastErr = err
			continue
		}
		slog.Info("winget installation succeeded", "method", method.name)
		return nil
	}

	return fmt.Errorf("all installation methods failed: %w", lastErr)
}

// installFromGitHub downloads and installs winget from GitHub releases.
func installFromGitHub(ctx context.Context) error {
	// PowerShell script to download and install winget with dependencies
	script := `
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

Write-Host "Downloading winget and dependencies..."

# Create temp directory
$tempDir = Join-Path $env:TEMP "winget-install"
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

try {
    # Get latest release info from GitHub
    $releaseUrl = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
    $headers = @{ "User-Agent" = "SlimRMM-Agent" }

    try {
        $release = Invoke-RestMethod -Uri $releaseUrl -Headers $headers -TimeoutSec 30
    } catch {
        Write-Host "Failed to get latest release, using known version"
        $release = @{
            assets = @(
                @{ name = "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"; browser_download_url = "https://github.com/microsoft/winget-cli/releases/download/v1.7.11261/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" }
                @{ name = "DesktopAppInstaller_License1.xml"; browser_download_url = "https://github.com/microsoft/winget-cli/releases/download/v1.7.11261/DesktopAppInstaller_License1.xml" }
            )
        }
    }

    # Download MSIX bundle
    $msixAsset = $release.assets | Where-Object { $_.name -like "*.msixbundle" } | Select-Object -First 1
    if (-not $msixAsset) {
        throw "MSIX bundle not found in release"
    }

    $msixPath = Join-Path $tempDir "winget.msixbundle"
    Write-Host "Downloading MSIX bundle from $($msixAsset.browser_download_url)..."
    Invoke-WebRequest -Uri $msixAsset.browser_download_url -OutFile $msixPath -UseBasicParsing -TimeoutSec 120

    # Download license file
    $licenseAsset = $release.assets | Where-Object { $_.name -like "*License*.xml" } | Select-Object -First 1
    $licensePath = $null
    if ($licenseAsset) {
        $licensePath = Join-Path $tempDir "license.xml"
        Write-Host "Downloading license file..."
        Invoke-WebRequest -Uri $licenseAsset.browser_download_url -OutFile $licensePath -UseBasicParsing -TimeoutSec 30
    }

    # Download VCLibs dependency (required for winget)
    Write-Host "Downloading VCLibs dependency..."
    $vclibsUrl = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
    $vclibsPath = Join-Path $tempDir "vclibs.appx"
    try {
        Invoke-WebRequest -Uri $vclibsUrl -OutFile $vclibsPath -UseBasicParsing -TimeoutSec 60
        Write-Host "Installing VCLibs..."
        Add-AppxPackage -Path $vclibsPath -ErrorAction SilentlyContinue
    } catch {
        Write-Host "VCLibs download/install failed (may already be installed): $_"
    }

    # Download UI.Xaml dependency
    Write-Host "Downloading UI.Xaml dependency..."
    $xamlUrl = "https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.8.6"
    $xamlPath = Join-Path $tempDir "uixaml.zip"
    try {
        Invoke-WebRequest -Uri $xamlUrl -OutFile $xamlPath -UseBasicParsing -TimeoutSec 60
        Expand-Archive -Path $xamlPath -DestinationPath (Join-Path $tempDir "uixaml") -Force
        $xamlAppx = Get-ChildItem -Path (Join-Path $tempDir "uixaml\tools\AppX\x64\Release") -Filter "*.appx" | Select-Object -First 1
        if ($xamlAppx) {
            Write-Host "Installing UI.Xaml..."
            Add-AppxPackage -Path $xamlAppx.FullName -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Host "UI.Xaml download/install failed (may already be installed): $_"
    }

    # Install winget using Add-AppxProvisionedPackage for system-wide installation
    Write-Host "Installing winget system-wide..."
    if ($licensePath -and (Test-Path $licensePath)) {
        Add-AppxProvisionedPackage -Online -PackagePath $msixPath -LicensePath $licensePath -ErrorAction Stop
    } else {
        # Try without license
        Add-AppxProvisionedPackage -Online -PackagePath $msixPath -SkipLicense -ErrorAction Stop
    }

    Write-Host "winget installation completed successfully"

} finally {
    # Cleanup
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
`

	return runPowerShellScript(ctx, script, 5*time.Minute)
}

// installViaProvisioning uses Add-AppxProvisionedPackage with existing packages.
func installViaProvisioning(ctx context.Context) error {
	script := `
$ErrorActionPreference = 'Stop'

# Check if App Installer is already provisioned but not available
$provisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq "Microsoft.DesktopAppInstaller" }
if ($provisioned) {
    Write-Host "App Installer is provisioned, attempting to reinstall..."
    # Remove and re-add
    Remove-AppxProvisionedPackage -Online -PackageName $provisioned.PackageName -ErrorAction SilentlyContinue
}

# Try to get from Windows Store cache
$storeAppPath = Get-ChildItem -Path "C:\Program Files\WindowsApps" -Filter "Microsoft.DesktopAppInstaller_*" -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending | Select-Object -First 1

if ($storeAppPath) {
    $appxManifest = Join-Path $storeAppPath.FullName "AppxManifest.xml"
    if (Test-Path $appxManifest) {
        Write-Host "Re-registering existing App Installer package..."
        Add-AppxPackage -Register $appxManifest -DisableDevelopmentMode -ForceApplicationShutdown
        exit 0
    }
}

throw "No existing App Installer package found for provisioning"
`
	return runPowerShellScript(ctx, script, 2*time.Minute)
}

// installViaAppxPackage uses Add-AppxPackage for user-level installation.
func installViaAppxPackage(ctx context.Context) error {
	script := `
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Download and install using Add-AppxPackage
$tempDir = Join-Path $env:TEMP "winget-install-appx"
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

try {
    $msixUrl = "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
    $msixPath = Join-Path $tempDir "winget.msixbundle"

    Write-Host "Downloading winget MSIX bundle..."
    Invoke-WebRequest -Uri $msixUrl -OutFile $msixPath -UseBasicParsing -TimeoutSec 120

    Write-Host "Installing winget..."
    Add-AppxPackage -Path $msixPath -ForceApplicationShutdown

    Write-Host "Installation completed"
} finally {
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}
`
	return runPowerShellScript(ctx, script, 3*time.Minute)
}

// runPowerShellScript executes a PowerShell script with timeout.
func runPowerShellScript(ctx context.Context, script string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", script,
	)

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	slog.Debug("PowerShell script output", "output", outputStr)

	if err != nil {
		return fmt.Errorf("PowerShell execution failed: %w (output: %s)", err, outputStr)
	}

	return nil
}
