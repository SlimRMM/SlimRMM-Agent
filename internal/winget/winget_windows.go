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
	slog.Info("searching for winget binary")

	// FIRST: Try PowerShell to find winget path - works best for SYSTEM account
	slog.Info("trying PowerShell to find winget")
	if path := findWingetViaPowerShell(); path != "" {
		slog.Info("found winget via PowerShell", "path", path)
		return path
	}

	// Second: Try direct path lookup (might work if PATH is set correctly for SYSTEM)
	slog.Info("trying PATH lookup for winget.exe")
	if path, err := exec.LookPath("winget.exe"); err == nil {
		slog.Info("found winget in PATH", "path", path)
		if canExecuteAsSystem(path) {
			slog.Info("found working winget via PATH", "path", path)
			return path
		}
		slog.Info("winget found in PATH but execution check failed", "path", path)
	} else {
		slog.Info("winget.exe not found in PATH", "error", err)
	}

	// Third: Try to find winget in WindowsApps using PowerShell (SYSTEM can't always read this directly)
	slog.Info("searching WindowsApps via PowerShell")
	if path := findWingetInWindowsAppsViaPowerShell(); path != "" {
		slog.Info("found winget in WindowsApps via PowerShell", "path", path)
		return path
	}

	// Fourth: Try direct directory scan of WindowsApps
	windowsAppsPath := `C:\Program Files\WindowsApps`
	slog.Info("checking WindowsApps directory directly", "path", windowsAppsPath)
	if entries, err := os.ReadDir(windowsAppsPath); err == nil {
		var foundPaths []string
		for _, entry := range entries {
			if entry.IsDir() && strings.HasPrefix(entry.Name(), "Microsoft.DesktopAppInstaller_") {
				wingetPath := filepath.Join(windowsAppsPath, entry.Name(), "winget.exe")
				if _, err := os.Stat(wingetPath); err == nil {
					foundPaths = append(foundPaths, wingetPath)
				}
			}
		}
		slog.Info("found DesktopAppInstaller directories", "count", len(foundPaths), "paths", foundPaths)
		// Sort to get the latest version (higher version numbers come later alphabetically)
		for i := len(foundPaths) - 1; i >= 0; i-- {
			wingetPath := foundPaths[i]
			slog.Info("testing winget path", "path", wingetPath)
			if canExecuteAsSystem(wingetPath) {
				slog.Info("found working winget", "path", wingetPath)
				return wingetPath
			}
			// Even if execution check fails, return the path if the file exists
			// The execution check might fail due to permission issues but the binary might still work
			slog.Info("execution check failed, but returning path anyway", "path", wingetPath)
			return wingetPath
		}
	} else {
		slog.Info("failed to read WindowsApps directory", "error", err)
	}

	// Fifth: Check common alternative locations
	alternativePaths := []string{
		`C:\Windows\System32\winget.exe`,
		filepath.Join(os.Getenv("LOCALAPPDATA"), `Microsoft\WindowsApps\winget.exe`),
	}
	slog.Info("checking alternative paths", "paths", alternativePaths)

	for _, pathPattern := range alternativePaths {
		if _, err := os.Stat(pathPattern); err == nil {
			slog.Info("testing alternative path", "path", pathPattern)
			if canExecuteAsSystem(pathPattern) {
				slog.Info("found working winget at alternative path", "path", pathPattern)
				return pathPattern
			}
		}
	}

	slog.Warn("winget not found in any location")
	return ""
}

// findWingetInWindowsAppsViaPowerShell searches for winget.exe using PowerShell
// This is more reliable for SYSTEM account which may not have direct read access
func findWingetInWindowsAppsViaPowerShell() string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	script := `
$ErrorActionPreference = 'SilentlyContinue'
$windowsApps = "C:\Program Files\WindowsApps"
$dirs = Get-ChildItem -Path $windowsApps -Directory -Filter "Microsoft.DesktopAppInstaller_*" | Sort-Object Name -Descending
foreach ($dir in $dirs) {
    $wingetPath = Join-Path $dir.FullName "winget.exe"
    if (Test-Path $wingetPath) {
        Write-Output $wingetPath
        exit 0
    }
}
`
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", script,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		slog.Info("PowerShell WindowsApps search failed", "error", err)
		return ""
	}

	path := strings.TrimSpace(string(output))
	if path != "" && strings.HasSuffix(strings.ToLower(path), "winget.exe") {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// findWingetViaPowerShell uses PowerShell to locate winget.exe
func findWingetViaPowerShell() string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// PowerShell command to find winget.exe - Get-Command is most reliable
	// as it works regardless of how winget was installed (provisioned, per-user, system)
	script := `
$ErrorActionPreference = 'SilentlyContinue'

# Method 1: Get-Command is the most reliable - works for all installation types
$cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
if ($cmd -and $cmd.Source) {
    Write-Output $cmd.Source
    exit 0
}

# Method 2: Try direct execution to get path from where.exe
$whereResult = where.exe winget.exe 2>$null | Select-Object -First 1
if ($whereResult -and (Test-Path $whereResult)) {
    Write-Output $whereResult
    exit 0
}

# Method 3: Search in WindowsApps directory directly
$windowsApps = Get-ChildItem "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*" -Directory -ErrorAction SilentlyContinue |
    Sort-Object { [version]($_.Name -replace 'Microsoft.DesktopAppInstaller_(\d+\.\d+\.\d+\.\d+)_.*','$1') } -Descending -ErrorAction SilentlyContinue
foreach ($app in $windowsApps) {
    $path = Join-Path $app.FullName "winget.exe"
    if (Test-Path $path) {
        Write-Output $path
        exit 0
    }
}

# Method 4: Try Get-AppxPackage with AllUsers (may work on some systems)
$pkg = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -AllUsers -ErrorAction SilentlyContinue | Select-Object -First 1
if ($pkg -and $pkg.InstallLocation) {
    $path = Join-Path $pkg.InstallLocation "winget.exe"
    if (Test-Path $path) {
        Write-Output $path
        exit 0
    }
}

# Method 5: Try without AllUsers flag
$pkg = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue | Select-Object -First 1
if ($pkg -and $pkg.InstallLocation) {
    $path = Join-Path $pkg.InstallLocation "winget.exe"
    if (Test-Path $path) {
        Write-Output $path
        exit 0
    }
}
`
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", script,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		slog.Debug("PowerShell winget search failed", "error", err, "output", string(output))
		return ""
	}

	path := strings.TrimSpace(string(output))
	slog.Debug("PowerShell returned path", "path", path)

	if path != "" && strings.HasSuffix(strings.ToLower(path), "winget.exe") {
		// Verify it actually works
		if canExecuteAsSystem(path) {
			return path
		}
		slog.Debug("found winget path but execution check failed", "path", path)
	}

	return ""
}

// canExecuteAsSystem verifies that the binary can be executed in SYSTEM context.
func canExecuteAsSystem(path string) bool {
	// Try to execute winget --version to verify it works
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, "--version")
	// Set environment to avoid user-specific issues
	cmd.Env = append(os.Environ(),
		"WINGET_DISABLE_INTERACTIVITY=1",
	)

	slog.Debug("executing winget --version", "path", path)
	output, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	if err != nil {
		slog.Debug("winget execution check failed",
			"path", path,
			"error", err,
			"output", outputStr,
			"ctx_error", ctx.Err(),
		)
		return false
	}

	slog.Debug("winget execution succeeded",
		"path", path,
		"output", outputStr,
	)
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

Write-Host "Preparing for system-wide winget installation..."

# Step 1: Remove ALL existing winget installations (per-user and provisioned)
# This ensures only our new system-wide installation will exist
Write-Host "Removing existing winget installations..."

try {
    # Remove provisioned package first (if exists)
    $provisioned = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq "Microsoft.DesktopAppInstaller" }
    if ($provisioned) {
        Write-Host "Removing provisioned package: $($provisioned.PackageName)"
        Remove-AppxProvisionedPackage -Online -PackageName $provisioned.PackageName -ErrorAction SilentlyContinue
    }

    # Remove all per-user installations using -AllUsers flag
    # This requires admin rights which SYSTEM has
    $packages = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -AllUsers -ErrorAction SilentlyContinue
    foreach ($pkg in $packages) {
        Write-Host "Removing package: $($pkg.PackageFullName)"
        try {
            Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction SilentlyContinue
        } catch {
            Write-Host "Could not remove $($pkg.PackageFullName): $_"
        }
    }

    Write-Host "Existing installations removed"
} catch {
    Write-Host "Warning during cleanup: $_ (continuing with installation)"
}

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

// ensureSystemOnly removes per-user winget installations.
// This ensures only the system-wide installation exists, preventing
// the need to update winget in multiple places.
func (c *Client) ensureSystemOnly(ctx context.Context, logger *slog.Logger) error {
	logger.Info("checking for per-user winget installations to remove")

	script := `
$ErrorActionPreference = 'SilentlyContinue'
$removed = 0

# Get all winget installations across all users
$allPackages = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -AllUsers -ErrorAction SilentlyContinue

# Get the provisioned package (system-wide)
$provisioned = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -eq "Microsoft.DesktopAppInstaller" }

foreach ($pkg in $allPackages) {
    # Check if this is a per-user installation (not the provisioned one)
    # Per-user packages have different PackageUserInformation
    $userInfo = $pkg.PackageUserInformation
    if ($userInfo) {
        foreach ($user in $userInfo) {
            # Skip S-1-5-18 (SYSTEM) as that's our provisioned package
            if ($user.UserSecurityId -ne 'S-1-5-18') {
                Write-Host "Found per-user installation for SID: $($user.UserSecurityId)"
                try {
                    Remove-AppxPackage -Package $pkg.PackageFullName -User $user.UserSecurityId -ErrorAction Stop
                    Write-Host "Removed per-user installation: $($pkg.PackageFullName)"
                    $removed++
                } catch {
                    Write-Host "Could not remove for user $($user.UserSecurityId): $_"
                }
            }
        }
    }
}

if ($removed -gt 0) {
    Write-Host "Removed $removed per-user installation(s)"
} else {
    Write-Host "No per-user installations found"
}
`

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", script,
	)

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	logger.Debug("ensureSystemOnly output", "output", outputStr)

	if err != nil {
		// Don't fail on errors - per-user removal is best-effort
		logger.Warn("could not remove all per-user installations",
			"error", err,
			"output", outputStr,
		)
	}

	return nil
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
