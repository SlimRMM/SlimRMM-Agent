// Package software provides software installation and uninstallation services.
//go:build darwin

package software

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/homebrew"
	"github.com/slimrmm/slimrmm-agent/internal/services/models"
)

// PKGUninstaller implements PlatformUninstaller for PKG packages on macOS.
type PKGUninstaller struct {
	logger *slog.Logger
}

// NewPKGUninstaller creates a new PKG uninstaller.
func NewPKGUninstaller(logger *slog.Logger) *PKGUninstaller {
	return &PKGUninstaller{logger: logger}
}

// CanHandle returns true if this uninstaller can handle PKG uninstallations.
func (u *PKGUninstaller) CanHandle(installationType models.InstallationType) bool {
	return installationType == models.InstallationTypePKG
}

// IsAvailable returns true (pkgutil is always available on macOS).
func (u *PKGUninstaller) IsAvailable() bool {
	return true
}

// Uninstall performs a PKG uninstallation by forgetting the receipt and removing files.
func (u *PKGUninstaller) Uninstall(ctx context.Context, req *models.UninstallRequest) (*models.UninstallResult, error) {
	startedAt := time.Now()

	pkgID := req.PackageID
	if pkgID == "" {
		return &models.UninstallResult{
			UninstallationID: req.UninstallationID,
			Status:           models.UninstallStatusFailed,
			Error:            "package_id (pkg receipt ID) is required for PKG uninstallation",
			StartedAt:        startedAt,
			CompletedAt:      time.Now(),
		}, nil
	}

	u.logger.Info("uninstalling PKG package",
		"uninstallation_id", req.UninstallationID,
		"package_id", pkgID,
	)

	var output strings.Builder
	exitCode := 0

	// Get list of files installed by this package
	listCmd := exec.CommandContext(ctx, "pkgutil", "--files", pkgID)
	filesOutput, listErr := listCmd.CombinedOutput()
	output.WriteString(fmt.Sprintf("pkgutil --files %s:\n%s\n", pkgID, string(filesOutput)))

	if listErr == nil && len(filesOutput) > 0 {
		// Remove installed files (reverse order for directories)
		files := strings.Split(strings.TrimSpace(string(filesOutput)), "\n")
		for i := len(files) - 1; i >= 0; i-- {
			file := files[i]
			if file == "" {
				continue
			}
			fullPath := "/" + file
			if u.isPathSafe(fullPath) {
				if err := os.RemoveAll(fullPath); err != nil {
					u.logger.Debug("failed to remove file", "path", fullPath, "error", err)
				}
			}
		}
	}

	// Forget the package receipt
	forgetCmd := exec.CommandContext(ctx, "sudo", "pkgutil", "--forget", pkgID)
	forgetOutput, forgetErr := forgetCmd.CombinedOutput()
	output.WriteString(fmt.Sprintf("\npkgutil --forget %s:\n%s\n", pkgID, string(forgetOutput)))

	if forgetErr != nil {
		if exitErr, ok := forgetErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	status := models.UninstallStatusCompleted
	var errMsg string
	if exitCode != 0 {
		status = models.UninstallStatusFailed
		errMsg = fmt.Sprintf("pkgutil --forget failed with exit code %d", exitCode)
	}

	return &models.UninstallResult{
		UninstallationID: req.UninstallationID,
		Status:           status,
		ExitCode:         exitCode,
		Output:           output.String(),
		Error:            errMsg,
		StartedAt:        startedAt,
		CompletedAt:      time.Now(),
	}, nil
}

// isPathSafe checks if a path is safe to delete on macOS.
func (u *PKGUninstaller) isPathSafe(path string) bool {
	protectedPaths := []string{
		"/System",
		"/Library",
		"/usr",
		"/bin",
		"/sbin",
		"/private/var",
		"/cores",
	}

	normalizedPath := filepath.Clean(path)
	for _, protected := range protectedPaths {
		if strings.HasPrefix(normalizedPath, protected) {
			return false
		}
	}

	return true
}

// Cleanup performs post-uninstall cleanup for PKG packages.
func (u *PKGUninstaller) Cleanup(ctx context.Context, req *models.UninstallRequest) (*models.CleanupResults, error) {
	results := &models.CleanupResults{
		PathsRemoved: []string{},
		PathsFailed:  []string{},
	}

	// Clean up Application Support and Preferences
	appName := req.PackageName
	if appName == "" {
		return results, nil
	}

	homeDir, _ := os.UserHomeDir()
	cleanupPaths := []string{
		filepath.Join(homeDir, "Library", "Application Support", appName),
		filepath.Join(homeDir, "Library", "Preferences", appName),
		filepath.Join(homeDir, "Library", "Caches", appName),
	}

	for _, path := range cleanupPaths {
		if _, err := os.Stat(path); err == nil {
			if err := os.RemoveAll(path); err != nil {
				results.PathsFailed = append(results.PathsFailed, path)
			} else {
				results.PathsRemoved = append(results.PathsRemoved, path)
			}
		}
	}

	return results, nil
}

// CaskUninstaller implements PlatformUninstaller for Homebrew Cask on macOS.
type CaskUninstaller struct {
	logger *slog.Logger
}

// NewCaskUninstaller creates a new Cask uninstaller.
func NewCaskUninstaller(logger *slog.Logger) *CaskUninstaller {
	return &CaskUninstaller{logger: logger}
}

// CanHandle returns true if this uninstaller can handle Cask uninstallations.
func (u *CaskUninstaller) CanHandle(installationType models.InstallationType) bool {
	return installationType == models.InstallationTypeCask
}

// IsAvailable returns true (cask uninstaller is always available on macOS).
// We use the Homebrew API for metadata and manually remove apps, so brew CLI is not required.
func (u *CaskUninstaller) IsAvailable() bool {
	return true
}

// Uninstall performs a manual cask uninstallation by removing the app bundle.
// This method uses the Homebrew API to get cask metadata and manually removes
// the application, avoiding the need for brew to be installed.
// It includes fallback logic for cases where the cask no longer exists in Homebrew.
func (u *CaskUninstaller) Uninstall(ctx context.Context, req *models.UninstallRequest) (*models.UninstallResult, error) {
	startedAt := time.Now()

	caskName := req.CaskName
	if caskName == "" {
		caskName = req.PackageID
	}

	u.logger.Info("uninstalling cask (manual removal)",
		"uninstallation_id", req.UninstallationID,
		"cask_name", caskName,
		"package_name", req.PackageName,
	)

	var output strings.Builder
	var appName string
	var apiAvailable bool

	// Try to fetch cask info from Homebrew API
	if caskName != "" && homebrew.IsValidCaskName(caskName) {
		caskInfo, err := homebrew.FetchCaskInfo(ctx, caskName)
		if err == nil {
			appName = caskInfo.GetAppName()
			apiAvailable = true
			output.WriteString(fmt.Sprintf("Cask info from API: %s\n", caskName))
		} else {
			output.WriteString(fmt.Sprintf("API lookup failed (using fallback): %v\n", err))
		}
	}

	// Fallback 1: Use PackageName if it looks like an app name
	if appName == "" && req.PackageName != "" {
		if strings.HasSuffix(strings.ToLower(req.PackageName), ".app") {
			appName = req.PackageName
			output.WriteString(fmt.Sprintf("Using package_name as app name: %s\n", appName))
		} else {
			// Try adding .app extension
			possibleApp := req.PackageName + ".app"
			if _, err := os.Stat(filepath.Join("/Applications", possibleApp)); err == nil {
				appName = possibleApp
				output.WriteString(fmt.Sprintf("Found app from package_name: %s\n", appName))
			}
		}
	}

	// Fallback 2: Try to derive app name from cask name
	if appName == "" && caskName != "" {
		derivedApp := u.deriveAppNameFromCask(caskName)
		if derivedApp != "" {
			appName = derivedApp
			output.WriteString(fmt.Sprintf("Derived app name from cask: %s\n", appName))
		}
	}

	// Fallback 3: Search in /Applications for similar names
	if appName == "" {
		searchTerm := caskName
		if searchTerm == "" {
			searchTerm = req.PackageName
		}
		if searchTerm != "" {
			foundApp := u.findAppInApplications(searchTerm)
			if foundApp != "" {
				appName = foundApp
				output.WriteString(fmt.Sprintf("Found app by search: %s\n", appName))
			}
		}
	}

	// If we still don't have an app name, fail
	if appName == "" {
		return &models.UninstallResult{
			UninstallationID: req.UninstallationID,
			Status:           models.UninstallStatusFailed,
			Error:            "could not determine app name - please provide package_name with the exact app bundle name (e.g., 'Firefox.app')",
			Output:           output.String(),
			StartedAt:        startedAt,
			CompletedAt:      time.Now(),
		}, nil
	}

	output.WriteString(fmt.Sprintf("Target app: %s\n", appName))

	// Construct the app path
	appPath := filepath.Join("/Applications", appName)

	// Check if the app exists
	if _, err := os.Stat(appPath); os.IsNotExist(err) {
		// Try user's Applications folder
		homeDir, _ := os.UserHomeDir()
		userAppPath := filepath.Join(homeDir, "Applications", appName)
		if _, err := os.Stat(userAppPath); err == nil {
			appPath = userAppPath
			output.WriteString(fmt.Sprintf("Found in user Applications: %s\n", appPath))
		} else {
			output.WriteString(fmt.Sprintf("App not found at %s or %s\n", appPath, userAppPath))
			return &models.UninstallResult{
				UninstallationID: req.UninstallationID,
				Status:           models.UninstallStatusFailed,
				Error:            fmt.Sprintf("app not found: %s", appName),
				Output:           output.String(),
				StartedAt:        startedAt,
				CompletedAt:      time.Now(),
			}, nil
		}
	}

	// Quit the app if it's running
	appNameWithoutExt := strings.TrimSuffix(appName, ".app")
	output.WriteString(fmt.Sprintf("Quitting app: %s\n", appNameWithoutExt))
	quitOps := homebrew.QuitAllInstances(ctx, appNameWithoutExt)
	for _, op := range quitOps {
		output.WriteString(fmt.Sprintf("  %s: %s (success: %v)\n", op.Operation, op.Target, op.Success))
	}

	// Remove the app bundle
	output.WriteString(fmt.Sprintf("Removing: %s\n", appPath))
	if err := os.RemoveAll(appPath); err != nil {
		return &models.UninstallResult{
			UninstallationID: req.UninstallationID,
			Status:           models.UninstallStatusFailed,
			ExitCode:         1,
			Error:            fmt.Sprintf("failed to remove app: %v", err),
			Output:           output.String(),
			StartedAt:        startedAt,
			CompletedAt:      time.Now(),
		}, nil
	}

	output.WriteString("App removed successfully\n")
	if !apiAvailable {
		output.WriteString("Note: Cleanup may be incomplete (cask not found in Homebrew API)\n")
	}

	return &models.UninstallResult{
		UninstallationID: req.UninstallationID,
		Status:           models.UninstallStatusCompleted,
		ExitCode:         0,
		Output:           output.String(),
		StartedAt:        startedAt,
		CompletedAt:      time.Now(),
	}, nil
}

// deriveAppNameFromCask tries to derive the app name from a cask name.
// e.g., "firefox" -> "Firefox.app", "visual-studio-code" -> "Visual Studio Code.app"
func (u *CaskUninstaller) deriveAppNameFromCask(caskName string) string {
	// Common cask name to app name mappings
	knownMappings := map[string]string{
		"firefox":            "Firefox.app",
		"google-chrome":      "Google Chrome.app",
		"visual-studio-code": "Visual Studio Code.app",
		"slack":              "Slack.app",
		"spotify":            "Spotify.app",
		"zoom":               "zoom.us.app",
		"vlc":                "VLC.app",
		"iterm2":             "iTerm.app",
		"docker":             "Docker.app",
		"discord":            "Discord.app",
		"notion":             "Notion.app",
		"1password":          "1Password.app",
		"rectangle":          "Rectangle.app",
		"alfred":             "Alfred 5.app",
		"raycast":            "Raycast.app",
		"obsidian":           "Obsidian.app",
		"telegram":           "Telegram.app",
		"whatsapp":           "WhatsApp.app",
		"signal":             "Signal.app",
	}

	if appName, ok := knownMappings[caskName]; ok {
		if _, err := os.Stat(filepath.Join("/Applications", appName)); err == nil {
			return appName
		}
	}

	// Try converting cask name to title case
	// "firefox" -> "Firefox.app"
	// "visual-studio-code" -> "Visual Studio Code.app"
	parts := strings.Split(caskName, "-")
	for i, part := range parts {
		if len(part) > 0 {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}
	titleCase := strings.Join(parts, " ") + ".app"
	if _, err := os.Stat(filepath.Join("/Applications", titleCase)); err == nil {
		return titleCase
	}

	// Try without spaces
	noSpaces := strings.Join(parts, "") + ".app"
	if _, err := os.Stat(filepath.Join("/Applications", noSpaces)); err == nil {
		return noSpaces
	}

	return ""
}

// findAppInApplications searches for an app matching the search term in /Applications.
func (u *CaskUninstaller) findAppInApplications(searchTerm string) string {
	searchLower := strings.ToLower(searchTerm)
	searchLower = strings.ReplaceAll(searchLower, "-", " ")
	searchLower = strings.ReplaceAll(searchLower, "_", " ")

	entries, err := os.ReadDir("/Applications")
	if err != nil {
		return ""
	}

	var bestMatch string
	var bestScore int

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".app") {
			continue
		}

		entryLower := strings.ToLower(entry.Name())
		entryLower = strings.TrimSuffix(entryLower, ".app")

		// Exact match (ignoring case and extension)
		if entryLower == searchLower {
			return entry.Name()
		}

		// Contains match
		score := 0
		if strings.Contains(entryLower, searchLower) {
			score = 100 - len(entryLower) // Prefer shorter names
		} else if strings.Contains(searchLower, entryLower) {
			score = 50 - len(entryLower)
		}

		if score > bestScore {
			bestScore = score
			bestMatch = entry.Name()
		}
	}

	// Only return if we have a reasonable match
	if bestScore > 0 {
		return bestMatch
	}

	return ""
}

// Cleanup performs post-uninstall cleanup for Cask packages.
// It tries to use the zap stanza from Homebrew API, with fallback to generic cleanup.
func (u *CaskUninstaller) Cleanup(ctx context.Context, req *models.UninstallRequest) (*models.CleanupResults, error) {
	results := &models.CleanupResults{
		PathsRemoved: []string{},
		PathsFailed:  []string{},
	}

	caskName := req.CaskName
	if caskName == "" {
		caskName = req.PackageID
	}

	// Try to use zap stanza from API if available
	if caskName != "" && homebrew.IsValidCaskName(caskName) {
		caskInfo, err := homebrew.FetchCaskInfoFull(caskName)
		if err == nil {
			zapResult, zapErr := homebrew.ExecuteZapStanza(ctx, caskInfo)
			if zapErr != nil {
				u.logger.Warn("zap stanza execution had errors", "cask_name", caskName, "error", zapErr)
			}
			if zapResult != nil {
				results.PathsRemoved = append(results.PathsRemoved, zapResult.PathsRemoved...)
				for _, op := range zapResult.Operations {
					if !op.Success && op.Error != "" {
						results.PathsFailed = append(results.PathsFailed, op.Target)
					}
				}
				return results, nil
			}
		} else {
			u.logger.Warn("could not fetch cask info for cleanup, using generic cleanup", "cask_name", caskName, "error", err)
		}
	}

	// Fallback: Generic cleanup based on app name
	appName := req.PackageName
	if appName == "" && caskName != "" {
		// Derive app name from cask name for cleanup paths
		parts := strings.Split(caskName, "-")
		for i, part := range parts {
			if len(part) > 0 {
				parts[i] = strings.ToUpper(part[:1]) + part[1:]
			}
		}
		appName = strings.Join(parts, " ")
	}

	if appName == "" {
		return results, nil
	}

	// Remove .app extension if present for cleanup path generation
	appName = strings.TrimSuffix(appName, ".app")

	u.logger.Info("performing generic cleanup", "app_name", appName)

	// Get bundle ID if we can find the app's Info.plist
	var bundleID string
	appPath := filepath.Join("/Applications", appName+".app")
	if bid, err := homebrew.GetAppBundleID(appPath); err == nil {
		bundleID = bid
	}

	// Generic cleanup paths
	homeDir, _ := os.UserHomeDir()
	cleanupPaths := []string{
		filepath.Join(homeDir, "Library", "Application Support", appName),
		filepath.Join(homeDir, "Library", "Caches", appName),
		filepath.Join(homeDir, "Library", "Preferences", appName+".plist"),
		filepath.Join(homeDir, "Library", "Saved Application State", appName+".savedState"),
		filepath.Join(homeDir, "Library", "Logs", appName),
	}

	// Add bundle ID based paths if available
	if bundleID != "" {
		cleanupPaths = append(cleanupPaths,
			filepath.Join(homeDir, "Library", "Application Support", bundleID),
			filepath.Join(homeDir, "Library", "Caches", bundleID),
			filepath.Join(homeDir, "Library", "Preferences", bundleID+".plist"),
			filepath.Join(homeDir, "Library", "Containers", bundleID),
			filepath.Join(homeDir, "Library", "Group Containers", bundleID),
			filepath.Join(homeDir, "Library", "HTTPStorages", bundleID),
			filepath.Join(homeDir, "Library", "WebKit", bundleID),
		)
	}

	for _, path := range cleanupPaths {
		if _, err := os.Stat(path); err == nil {
			if err := os.RemoveAll(path); err != nil {
				results.PathsFailed = append(results.PathsFailed, path)
			} else {
				results.PathsRemoved = append(results.PathsRemoved, path)
			}
		}
	}

	return results, nil
}
