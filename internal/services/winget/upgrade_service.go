// Package winget provides winget upgrade services.
package winget

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/actions"
	"github.com/slimrmm/slimrmm-agent/internal/helper"
	"github.com/slimrmm/slimrmm-agent/internal/winget"
)

// UpgradeResult represents the result of a package upgrade.
type UpgradeResult struct {
	PackageID   string
	PackageName string
	OldVersion  string
	NewVersion  string
	Status      string // success, failed, skipped
	Output      string
	Error       string
	ExitCode    int
	Context     string // user, system
	WingetLog   string
}

// UpgradeConfig contains configuration for upgrade operations.
type UpgradeConfig struct {
	PackageID       string
	PackageName     string
	TimeoutSeconds  int
	TryUserContext  bool
	FallbackSystem  bool
}

// ProgressCallback is called to report upgrade progress.
type ProgressCallback func(output string)

// UpgradeService provides winget upgrade operations.
type UpgradeService struct {
	logger *slog.Logger
}

// NewUpgradeService creates a new winget upgrade service.
func NewUpgradeService(logger *slog.Logger) *UpgradeService {
	if logger == nil {
		logger = slog.Default()
	}
	return &UpgradeService{logger: logger}
}

// IsAvailable checks if winget is available on this system.
func (s *UpgradeService) IsAvailable() bool {
	client := winget.GetDefault()
	return client.IsAvailable()
}

// GetBinaryPath returns the path to the winget binary.
func (s *UpgradeService) GetBinaryPath() string {
	client := winget.GetDefault()
	return client.GetBinaryPath()
}

// UpgradePackage upgrades a single package using winget.
func (s *UpgradeService) UpgradePackage(ctx context.Context, update actions.Update) *UpgradeResult {
	result := &UpgradeResult{
		PackageID:   update.KB, // KB contains the package ID for winget updates
		PackageName: update.Name,
		OldVersion:  update.CurrentVer,
		NewVersion:  update.Version,
	}

	client := winget.GetDefault()
	if !client.IsAvailable() {
		result.Status = "failed"
		result.Error = "winget not available"
		return result
	}

	// Run winget upgrade via client
	upgradeResult, err := client.UpgradePackage(ctx, update.KB)
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("upgrade failed: %v", err)
		s.logger.Error("winget upgrade failed",
			"package", update.KB,
			"error", err,
		)
		return result
	}

	if upgradeResult.Success {
		if upgradeResult.Error == "already up to date" {
			result.Status = "skipped"
			result.Error = "already up to date"
		} else {
			result.Status = "success"
			s.logger.Info("winget upgrade succeeded",
				"package", update.KB,
				"old_version", update.CurrentVer,
				"new_version", update.Version,
			)
		}
	} else {
		result.Status = "failed"
		result.Error = fmt.Sprintf("upgrade failed: %s - %s", upgradeResult.Error, upgradeResult.Output)
		result.Output = upgradeResult.Output
		s.logger.Error("winget upgrade failed",
			"package", update.KB,
			"error", upgradeResult.Error,
			"output", upgradeResult.Output,
		)
	}

	return result
}

// UpgradeWithContext tries to upgrade a package, first in user context, then system context.
func (s *UpgradeService) UpgradeWithContext(ctx context.Context, config UpgradeConfig, progress ProgressCallback) *UpgradeResult {
	result := &UpgradeResult{
		PackageID:   config.PackageID,
		PackageName: config.PackageName,
	}

	client := winget.GetDefault()
	if !client.IsAvailable() {
		result.Status = "failed"
		result.Error = "winget not available"
		return result
	}

	wingetPath := client.GetBinaryPath()

	// Try user context first if enabled
	if config.TryUserContext {
		if progress != nil {
			progress("Trying user context...\n")
		}

		userResult := s.tryUserContext(wingetPath, config.PackageID)
		if userResult != nil {
			// User context returned a definitive result
			if userResult.Status == "success" || (userResult.Status == "failed" && !s.isPackageNotFoundError(userResult)) {
				return userResult
			}

			// Package not found in user context, fall back to system
			if progress != nil {
				progress("Not found in user context, trying system context...\n")
			}
		}
	}

	// Fall back to system context
	if config.FallbackSystem || !config.TryUserContext {
		s.logger.Info("trying winget update in system context", "package_id", config.PackageID)
		return s.runSystemContext(ctx, wingetPath, config, progress)
	}

	return result
}

// tryUserContext attempts upgrade in user context via helper.
func (s *UpgradeService) tryUserContext(wingetPath, packageID string) *UpgradeResult {
	result := &UpgradeResult{
		PackageID: packageID,
		Context:   "user",
	}

	helperClient, helperErr := helper.GetManager().Acquire()
	if helperErr != nil {
		s.logger.Debug("helper not available", "error", helperErr)
		return nil // Fall back to system context
	}
	defer helper.GetManager().Release()

	upgradeResult, err := helperClient.UpgradeWingetPackage(wingetPath, packageID)
	if err != nil || upgradeResult == nil {
		return nil // Fall back to system context
	}

	result.Output = upgradeResult.Output
	result.ExitCode = upgradeResult.ExitCode
	result.WingetLog = upgradeResult.WingetLog

	if upgradeResult.Success {
		result.Status = "success"
		s.logger.Info("winget update completed via user context", "package_id", packageID)
	} else {
		result.Status = "failed"
		result.Error = upgradeResult.Error
	}

	return result
}

// runSystemContext runs upgrade in system context.
func (s *UpgradeService) runSystemContext(ctx context.Context, wingetPath string, config UpgradeConfig, progress ProgressCallback) *UpgradeResult {
	result := &UpgradeResult{
		PackageID:   config.PackageID,
		PackageName: config.PackageName,
		Context:     "system",
	}

	// Set timeout
	timeout := time.Duration(config.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Run winget upgrade
	cmd := exec.CommandContext(ctx, wingetPath, "upgrade",
		"--id", config.PackageID,
		"--accept-source-agreements",
		"--accept-package-agreements",
		"--disable-interactivity",
		"--silent",
	)

	// Capture output
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	var outputBuffer strings.Builder
	var errorBuffer strings.Builder

	if err := cmd.Start(); err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to start winget: %v", err)
		return result
	}

	// Stream output
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				chunk := string(buf[:n])
				outputBuffer.WriteString(chunk)
				if progress != nil {
					progress(chunk)
				}
			}
			if err != nil {
				break
			}
		}
	}()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stderr.Read(buf)
			if n > 0 {
				chunk := string(buf[:n])
				errorBuffer.WriteString(chunk)
				if progress != nil {
					progress(chunk)
				}
			}
			if err != nil {
				break
			}
		}
	}()

	err := cmd.Wait()
	result.Output = outputBuffer.String()

	status, errorMsg := s.evaluateExitStatus(err)
	result.Status = status
	result.Error = errorMsg

	if status == "failed" {
		s.logger.Error("winget upgrade failed in system context",
			"package_id", config.PackageID,
			"error", errorMsg,
			"output", outputBuffer.String(),
			"error_output", errorBuffer.String(),
		)
	} else {
		s.logger.Info("winget upgrade completed in system context",
			"package_id", config.PackageID,
			"status", status,
		)
	}

	return result
}

// evaluateExitStatus evaluates the exit status of a winget command.
func (s *UpgradeService) evaluateExitStatus(err error) (status string, errorMsg string) {
	if err == nil {
		return "success", ""
	}

	// Check for specific exit codes
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode := exitErr.ExitCode()
		// 0x8A150011 = No applicable upgrade found (already up to date)
		if exitCode == 0x8A150011 || exitCode == -1978335215 {
			return "success", "already up to date"
		}
		return "failed", fmt.Sprintf("upgrade failed with exit code %d: %v", exitCode, err)
	}

	return "failed", fmt.Sprintf("upgrade failed: %v", err)
}

// isPackageNotFoundError checks if the result indicates package not found.
func (s *UpgradeService) isPackageNotFoundError(result *UpgradeResult) bool {
	return winget.IsPackageNotFound(result.ExitCode) ||
		strings.Contains(strings.ToLower(result.Output), "no installed package")
}

// UpgradeByID upgrades a package by its ID in system context.
func (s *UpgradeService) UpgradeByID(ctx context.Context, packageID string, timeoutSeconds int, progress ProgressCallback) *UpgradeResult {
	config := UpgradeConfig{
		PackageID:      packageID,
		TimeoutSeconds: timeoutSeconds,
		TryUserContext: false,
		FallbackSystem: true,
	}
	return s.runSystemContext(ctx, s.GetBinaryPath(), config, progress)
}
