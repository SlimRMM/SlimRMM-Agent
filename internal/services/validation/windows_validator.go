// Package validation provides pre-uninstall validation services.
//go:build windows

package validation

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// WingetValidator validates Winget package installations on Windows.
type WingetValidator struct {
	logger *slog.Logger
}

// NewWingetValidator creates a new Winget validator.
func NewWingetValidator(logger *slog.Logger) *WingetValidator {
	return &WingetValidator{logger: logger}
}

// CanHandle returns true for winget installations.
func (v *WingetValidator) CanHandle(installationType string) bool {
	return installationType == "winget"
}

// IsAvailable returns true if winget is available.
func (v *WingetValidator) IsAvailable() bool {
	_, err := exec.LookPath("winget")
	return err == nil
}

// Validate validates a Winget package installation.
func (v *WingetValidator) Validate(ctx context.Context, req *ValidationRequest) (*ValidationResult, error) {
	result := &ValidationResult{
		InstallType:    "winget",
		PackageManager: "winget",
	}

	packageID := req.WingetPackageID
	if packageID == "" {
		packageID = req.PackageIdentifier
	}

	// Check if winget can find the package
	cmd := exec.CommandContext(ctx, "winget", "list", "--id", packageID, "--accept-source-agreements")
	output, err := cmd.Output()
	if err != nil {
		result.IsInstalled = false
		result.Errors = append(result.Errors, "Package not found via winget")
		return result, nil
	}

	outputStr := string(output)
	if strings.Contains(outputStr, packageID) {
		result.IsInstalled = true
		result.CurrentVersion = v.parseVersion(outputStr, packageID)
		result.RunningProcesses = v.findRunningProcesses(ctx, packageID)
		result.EstimatedSpaceBytes = v.estimatePackageSize(ctx, packageID)
	}

	return result, nil
}

// parseVersion extracts the version from winget list output.
func (v *WingetValidator) parseVersion(output, packageID string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, packageID) {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				for i := len(parts) - 1; i >= 0; i-- {
					if matched, _ := regexp.MatchString(`^\d+\.`, parts[i]); matched {
						return parts[i]
					}
				}
			}
			break
		}
	}
	return ""
}

// findRunningProcesses finds processes related to the package.
func (v *WingetValidator) findRunningProcesses(ctx context.Context, packageID string) []ProcessInfo {
	var processes []ProcessInfo

	cmd := exec.CommandContext(ctx, "tasklist", "/FO", "CSV", "/NH")
	output, err := cmd.Output()
	if err != nil {
		return processes
	}

	searchTerm := strings.ToLower(strings.ReplaceAll(packageID, ".", ""))
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) >= 2 {
			processName := strings.Trim(parts[0], "\"")
			pid := strings.Trim(parts[1], "\"")

			if strings.Contains(strings.ToLower(processName), searchTerm) {
				pidInt, _ := strconv.Atoi(pid)
				processes = append(processes, ProcessInfo{
					Name: processName,
					PID:  pidInt,
				})
			}
		}
	}

	return processes
}

// estimatePackageSize estimates the package size.
func (v *WingetValidator) estimatePackageSize(ctx context.Context, packageID string) int64 {
	cmd := exec.CommandContext(ctx, "winget", "show", "--id", packageID, "--accept-source-agreements")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "size") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return parseHumanSize(strings.TrimSpace(parts[1]))
			}
		}
	}

	return 0
}

// MSIValidator validates MSI package installations on Windows.
type MSIValidator struct {
	logger *slog.Logger
}

// NewMSIValidator creates a new MSI validator.
func NewMSIValidator(logger *slog.Logger) *MSIValidator {
	return &MSIValidator{logger: logger}
}

// CanHandle returns true for MSI installations.
func (v *MSIValidator) CanHandle(installationType string) bool {
	return installationType == "msi"
}

// IsAvailable returns true (MSI is always available on Windows).
func (v *MSIValidator) IsAvailable() bool {
	return true
}

// Validate validates an MSI package installation.
func (v *MSIValidator) Validate(ctx context.Context, req *ValidationRequest) (*ValidationResult, error) {
	result := &ValidationResult{
		InstallType:    "msi",
		PackageManager: "msiexec",
	}

	productCode := req.MSIProductCode
	if productCode == "" {
		productCode = req.PackageIdentifier
	}

	// Query registry for MSI product
	regPaths := []string{
		fmt.Sprintf(`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\%s`, productCode),
		fmt.Sprintf(`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\%s`, productCode),
		fmt.Sprintf(`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\%s`, productCode),
	}

	for _, regPath := range regPaths {
		cmd := exec.CommandContext(ctx, "reg", "query", regPath, "/v", "DisplayName")
		output, err := cmd.Output()
		if err == nil {
			result.IsInstalled = true

			outputStr := string(output)
			if idx := strings.Index(outputStr, "REG_SZ"); idx != -1 {
				result.InstallLocation = strings.TrimSpace(outputStr[idx+6:])
			}

			// Get version
			cmd = exec.CommandContext(ctx, "reg", "query", regPath, "/v", "DisplayVersion")
			if verOutput, err := cmd.Output(); err == nil {
				if idx := strings.Index(string(verOutput), "REG_SZ"); idx != -1 {
					result.CurrentVersion = strings.TrimSpace(string(verOutput)[idx+6:])
				}
			}

			// Get estimated size
			cmd = exec.CommandContext(ctx, "reg", "query", regPath, "/v", "EstimatedSize")
			if sizeOutput, err := cmd.Output(); err == nil {
				if idx := strings.Index(string(sizeOutput), "REG_DWORD"); idx != -1 {
					sizeStr := strings.TrimSpace(string(sizeOutput)[idx+9:])
					if size, err := strconv.ParseInt(strings.TrimPrefix(sizeStr, "0x"), 16, 64); err == nil {
						result.EstimatedSpaceBytes = size * 1024
					}
				}
			}

			break
		}
	}

	return result, nil
}

// parseHumanSize parses human-readable size strings (e.g., "100 MB", "1.5 GB").
func parseHumanSize(sizeStr string) int64 {
	sizeStr = strings.TrimSpace(strings.ToUpper(sizeStr))

	multipliers := map[string]int64{
		"B":  1,
		"KB": 1024,
		"MB": 1024 * 1024,
		"GB": 1024 * 1024 * 1024,
		"TB": 1024 * 1024 * 1024 * 1024,
	}

	for suffix, multiplier := range multipliers {
		if strings.HasSuffix(sizeStr, suffix) {
			numStr := strings.TrimSpace(strings.TrimSuffix(sizeStr, suffix))
			if num, err := strconv.ParseFloat(numStr, 64); err == nil {
				return int64(num * float64(multiplier))
			}
		}
	}

	return 0
}
