// Package validation provides pre-uninstall validation services.
//go:build linux

package validation

import (
	"context"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
)

// DEBValidator validates DEB package installations on Linux.
type DEBValidator struct {
	logger *slog.Logger
}

// NewDEBValidator creates a new DEB validator.
func NewDEBValidator(logger *slog.Logger) *DEBValidator {
	return &DEBValidator{logger: logger}
}

// CanHandle returns true for DEB installations.
func (v *DEBValidator) CanHandle(installationType string) bool {
	return installationType == "deb"
}

// IsAvailable returns true if dpkg is available.
func (v *DEBValidator) IsAvailable() bool {
	_, err := exec.LookPath("dpkg")
	return err == nil
}

// Validate validates a DEB package installation.
func (v *DEBValidator) Validate(ctx context.Context, req *ValidationRequest) (*ValidationResult, error) {
	result := &ValidationResult{
		InstallType:    "deb",
		PackageManager: v.detectPackageManager(),
	}

	packageName := req.PackageName
	if packageName == "" {
		packageName = req.PackageIdentifier
	}

	// Check if package is installed via dpkg
	cmd := exec.CommandContext(ctx, "dpkg", "-s", packageName)
	output, err := cmd.Output()
	if err != nil {
		result.IsInstalled = false
		result.Errors = append(result.Errors, "Package not installed")
		return result, nil
	}

	result.IsInstalled = true

	// Parse dpkg output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			switch key {
			case "Version":
				result.CurrentVersion = value
			case "Installed-Size":
				if size, err := strconv.ParseInt(value, 10, 64); err == nil {
					result.EstimatedSpaceBytes = size * 1024 // KB to bytes
				}
			}
		}
	}

	// Check for reverse dependencies
	cmd = exec.CommandContext(ctx, "apt-cache", "rdepends", "--installed", packageName)
	if rdOutput, err := cmd.Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(rdOutput)), "\n")
		for _, line := range lines[1:] { // Skip first line (package name)
			dep := strings.TrimSpace(line)
			if dep != "" && !strings.HasPrefix(dep, "|") {
				result.DependentPackages = append(result.DependentPackages, dep)
			}
		}
	}

	return result, nil
}

// detectPackageManager detects the available package manager.
func (v *DEBValidator) detectPackageManager() string {
	if _, err := exec.LookPath("apt-get"); err == nil {
		return "apt-get"
	}
	return "dpkg"
}

// RPMValidator validates RPM package installations on Linux.
type RPMValidator struct {
	logger *slog.Logger
}

// NewRPMValidator creates a new RPM validator.
func NewRPMValidator(logger *slog.Logger) *RPMValidator {
	return &RPMValidator{logger: logger}
}

// CanHandle returns true for RPM installations.
func (v *RPMValidator) CanHandle(installationType string) bool {
	return installationType == "rpm"
}

// IsAvailable returns true if rpm is available.
func (v *RPMValidator) IsAvailable() bool {
	_, err := exec.LookPath("rpm")
	return err == nil
}

// Validate validates an RPM package installation.
func (v *RPMValidator) Validate(ctx context.Context, req *ValidationRequest) (*ValidationResult, error) {
	result := &ValidationResult{
		InstallType:    "rpm",
		PackageManager: v.detectPackageManager(),
	}

	packageName := req.PackageName
	if packageName == "" {
		packageName = req.PackageIdentifier
	}

	// Check if package is installed via rpm
	cmd := exec.CommandContext(ctx, "rpm", "-q", packageName)
	output, err := cmd.Output()
	if err != nil {
		result.IsInstalled = false
		result.Errors = append(result.Errors, "Package not installed")
		return result, nil
	}

	result.IsInstalled = true
	result.CurrentVersion = strings.TrimSpace(string(output))

	// Get package size
	cmd = exec.CommandContext(ctx, "rpm", "-q", "--queryformat", "%{SIZE}", packageName)
	if sizeOutput, err := cmd.Output(); err == nil {
		if size, err := strconv.ParseInt(strings.TrimSpace(string(sizeOutput)), 10, 64); err == nil {
			result.EstimatedSpaceBytes = size
		}
	}

	// Check for reverse dependencies
	pkgMgr := result.PackageManager
	var rdCmd *exec.Cmd
	if pkgMgr == "dnf" {
		rdCmd = exec.CommandContext(ctx, "dnf", "repoquery", "--installed", "--whatrequires", packageName)
	} else if pkgMgr == "yum" {
		rdCmd = exec.CommandContext(ctx, "repoquery", "--installed", "--whatrequires", packageName)
	}

	if rdCmd != nil {
		if rdOutput, err := rdCmd.Output(); err == nil {
			lines := strings.Split(strings.TrimSpace(string(rdOutput)), "\n")
			for _, line := range lines {
				dep := strings.TrimSpace(line)
				if dep != "" {
					result.DependentPackages = append(result.DependentPackages, dep)
				}
			}
		}
	}

	return result, nil
}

// detectPackageManager detects the available RPM package manager.
func (v *RPMValidator) detectPackageManager() string {
	managers := []string{"dnf", "yum", "zypper"}
	for _, mgr := range managers {
		if _, err := exec.LookPath(mgr); err == nil {
			return mgr
		}
	}
	return "rpm"
}
