// Package winget provides Windows Package Manager (winget) detection and package operations.
package winget

import (
	"context"
	"fmt"
	"strings"
)

// PackageResult contains the result of a package operation.
type PackageResult struct {
	Success  bool
	Output   string
	ExitCode int
	Error    string
}

// ListResult contains the result of checking if a package is installed.
type ListResult struct {
	Installed bool
	Output    string
	Error     string
}

// InstallOptions contains options for package installation.
type InstallOptions struct {
	Version string
	Scope   string // "user" or "machine"
	Silent  bool
}

// IsPackageInstalled checks if a winget package is installed.
// This is a convenience method that wraps ListPackage.
func (c *Client) IsPackageInstalled(ctx context.Context, packageID string) (bool, error) {
	result, err := c.ListPackage(ctx, packageID)
	if err != nil {
		return false, err
	}
	return result.Installed, nil
}

// ListPackage checks if a specific package is installed via winget.
func (c *Client) ListPackage(ctx context.Context, packageID string) (*ListResult, error) {
	if !c.IsAvailable() {
		return nil, ErrWingetNotAvailable
	}

	if !IsValidPackageID(packageID) {
		return nil, fmt.Errorf("invalid package ID: %s", packageID)
	}

	output, err := c.executeWingetCommand(ctx, "list", "--id", packageID, "--accept-source-agreements")
	result := &ListResult{
		Output: output,
	}

	if err != nil {
		result.Error = err.Error()
		result.Installed = false
		return result, nil
	}

	// Package is installed if the output contains the package ID
	result.Installed = strings.Contains(output, packageID)
	return result, nil
}

// InstallPackage installs a package via winget.
func (c *Client) InstallPackage(ctx context.Context, packageID string, opts *InstallOptions) (*PackageResult, error) {
	if !c.IsAvailable() {
		return nil, ErrWingetNotAvailable
	}

	if !IsValidPackageID(packageID) {
		return nil, fmt.Errorf("invalid package ID: %s", packageID)
	}

	args := []string{
		"install",
		"--id", packageID,
		"--accept-source-agreements",
		"--accept-package-agreements",
		"--disable-interactivity",
	}

	if opts != nil {
		if opts.Scope != "" {
			args = append(args, "--scope", opts.Scope)
		}
		if opts.Silent {
			args = append(args, "--silent")
		}
		if opts.Version != "" {
			args = append(args, "--version", opts.Version)
		}
	}

	output, err := c.executeWingetCommand(ctx, args...)
	result := &PackageResult{
		Output:   output,
		Success:  err == nil,
		ExitCode: 0,
	}

	if err != nil {
		result.Error = err.Error()
		if exitErr, ok := extractExitCode(err); ok {
			result.ExitCode = exitErr
		} else {
			result.ExitCode = -1
		}
	}

	return result, nil
}

// UpgradePackage upgrades a package via winget.
func (c *Client) UpgradePackage(ctx context.Context, packageID string) (*PackageResult, error) {
	if !c.IsAvailable() {
		return nil, ErrWingetNotAvailable
	}

	if !IsValidPackageID(packageID) {
		return nil, fmt.Errorf("invalid package ID: %s", packageID)
	}

	args := []string{
		"upgrade",
		"--id", packageID,
		"--accept-source-agreements",
		"--accept-package-agreements",
		"--disable-interactivity",
		"--silent",
	}

	output, err := c.executeWingetCommand(ctx, args...)
	result := &PackageResult{
		Output:   output,
		Success:  err == nil,
		ExitCode: 0,
	}

	if err != nil {
		result.Error = err.Error()
		if exitCode, ok := extractExitCode(err); ok {
			result.ExitCode = exitCode
			// Check for "already up to date" exit codes
			if IsNoUpdateAvailable(exitCode) || IsNoApplicableUpgrade(exitCode) {
				result.Success = true
				result.Error = "already up to date"
			}
		} else {
			result.ExitCode = -1
		}
	}

	return result, nil
}
