package winget

import "errors"

var (
	// ErrNotWindows is returned when attempting winget operations on non-Windows systems.
	ErrNotWindows = errors.New("winget is only available on Windows")

	// ErrInstallFailed is returned when winget installation fails.
	ErrInstallFailed = errors.New("winget installation failed")

	// ErrNotAvailable is returned when winget is not installed.
	ErrNotAvailable = errors.New("winget is not available")
)

// Windows exit codes for winget operations.
// These are documented at: https://github.com/microsoft/winget-cli/blob/master/doc/windows/package-manager/winget/returnCodes.md
const (
	// ExitSuccess indicates successful operation.
	ExitSuccess = 0

	// ExitNoUpdateAvailable indicates no update is available for the package.
	// Hex: 0x8A150011, Signed: -1978335215
	ExitNoUpdateAvailable = 0x8A150011
	ExitNoUpdateAvailableSigned = -1978335215

	// ExitPackageNotFound indicates the package was not found.
	// Hex: 0x8A150014, Signed: -1978335212
	ExitPackageNotFound = 0x8A150014
	ExitPackageNotFoundSigned = -1978335212

	// ExitNoApplicableUpgrade indicates no applicable upgrade found.
	// Hex: 0x8A150010, Signed: -1978335216
	ExitNoApplicableUpgrade = 0x8A150010
	ExitNoApplicableUpgradeSigned = -1978335216

	// ExitPackageAlreadyInstalled indicates the package is already installed.
	// Hex: 0x8A150013, Signed: -1978335213
	ExitPackageAlreadyInstalled = 0x8A150013
	ExitPackageAlreadyInstalledSigned = -1978335213
)

// IsNoUpdateAvailable checks if the exit code indicates no update is available.
func IsNoUpdateAvailable(exitCode int) bool {
	return exitCode == ExitNoUpdateAvailable || exitCode == ExitNoUpdateAvailableSigned
}

// IsPackageNotFound checks if the exit code indicates package not found.
func IsPackageNotFound(exitCode int) bool {
	return exitCode == ExitPackageNotFound || exitCode == ExitPackageNotFoundSigned
}

// IsNoApplicableUpgrade checks if the exit code indicates no applicable upgrade.
func IsNoApplicableUpgrade(exitCode int) bool {
	return exitCode == ExitNoApplicableUpgrade || exitCode == ExitNoApplicableUpgradeSigned
}

// IsPackageAlreadyInstalled checks if the exit code indicates package already installed.
func IsPackageAlreadyInstalled(exitCode int) bool {
	return exitCode == ExitPackageAlreadyInstalled || exitCode == ExitPackageAlreadyInstalledSigned
}
