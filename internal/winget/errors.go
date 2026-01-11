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
