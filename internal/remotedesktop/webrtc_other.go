//go:build cgo && !windows

package remotedesktop

// windowsHelperConfig is nil on non-Windows platforms
var windowsHelperConfig func(*ScreenCapture, *InputController)
