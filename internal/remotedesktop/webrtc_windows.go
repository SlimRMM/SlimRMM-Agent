//go:build cgo && windows

package remotedesktop

// configureWindowsHelper sets up the input controller to use the helper process
// if the screen capture is using it.
func configureWindowsHelper(capture *ScreenCapture, input *InputController) {
	capture.ConfigureInputController(input)
}

// init registers the Windows helper configuration
func init() {
	// This will be called when the session is created
	windowsHelperConfig = configureWindowsHelper
}

// windowsHelperConfig holds the Windows-specific configuration function
var windowsHelperConfig func(*ScreenCapture, *InputController)
