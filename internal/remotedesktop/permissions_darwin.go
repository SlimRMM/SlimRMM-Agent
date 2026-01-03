//go:build darwin

package remotedesktop

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreGraphics -framework CoreFoundation -framework ApplicationServices -framework Foundation

#include <CoreGraphics/CoreGraphics.h>
#include <CoreFoundation/CoreFoundation.h>
#include <ApplicationServices/ApplicationServices.h>
#import <Foundation/Foundation.h>

// CheckScreenRecordingPermission checks if screen recording permission is granted
// without triggering the permission dialog (macOS 10.15+).
int CheckScreenRecordingPermission(void) {
    // CGPreflightScreenCaptureAccess is available on macOS 10.15+
    // It checks permission without triggering the dialog
    if (@available(macOS 10.15, *)) {
        return CGPreflightScreenCaptureAccess() ? 1 : 0;
    }
    // On older macOS versions, assume permission is granted
    return 1;
}

// RequestScreenRecordingPermission requests screen recording permission
// and shows the system dialog if needed (macOS 10.15+).
int RequestScreenRecordingPermission(void) {
    if (@available(macOS 10.15, *)) {
        return CGRequestScreenCaptureAccess() ? 1 : 0;
    }
    // On older macOS versions, assume permission is granted
    return 1;
}

// CheckAccessibilityPermission checks if accessibility permission is granted.
// This is needed for input control (mouse/keyboard).
int CheckAccessibilityPermission(void) {
    // AXIsProcessTrusted checks if the app has accessibility permissions
    return AXIsProcessTrusted() ? 1 : 0;
}

// RequestAccessibilityPermission opens the System Preferences to the
// Accessibility pane so the user can grant permission.
void RequestAccessibilityPermission(void) {
    // This will prompt the user if not already trusted
    NSDictionary *options = @{(__bridge NSString *)kAXTrustedCheckOptionPrompt: @YES};
    AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options);
}
*/
import "C"

import (
	"log/slog"
)

// TriggerScreenRecordingPermission attempts to request screen recording permission.
// Returns true if permission is granted.
func TriggerScreenRecordingPermission() bool {
	return C.RequestScreenRecordingPermission() == 1
}

// CheckScreenRecordingPermission checks if screen recording permission is granted
// without triggering the permission dialog.
func CheckScreenRecordingPermission() bool {
	return C.CheckScreenRecordingPermission() == 1
}

// RequestScreenRecordingPermission requests screen recording permission
// and shows the system dialog if needed.
func RequestScreenRecordingPermission() bool {
	return C.RequestScreenRecordingPermission() == 1
}

// CheckAccessibilityPermission checks if accessibility permission is granted.
// This is needed for input control (mouse/keyboard).
func CheckAccessibilityPermission() bool {
	return C.CheckAccessibilityPermission() == 1
}

// RequestAccessibilityPermission opens the System Preferences to the
// Accessibility pane so the user can grant permission.
func RequestAccessibilityPermission() {
	C.RequestAccessibilityPermission()
}

// InitializePermissions checks and requests necessary permissions on macOS.
// This should be called at agent startup.
func InitializePermissions(logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}

	// Check and request screen recording permission
	if CheckScreenRecordingPermission() {
		logger.Info("screen recording permission already granted")
	} else {
		logger.Info("requesting screen recording permission")
		if RequestScreenRecordingPermission() {
			logger.Info("screen recording permission granted")
		} else {
			logger.Warn("screen recording permission denied - remote desktop will not work")
		}
	}

	// Check accessibility permission (for input control)
	if CheckAccessibilityPermission() {
		logger.Info("accessibility permission already granted")
	} else {
		logger.Warn("accessibility permission not granted - requesting")
		RequestAccessibilityPermission()
		// Check again after request
		if CheckAccessibilityPermission() {
			logger.Info("accessibility permission granted")
		} else {
			logger.Warn("accessibility permission denied - remote control will not work")
		}
	}
}

// GetPermissionStatus returns the current status of macOS permissions.
func GetPermissionStatus() map[string]bool {
	return map[string]bool{
		"screen_recording": CheckScreenRecordingPermission(),
		"accessibility":    CheckAccessibilityPermission(),
	}
}
