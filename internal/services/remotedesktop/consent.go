//go:build linux || darwin

package remotedesktop

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// requestConsentPlatform shows a platform-native dialog asking the local user
// to approve or deny a remote desktop connection request.
func (s *Service) requestConsentPlatform(ctx context.Context, requesterName string, timeout time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	timeoutSec := fmt.Sprintf("%d", int(timeout.Seconds()))
	message := fmt.Sprintf("%s wants to connect via Remote Desktop. Allow?", requesterName)

	switch {
	case isLinux():
		return s.requestConsentLinux(ctx, message, timeoutSec)
	case isDarwin():
		return s.requestConsentDarwin(ctx, message, timeout)
	default:
		return false, fmt.Errorf("unsupported platform for consent dialog")
	}
}

// requestConsentLinux tries zenity first, then falls back to kdialog.
// If no graphical dialog tool is available, it denies the request.
func (s *Service) requestConsentLinux(ctx context.Context, message, timeoutSec string) (bool, error) {
	// Try zenity first.
	if zenityPath, err := exec.LookPath("zenity"); err == nil {
		cmd := exec.CommandContext(ctx, zenityPath, "--question",
			"--title=Remote Desktop Request",
			"--text="+message,
			"--timeout="+timeoutSec)
		err := cmd.Run()
		if ctx.Err() != nil {
			s.logger.Warn("consent dialog timed out")
			return false, nil
		}
		return err == nil, nil
	}

	// Fall back to kdialog.
	if kdialogPath, err := exec.LookPath("kdialog"); err == nil {
		cmd := exec.CommandContext(ctx, kdialogPath,
			"--title", "Remote Desktop Request",
			"--yesno", message)
		err := cmd.Run()
		if ctx.Err() != nil {
			s.logger.Warn("consent dialog timed out")
			return false, nil
		}
		return err == nil, nil
	}

	s.logger.Warn("no graphical dialog tool available, denying consent")
	return false, fmt.Errorf("no dialog tool available (install zenity or kdialog)")
}

// requestConsentDarwin uses osascript to show a native macOS dialog.
func (s *Service) requestConsentDarwin(ctx context.Context, message string, timeout time.Duration) (bool, error) {
	script := fmt.Sprintf(
		`display dialog %q buttons {"Deny", "Allow"} default button "Allow" giving up after %d`,
		message, int(timeout.Seconds()),
	)

	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	output, err := cmd.Output()
	if ctx.Err() != nil {
		s.logger.Warn("consent dialog timed out")
		return false, nil
	}
	if err != nil {
		return false, nil
	}

	return strings.Contains(string(output), "Allow"), nil
}

// isLinux returns true if the current OS is linux.
func isLinux() bool {
	return runtime.GOOS == "linux"
}

// isDarwin returns true if the current OS is darwin (macOS).
func isDarwin() bool {
	return runtime.GOOS == "darwin"
}
