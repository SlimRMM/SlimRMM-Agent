//go:build windows

package remotedesktop

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// requestConsentPlatform shows a consent dialog on Windows using PowerShell.
func (s *Service) requestConsentPlatform(ctx context.Context, requesterName string, timeout time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	message := fmt.Sprintf("%s wants to connect via Remote Desktop. Allow?", requesterName)

	// Use PowerShell to show a message box.
	script := fmt.Sprintf(
		`Add-Type -AssemblyName PresentationFramework; `+
			`[System.Windows.MessageBox]::Show('%s', 'Remote Desktop Request', 'YesNo', 'Question')`,
		message,
	)

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", script)
	output, err := cmd.Output()
	if ctx.Err() != nil {
		s.logger.Warn("consent dialog timed out")
		return false, nil
	}
	if err != nil {
		s.logger.Warn("consent dialog failed, denying access", "error", err)
		return false, nil
	}

	result := strings.TrimSpace(string(output))
	return result == "Yes", nil
}
