//go:build darwin

package tamper

import (
	"fmt"
	"os/exec"
)

// protectFilePlatform makes a file immutable using chflags schg.
// The schg (system immutable) flag prevents modification even by root.
func (p *Protection) protectFilePlatform(path string) error {
	cmd := exec.Command("chflags", "schg", path)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("chflags schg failed: %w", err)
	}
	return nil
}

// unprotectFilePlatform removes the system immutable flag.
func (p *Protection) unprotectFilePlatform(path string) error {
	cmd := exec.Command("chflags", "noschg", path)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("chflags noschg failed: %w", err)
	}
	return nil
}

// InstallWatchdog installs a launchd watchdog for the agent.
// macOS launchd already has KeepAlive functionality, but this adds
// an additional layer of protection with a separate watchdog daemon.
func InstallWatchdog() error {
	watchdogPlist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>io.slimrmm.watchdog</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>while true; do launchctl list io.slimrmm.agent > /dev/null 2>&amp;1 || launchctl bootstrap system /Library/LaunchDaemons/io.slimrmm.agent.plist 2>/dev/null || launchctl load -w /Library/LaunchDaemons/io.slimrmm.agent.plist 2>/dev/null; sleep 10; done</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/slimrmm/watchdog.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/slimrmm/watchdog.log</string>
</dict>
</plist>
`

	plistPath := "/Library/LaunchDaemons/io.slimrmm.watchdog.plist"

	// Write watchdog plist
	cmd := exec.Command("bash", "-c", fmt.Sprintf("cat > %s << 'WATCHDOG_EOF'\n%sWATCHDOG_EOF", plistPath, watchdogPlist))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to write watchdog plist: %w", err)
	}

	// Set proper permissions
	if err := exec.Command("chmod", "644", plistPath).Run(); err != nil {
		return fmt.Errorf("failed to set plist permissions: %w", err)
	}

	if err := exec.Command("chown", "root:wheel", plistPath).Run(); err != nil {
		return fmt.Errorf("failed to set plist ownership: %w", err)
	}

	// Load watchdog
	// Try modern bootstrap first, fall back to legacy load
	if err := exec.Command("launchctl", "bootstrap", "system", plistPath).Run(); err != nil {
		if err := exec.Command("launchctl", "load", "-w", plistPath).Run(); err != nil {
			return fmt.Errorf("failed to load watchdog: %w", err)
		}
	}

	return nil
}

// UninstallWatchdog removes the watchdog daemon.
func UninstallWatchdog() error {
	plistPath := "/Library/LaunchDaemons/io.slimrmm.watchdog.plist"

	// Unload watchdog
	_ = exec.Command("launchctl", "bootout", "system", plistPath).Run()
	_ = exec.Command("launchctl", "unload", plistPath).Run()

	// Remove plist
	return exec.Command("rm", "-f", plistPath).Run()
}

// ProtectServiceFile makes the launchd plist immutable.
func ProtectServiceFile() error {
	return exec.Command("chflags", "schg", "/Library/LaunchDaemons/io.slimrmm.agent.plist").Run()
}

// UnprotectServiceFile removes immutable flag from plist.
func UnprotectServiceFile() error {
	return exec.Command("chflags", "noschg", "/Library/LaunchDaemons/io.slimrmm.agent.plist").Run()
}

// ProtectAppBundle protects the entire app bundle from modification.
func ProtectAppBundle() error {
	paths := []string{
		"/Applications/SlimRMM.app/Contents/MacOS/slimrmm-agent",
		"/Applications/SlimRMM.app/Contents/Info.plist",
	}

	for _, path := range paths {
		if err := exec.Command("chflags", "schg", path).Run(); err != nil {
			return fmt.Errorf("failed to protect %s: %w", path, err)
		}
	}

	return nil
}

// UnprotectAppBundle removes protection from the app bundle.
func UnprotectAppBundle() error {
	paths := []string{
		"/Applications/SlimRMM.app/Contents/MacOS/slimrmm-agent",
		"/Applications/SlimRMM.app/Contents/Info.plist",
	}

	for _, path := range paths {
		_ = exec.Command("chflags", "noschg", path).Run()
	}

	return nil
}
