// Package software provides software installation and uninstallation services.
package software

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/services/models"
)

// DefaultFileLockService implements FileLockService.
type DefaultFileLockService struct {
	logger *slog.Logger
}

// NewFileLockService creates a new file lock service.
func NewFileLockService(logger *slog.Logger) *DefaultFileLockService {
	return &DefaultFileLockService{logger: logger}
}

// DetectLocks detects file locks for the given paths.
func (s *DefaultFileLockService) DetectLocks(ctx context.Context, paths []string) ([]models.FileLockInfo, error) {
	var locks []models.FileLockInfo

	for _, path := range paths {
		pathLocks, err := s.detectLocksForPath(ctx, path)
		if err != nil {
			s.logger.Warn("failed to detect locks for path", "path", path, "error", err)
			continue
		}
		locks = append(locks, pathLocks...)
	}

	return locks, nil
}

// detectLocksForPath detects file locks for a single path.
func (s *DefaultFileLockService) detectLocksForPath(ctx context.Context, path string) ([]models.FileLockInfo, error) {
	switch runtime.GOOS {
	case "windows":
		return s.detectWindowsLocks(ctx, path)
	case "darwin":
		return s.detectDarwinLocks(ctx, path)
	case "linux":
		return s.detectLinuxLocks(ctx, path)
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// detectWindowsLocks detects file locks on Windows using handle.exe or PowerShell.
func (s *DefaultFileLockService) detectWindowsLocks(ctx context.Context, path string) ([]models.FileLockInfo, error) {
	// Use PowerShell to query file locks
	script := fmt.Sprintf(`
$ErrorActionPreference = 'SilentlyContinue'
$path = '%s'

# Get processes that might be using the file/directory
$processes = Get-Process | Where-Object {
    try {
        $_.Modules | Where-Object { $_.FileName -like "$path*" }
    } catch { $false }
}

foreach ($proc in $processes) {
    "$($proc.Name),$($proc.Id)"
}
`, strings.ReplaceAll(path, "'", "''"))

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	var locks []models.FileLockInfo
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		if len(parts) != 2 {
			continue
		}
		pid, _ := strconv.Atoi(parts[1])
		locks = append(locks, models.FileLockInfo{
			Path:    path,
			Process: parts[0],
			PID:     pid,
		})
	}

	return locks, nil
}

// detectDarwinLocks detects file locks on macOS using lsof.
func (s *DefaultFileLockService) detectDarwinLocks(ctx context.Context, path string) ([]models.FileLockInfo, error) {
	cmd := exec.CommandContext(ctx, "lsof", "+D", path)
	output, _ := cmd.CombinedOutput() // lsof returns non-zero if no files found

	var locks []models.FileLockInfo
	lines := strings.Split(string(output), "\n")

	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // Skip header
		}
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		pid, _ := strconv.Atoi(fields[1])
		locks = append(locks, models.FileLockInfo{
			Path:     fields[8],
			Process:  fields[0],
			PID:      pid,
			LockType: fields[3],
		})
	}

	return locks, nil
}

// detectLinuxLocks detects file locks on Linux using lsof.
func (s *DefaultFileLockService) detectLinuxLocks(ctx context.Context, path string) ([]models.FileLockInfo, error) {
	// Same as macOS, using lsof
	return s.detectDarwinLocks(ctx, path)
}

// ResolveLocks resolves file locks using the specified strategies.
func (s *DefaultFileLockService) ResolveLocks(ctx context.Context, resolutions []models.FileLockResolution) error {
	for _, res := range resolutions {
		if err := s.resolveLock(ctx, res); err != nil {
			s.logger.Warn("failed to resolve lock",
				"path", res.Lock.Path,
				"process", res.Lock.Process,
				"pid", res.Lock.PID,
				"strategy", res.Strategy,
				"error", err,
			)
			// Continue with other resolutions
		}
	}
	return nil
}

// resolveLock resolves a single file lock.
func (s *DefaultFileLockService) resolveLock(ctx context.Context, res models.FileLockResolution) error {
	switch res.Strategy {
	case "terminate":
		return s.terminateProcess(ctx, res.Lock.PID, res.ForceKill)
	case "schedule":
		return s.scheduleForReboot(ctx, res.Lock.Path)
	case "rename":
		return s.renameLockedFile(ctx, res.Lock.Path)
	case "skip":
		s.logger.Info("skipping locked file", "path", res.Lock.Path)
		return nil
	default:
		return fmt.Errorf("unknown resolution strategy: %s", res.Strategy)
	}
}

// terminateProcess terminates a process by PID.
func (s *DefaultFileLockService) terminateProcess(ctx context.Context, pid int, forceKill bool) error {
	s.logger.Info("terminating process", "pid", pid, "force", forceKill)

	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}

	if forceKill {
		return process.Kill()
	}

	// Try graceful termination first
	if runtime.GOOS == "windows" {
		cmd := exec.CommandContext(ctx, "taskkill", "/PID", strconv.Itoa(pid))
		return cmd.Run()
	}
	return process.Signal(os.Interrupt)
}

// scheduleForReboot schedules a file for deletion on reboot (Windows only).
func (s *DefaultFileLockService) scheduleForReboot(ctx context.Context, path string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("schedule for reboot is only supported on Windows")
	}

	script := fmt.Sprintf(`
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = $true, CharSet = [System.Runtime.InteropServices.CharSet]::Unicode)]
[System.Boolean] static bool MoveFileEx(string lpExistingFileName, string lpNewFileName, uint dwFlags);

$MOVEFILE_DELAY_UNTIL_REBOOT = 0x4
[void][kernel32]::MoveFileEx('%s', $null, $MOVEFILE_DELAY_UNTIL_REBOOT)
`, strings.ReplaceAll(path, "'", "''"))

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	return cmd.Run()
}

// renameLockedFile renames a locked file to allow cleanup.
func (s *DefaultFileLockService) renameLockedFile(ctx context.Context, path string) error {
	newPath := path + ".rmm_delete"
	s.logger.Info("renaming locked file", "from", path, "to", newPath)
	return os.Rename(path, newPath)
}

// IsPathLocked checks if a specific path is locked.
func (s *DefaultFileLockService) IsPathLocked(ctx context.Context, path string) (bool, error) {
	locks, err := s.detectLocksForPath(ctx, path)
	if err != nil {
		return false, err
	}
	return len(locks) > 0, nil
}

// WaitForLocksRelease waits for file locks to be released with timeout.
func (s *DefaultFileLockService) WaitForLocksRelease(ctx context.Context, paths []string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	checkInterval := 500 * time.Millisecond

	s.logger.Info("waiting for locks to be released", "paths", paths, "timeout", timeout)

	for time.Now().Before(deadline) {
		allClear := true

		for _, path := range paths {
			locks, err := s.detectLocksForPath(ctx, path)
			if err != nil {
				continue
			}

			if len(locks) > 0 {
				allClear = false
				s.logger.Debug("locks still present", "path", path, "count", len(locks))
				break
			}
		}

		if allClear {
			s.logger.Info("all locks released")
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(checkInterval):
			continue
		}
	}

	return fmt.Errorf("timeout waiting for locks to be released")
}

// GetFileHandleCount returns the number of open handles for a path.
func (s *DefaultFileLockService) GetFileHandleCount(ctx context.Context, path string) int {
	locks, err := s.detectLocksForPath(ctx, path)
	if err != nil {
		s.logger.Warn("failed to get file handle count", "path", path, "error", err)
		return -1
	}

	return len(locks)
}
