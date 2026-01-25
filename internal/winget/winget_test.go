package winget

import (
	"context"
	"log/slog"
	"os"
	"runtime"
	"testing"
)

func TestIsValidPackageID(t *testing.T) {
	tests := []struct {
		id    string
		valid bool
	}{
		{"Microsoft.PowerShell", true},
		{"Google.Chrome", true},
		{"Mozilla.Firefox", true},
		{"7zip.7zip", true},
		{"JetBrains.IntelliJIDEA.Community", true},
		{"Microsoft.VisualStudioCode", true},
		{"VideoLAN.VLC", true},
		{"a", true},
		{"A", true},
		{"1password", true},
		{"Package_With_Underscore", true},
		{"Package-With-Hyphen", true},
		{"", false},                       // Empty
		{"-starts-with-hyphen", false},    // Starts with hyphen
		{".starts.with.dot", false},       // Starts with dot
		{"_starts_with_underscore", false}, // Starts with underscore
		{"contains space", false},         // Contains space
		{"contains@symbol", false},        // Contains @
		{"contains#symbol", false},        // Contains #
		// Very long ID (>256 chars)
		{string(make([]byte, 257)), false},
	}

	for _, tt := range tests {
		name := tt.id
		if len(name) > 30 {
			name = name[:30] + "..."
		}
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			if got := IsValidPackageID(tt.id); got != tt.valid {
				t.Errorf("IsValidPackageID(%q) = %v, want %v", tt.id, got, tt.valid)
			}
		})
	}
}

func TestIsValidPackageIDBoundary(t *testing.T) {
	// Test exactly 256 characters (should be valid if pattern matches)
	validLong := make([]byte, 256)
	for i := range validLong {
		validLong[i] = 'a'
	}
	if !IsValidPackageID(string(validLong)) {
		t.Error("256-char ID should be valid")
	}

	// Test 257 characters (should be invalid due to length)
	invalidLong := make([]byte, 257)
	for i := range invalidLong {
		invalidLong[i] = 'a'
	}
	if IsValidPackageID(string(invalidLong)) {
		t.Error("257-char ID should be invalid")
	}
}

func TestErrors(t *testing.T) {
	if ErrNotWindows == nil {
		t.Error("ErrNotWindows should not be nil")
	}
	if ErrNotWindows.Error() != "winget is only available on Windows" {
		t.Errorf("ErrNotWindows = %v, want 'winget is only available on Windows'", ErrNotWindows)
	}

	if ErrInstallFailed == nil {
		t.Error("ErrInstallFailed should not be nil")
	}
	if ErrInstallFailed.Error() != "winget installation failed" {
		t.Errorf("ErrInstallFailed = %v, want 'winget installation failed'", ErrInstallFailed)
	}

	if ErrNotAvailable == nil {
		t.Error("ErrNotAvailable should not be nil")
	}
	if ErrNotAvailable.Error() != "winget is not available" {
		t.Errorf("ErrNotAvailable = %v, want 'winget is not available'", ErrNotAvailable)
	}

	if ErrWingetNotAvailable == nil {
		t.Error("ErrWingetNotAvailable should not be nil")
	}
	if ErrWingetNotAvailable.Error() != "winget binary not available" {
		t.Errorf("ErrWingetNotAvailable = %v, want 'winget binary not available'", ErrWingetNotAvailable)
	}
}

func TestExitCodeConstants(t *testing.T) {
	if ExitSuccess != 0 {
		t.Errorf("ExitSuccess = %d, want 0", ExitSuccess)
	}
	if ExitNoUpdateAvailable != 0x8A150011 {
		t.Errorf("ExitNoUpdateAvailable = 0x%X, want 0x8A150011", ExitNoUpdateAvailable)
	}
	if ExitNoUpdateAvailableSigned != -1978335215 {
		t.Errorf("ExitNoUpdateAvailableSigned = %d, want -1978335215", ExitNoUpdateAvailableSigned)
	}
	if ExitPackageNotFound != 0x8A150014 {
		t.Errorf("ExitPackageNotFound = 0x%X, want 0x8A150014", ExitPackageNotFound)
	}
	if ExitPackageNotFoundSigned != -1978335212 {
		t.Errorf("ExitPackageNotFoundSigned = %d, want -1978335212", ExitPackageNotFoundSigned)
	}
	if ExitNoApplicableUpgrade != 0x8A150010 {
		t.Errorf("ExitNoApplicableUpgrade = 0x%X, want 0x8A150010", ExitNoApplicableUpgrade)
	}
	if ExitNoApplicableUpgradeSigned != -1978335216 {
		t.Errorf("ExitNoApplicableUpgradeSigned = %d, want -1978335216", ExitNoApplicableUpgradeSigned)
	}
	if ExitPackageAlreadyInstalled != 0x8A150013 {
		t.Errorf("ExitPackageAlreadyInstalled = 0x%X, want 0x8A150013", ExitPackageAlreadyInstalled)
	}
	if ExitPackageAlreadyInstalledSigned != -1978335213 {
		t.Errorf("ExitPackageAlreadyInstalledSigned = %d, want -1978335213", ExitPackageAlreadyInstalledSigned)
	}
}

func TestIsNoUpdateAvailable(t *testing.T) {
	if !IsNoUpdateAvailable(ExitNoUpdateAvailable) {
		t.Error("IsNoUpdateAvailable(ExitNoUpdateAvailable) should be true")
	}
	if !IsNoUpdateAvailable(ExitNoUpdateAvailableSigned) {
		t.Error("IsNoUpdateAvailable(ExitNoUpdateAvailableSigned) should be true")
	}
	if IsNoUpdateAvailable(0) {
		t.Error("IsNoUpdateAvailable(0) should be false")
	}
	if IsNoUpdateAvailable(1) {
		t.Error("IsNoUpdateAvailable(1) should be false")
	}
}

func TestIsPackageNotFound(t *testing.T) {
	if !IsPackageNotFound(ExitPackageNotFound) {
		t.Error("IsPackageNotFound(ExitPackageNotFound) should be true")
	}
	if !IsPackageNotFound(ExitPackageNotFoundSigned) {
		t.Error("IsPackageNotFound(ExitPackageNotFoundSigned) should be true")
	}
	if IsPackageNotFound(0) {
		t.Error("IsPackageNotFound(0) should be false")
	}
	if IsPackageNotFound(1) {
		t.Error("IsPackageNotFound(1) should be false")
	}
}

func TestIsNoApplicableUpgrade(t *testing.T) {
	if !IsNoApplicableUpgrade(ExitNoApplicableUpgrade) {
		t.Error("IsNoApplicableUpgrade(ExitNoApplicableUpgrade) should be true")
	}
	if !IsNoApplicableUpgrade(ExitNoApplicableUpgradeSigned) {
		t.Error("IsNoApplicableUpgrade(ExitNoApplicableUpgradeSigned) should be true")
	}
	if IsNoApplicableUpgrade(0) {
		t.Error("IsNoApplicableUpgrade(0) should be false")
	}
}

func TestIsPackageAlreadyInstalled(t *testing.T) {
	if !IsPackageAlreadyInstalled(ExitPackageAlreadyInstalled) {
		t.Error("IsPackageAlreadyInstalled(ExitPackageAlreadyInstalled) should be true")
	}
	if !IsPackageAlreadyInstalled(ExitPackageAlreadyInstalledSigned) {
		t.Error("IsPackageAlreadyInstalled(ExitPackageAlreadyInstalledSigned) should be true")
	}
	if IsPackageAlreadyInstalled(0) {
		t.Error("IsPackageAlreadyInstalled(0) should be false")
	}
}

func TestStatusStruct(t *testing.T) {
	status := Status{
		Available:                   true,
		Version:                     "1.6.3132",
		BinaryPath:                  "C:\\Program Files\\WindowsApps\\winget.exe",
		SystemLevel:                 true,
		PowerShell7Available:        true,
		WinGetClientModuleAvailable: true,
		LastRepair:                  "2024-01-15T10:30:00Z",
	}

	if !status.Available {
		t.Error("Available should be true")
	}
	if status.Version != "1.6.3132" {
		t.Errorf("Version = %s, want 1.6.3132", status.Version)
	}
	if status.BinaryPath != "C:\\Program Files\\WindowsApps\\winget.exe" {
		t.Errorf("BinaryPath = %s, want 'C:\\Program Files\\WindowsApps\\winget.exe'", status.BinaryPath)
	}
	if !status.SystemLevel {
		t.Error("SystemLevel should be true")
	}
	if !status.PowerShell7Available {
		t.Error("PowerShell7Available should be true")
	}
	if !status.WinGetClientModuleAvailable {
		t.Error("WinGetClientModuleAvailable should be true")
	}
	if status.LastRepair != "2024-01-15T10:30:00Z" {
		t.Errorf("LastRepair = %s, want '2024-01-15T10:30:00Z'", status.LastRepair)
	}
}

func TestNew(t *testing.T) {
	client := New()
	if client == nil {
		t.Error("New should return non-nil client")
	}
}

func TestGetDefault(t *testing.T) {
	client := GetDefault()
	if client == nil {
		t.Error("GetDefault should return non-nil client")
	}

	// Verify singleton
	client2 := GetDefault()
	if client != client2 {
		t.Error("GetDefault should return same instance")
	}
}

func TestClientIsAvailable(t *testing.T) {
	client := New()
	// On non-Windows, should return false
	if client.IsAvailable() {
		if runtime.GOOS != "windows" {
			t.Error("IsAvailable should return false on non-Windows")
		} else {
			t.Log("IsAvailable returned true (running on Windows)")
		}
	}
}

func TestClientGetVersion(t *testing.T) {
	client := New()
	version := client.GetVersion()
	// On non-Windows, should be empty
	if version != "" && runtime.GOOS != "windows" {
		t.Errorf("GetVersion = %s, want empty on non-Windows", version)
	}
}

func TestClientGetBinaryPath(t *testing.T) {
	client := New()
	path := client.GetBinaryPath()
	// On non-Windows, should be empty
	if path != "" && runtime.GOOS != "windows" {
		t.Errorf("GetBinaryPath = %s, want empty on non-Windows", path)
	}
}

func TestClientGetStatus(t *testing.T) {
	client := New()
	status := client.GetStatus()

	// On non-Windows, should indicate not available
	if runtime.GOOS != "windows" {
		if status.Available {
			t.Error("Status.Available should be false on non-Windows")
		}
		if status.BinaryPath != "" {
			t.Errorf("Status.BinaryPath = %s, want empty on non-Windows", status.BinaryPath)
		}
	}
}

func TestClientRefresh(t *testing.T) {
	client := New()
	// Refresh should not panic
	client.Refresh()

	// On non-Windows, should still be unavailable
	if runtime.GOOS != "windows" && client.IsAvailable() {
		t.Error("IsAvailable should be false after Refresh on non-Windows")
	}
}

func TestClientIsSystemLevel(t *testing.T) {
	client := New()
	// On non-Windows, should return false
	if client.IsSystemLevel() && runtime.GOOS != "windows" {
		t.Error("IsSystemLevel should return false on non-Windows")
	}
}

func TestClientInstall(t *testing.T) {
	client := New()
	ctx := context.Background()

	err := client.Install(ctx)
	// On non-Windows, should return ErrNotWindows
	if runtime.GOOS != "windows" {
		if err != ErrNotWindows {
			t.Errorf("Install error = %v, want ErrNotWindows", err)
		}
	}
}

func TestClientUpdate(t *testing.T) {
	client := New()
	ctx := context.Background()

	err := client.Update(ctx)
	// On non-Windows, should return nil (no-op)
	if runtime.GOOS != "windows" && err != nil {
		t.Errorf("Update error = %v, want nil on non-Windows", err)
	}
}

func TestEnsureInstalled(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	err := EnsureInstalled(ctx, logger)
	// On non-Windows, should return nil (skip)
	if runtime.GOOS != "windows" && err != nil {
		t.Errorf("EnsureInstalled error = %v, want nil on non-Windows", err)
	}
}

func TestEnsureSystemOnly(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	err := EnsureSystemOnly(ctx, logger)
	// On non-Windows, should return nil (skip)
	if runtime.GOOS != "windows" && err != nil {
		t.Errorf("EnsureSystemOnly error = %v, want nil on non-Windows", err)
	}
}

func TestCheckAndUpdate(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	updated, err := CheckAndUpdate(ctx, logger)
	// On non-Windows, should return false, nil
	if runtime.GOOS != "windows" {
		if updated {
			t.Error("CheckAndUpdate should return false on non-Windows")
		}
		if err != nil {
			t.Errorf("CheckAndUpdate error = %v, want nil on non-Windows", err)
		}
	}
}

func TestClientStruct(t *testing.T) {
	client := &Client{}
	if client == nil {
		t.Error("Client should be constructable")
	}
}

func TestPackageIDPatternCompiled(t *testing.T) {
	// Verify the regex is compiled and works
	if packageIDPattern == nil {
		t.Fatal("packageIDPattern should be compiled")
	}

	// Test pattern matches expected IDs
	testIDs := []string{
		"Microsoft.PowerShell",
		"a",
		"1password",
		"Package.Name.With.Dots",
	}
	for _, id := range testIDs {
		if !packageIDPattern.MatchString(id) {
			t.Errorf("packageIDPattern should match %q", id)
		}
	}
}
