package models

import (
	"testing"
	"time"
)

func TestInstallationTypeConstants(t *testing.T) {
	types := []InstallationType{
		InstallationTypeWinget,
		InstallationTypeMSI,
		InstallationTypePKG,
		InstallationTypeCask,
		InstallationTypeDEB,
		InstallationTypeRPM,
		InstallationTypeFormula,
	}

	for _, typ := range types {
		if typ == "" {
			t.Error("InstallationType constant should not be empty")
		}
	}

	// Test specific values
	if InstallationTypeWinget != "winget" {
		t.Errorf("InstallationTypeWinget = %s, want winget", InstallationTypeWinget)
	}
	if InstallationTypeMSI != "msi" {
		t.Errorf("InstallationTypeMSI = %s, want msi", InstallationTypeMSI)
	}
	if InstallationTypePKG != "pkg" {
		t.Errorf("InstallationTypePKG = %s, want pkg", InstallationTypePKG)
	}
	if InstallationTypeCask != "cask" {
		t.Errorf("InstallationTypeCask = %s, want cask", InstallationTypeCask)
	}
	if InstallationTypeDEB != "deb" {
		t.Errorf("InstallationTypeDEB = %s, want deb", InstallationTypeDEB)
	}
	if InstallationTypeRPM != "rpm" {
		t.Errorf("InstallationTypeRPM = %s, want rpm", InstallationTypeRPM)
	}
	if InstallationTypeFormula != "formula" {
		t.Errorf("InstallationTypeFormula = %s, want formula", InstallationTypeFormula)
	}
}

func TestInstallationStatusConstants(t *testing.T) {
	statuses := []InstallationStatus{
		StatusPending,
		StatusInstalling,
		StatusCompleted,
		StatusFailed,
		StatusCancelled,
	}

	for _, status := range statuses {
		if status == "" {
			t.Error("InstallationStatus constant should not be empty")
		}
	}

	// Test specific values
	if StatusPending != "pending" {
		t.Errorf("StatusPending = %s, want pending", StatusPending)
	}
	if StatusCompleted != "completed" {
		t.Errorf("StatusCompleted = %s, want completed", StatusCompleted)
	}
}

func TestUninstallationStatusConstants(t *testing.T) {
	statuses := []UninstallationStatus{
		UninstallStatusPending,
		UninstallStatusUninstalling,
		UninstallStatusCleaningUp,
		UninstallStatusCompleted,
		UninstallStatusFailed,
		UninstallStatusCancelled,
		UninstallStatusRolledBack,
	}

	for _, status := range statuses {
		if status == "" {
			t.Error("UninstallationStatus constant should not be empty")
		}
	}

	// Test specific values
	if UninstallStatusRolledBack != "rolled_back" {
		t.Errorf("UninstallStatusRolledBack = %s, want rolled_back", UninstallStatusRolledBack)
	}
}

func TestCleanupModeConstants(t *testing.T) {
	modes := []CleanupMode{
		CleanupModeNone,
		CleanupModeBasic,
		CleanupModeFull,
		CleanupModeComplete,
	}

	for _, mode := range modes {
		if mode == "" {
			t.Error("CleanupMode constant should not be empty")
		}
	}

	// Test specific values
	if CleanupModeNone != "none" {
		t.Errorf("CleanupModeNone = %s, want none", CleanupModeNone)
	}
	if CleanupModeComplete != "complete" {
		t.Errorf("CleanupModeComplete = %s, want complete", CleanupModeComplete)
	}
}

func TestInstallRequest(t *testing.T) {
	req := InstallRequest{
		InstallationID:   "install-123",
		InstallationType: InstallationTypeWinget,
		PackageID:        "Microsoft.VisualStudioCode",
		PackageName:      "Visual Studio Code",
		Silent:           true,
		TimeoutSeconds:   300,
	}

	if req.InstallationID != "install-123" {
		t.Errorf("InstallationID = %s, want install-123", req.InstallationID)
	}
	if req.InstallationType != InstallationTypeWinget {
		t.Errorf("InstallationType = %s, want winget", req.InstallationType)
	}
	if !req.Silent {
		t.Error("Silent should be true")
	}
}

func TestInstallResult(t *testing.T) {
	now := time.Now()
	result := InstallResult{
		InstallationID: "install-123",
		Status:         StatusCompleted,
		ExitCode:       0,
		StartedAt:      now,
		CompletedAt:    now.Add(time.Minute),
		Duration:       60.0,
	}

	if result.Status != StatusCompleted {
		t.Errorf("Status = %s, want completed", result.Status)
	}
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}
	if result.Duration != 60.0 {
		t.Errorf("Duration = %f, want 60.0", result.Duration)
	}
}

func TestInstallProgress(t *testing.T) {
	progress := InstallProgress{
		InstallationID: "install-123",
		Status:         StatusInstalling,
		Output:         "Downloading...",
		Percent:        50,
	}

	if progress.Percent != 50 {
		t.Errorf("Percent = %d, want 50", progress.Percent)
	}
}

func TestUninstallRequest(t *testing.T) {
	req := UninstallRequest{
		UninstallationID: "uninstall-456",
		InstallationType: InstallationTypeMSI,
		ProductCode:      "{12345678-1234-1234-1234-123456789012}",
		CleanupMode:      CleanupModeFull,
		CleanupPaths:     []string{"/path/to/app"},
		ForceKill:        true,
		CreateSnapshot:   true,
	}

	if req.UninstallationID != "uninstall-456" {
		t.Errorf("UninstallationID = %s, want uninstall-456", req.UninstallationID)
	}
	if req.CleanupMode != CleanupModeFull {
		t.Errorf("CleanupMode = %s, want full", req.CleanupMode)
	}
	if !req.ForceKill {
		t.Error("ForceKill should be true")
	}
	if !req.CreateSnapshot {
		t.Error("CreateSnapshot should be true")
	}
	if len(req.CleanupPaths) != 1 {
		t.Errorf("CleanupPaths length = %d, want 1", len(req.CleanupPaths))
	}
}

func TestCaskCleanup(t *testing.T) {
	cleanup := CaskCleanup{
		Artifacts: []CaskArtifact{
			{Type: "app", Values: []string{"/Applications/MyApp.app"}},
			{Type: "binary", Values: []string{"/usr/local/bin/myapp"}},
		},
		ZapStanza: &ZapStanza{
			Trash:     []string{"~/Library/Preferences/com.myapp.plist"},
			Delete:    []string{"/var/log/myapp"},
			LaunchCtl: []string{"com.myapp.helper"},
		},
		CaskDir: "/usr/local/Caskroom/myapp",
	}

	if len(cleanup.Artifacts) != 2 {
		t.Errorf("Artifacts length = %d, want 2", len(cleanup.Artifacts))
	}
	if cleanup.Artifacts[0].Type != "app" {
		t.Errorf("Artifacts[0].Type = %s, want app", cleanup.Artifacts[0].Type)
	}
	if cleanup.ZapStanza == nil {
		t.Error("ZapStanza should not be nil")
	}
	if len(cleanup.ZapStanza.Trash) != 1 {
		t.Errorf("ZapStanza.Trash length = %d, want 1", len(cleanup.ZapStanza.Trash))
	}
}

func TestUninstallResult(t *testing.T) {
	now := time.Now()
	result := UninstallResult{
		UninstallationID: "uninstall-456",
		Status:           UninstallStatusCompleted,
		ExitCode:         0,
		StartedAt:        now,
		CompletedAt:      now.Add(time.Minute * 2),
		Duration:         120.0,
		CleanupResults: &CleanupResults{
			PathsRemoved:    []string{"/path/to/app"},
			PathsFailed:     []string{},
			RegistryRemoved: []string{"HKLM\\Software\\MyApp"},
			BytesFreed:      1024000,
		},
		SnapshotID: "snap-789",
	}

	if result.Status != UninstallStatusCompleted {
		t.Errorf("Status = %s, want completed", result.Status)
	}
	if result.CleanupResults == nil {
		t.Error("CleanupResults should not be nil")
	}
	if result.CleanupResults.BytesFreed != 1024000 {
		t.Errorf("BytesFreed = %d, want 1024000", result.CleanupResults.BytesFreed)
	}
	if result.SnapshotID != "snap-789" {
		t.Errorf("SnapshotID = %s, want snap-789", result.SnapshotID)
	}
}

func TestUninstallProgress(t *testing.T) {
	progress := UninstallProgress{
		UninstallationID: "uninstall-456",
		Status:           UninstallStatusCleaningUp,
		Output:           "Removing leftover files...",
		Phase:            "cleanup",
	}

	if progress.Phase != "cleanup" {
		t.Errorf("Phase = %s, want cleanup", progress.Phase)
	}
}

func TestFileLockInfo(t *testing.T) {
	lock := FileLockInfo{
		Path:     "/var/lib/app/data.db",
		Process:  "myapp",
		PID:      12345,
		LockType: "exclusive",
	}

	if lock.Path != "/var/lib/app/data.db" {
		t.Errorf("Path = %s, want /var/lib/app/data.db", lock.Path)
	}
	if lock.PID != 12345 {
		t.Errorf("PID = %d, want 12345", lock.PID)
	}
}

func TestFileLockResolution(t *testing.T) {
	resolution := FileLockResolution{
		Lock: FileLockInfo{
			Path:    "/var/lib/app/data.db",
			Process: "myapp",
			PID:     12345,
		},
		Strategy:  "terminate",
		ForceKill: true,
	}

	if resolution.Strategy != "terminate" {
		t.Errorf("Strategy = %s, want terminate", resolution.Strategy)
	}
	if !resolution.ForceKill {
		t.Error("ForceKill should be true")
	}
}

func TestSnapshot(t *testing.T) {
	now := time.Now()
	snapshot := Snapshot{
		ID:        "snap-123",
		CreatedAt: now,
		PackageInfo: map[string]string{
			"name":    "MyApp",
			"version": "1.0.0",
		},
		RegistryKeys: []string{"HKLM\\Software\\MyApp"},
		FilePaths:    []string{"/opt/myapp"},
		SnapshotPath: "/var/lib/slimrmm/snapshots/snap-123",
	}

	if snapshot.ID != "snap-123" {
		t.Errorf("ID = %s, want snap-123", snapshot.ID)
	}
	if snapshot.PackageInfo["name"] != "MyApp" {
		t.Errorf("PackageInfo[name] = %s, want MyApp", snapshot.PackageInfo["name"])
	}
	if len(snapshot.RegistryKeys) != 1 {
		t.Errorf("RegistryKeys length = %d, want 1", len(snapshot.RegistryKeys))
	}
}

func TestOperationLog(t *testing.T) {
	now := time.Now()
	log := OperationLog{
		Timestamp: now,
		Level:     "info",
		Message:   "Installation started",
		Details:   "Package: MyApp",
	}

	if log.Level != "info" {
		t.Errorf("Level = %s, want info", log.Level)
	}
	if log.Message != "Installation started" {
		t.Errorf("Message = %s, want 'Installation started'", log.Message)
	}
}
