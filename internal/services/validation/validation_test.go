package validation

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestValidationResult(t *testing.T) {
	result := ValidationResult{
		IsInstalled:         true,
		CurrentVersion:      "1.0.0",
		InstallLocation:     "/opt/myapp",
		Dependencies:        []string{"lib1", "lib2"},
		DependentPackages:   []string{},
		RunningProcesses:    []ProcessInfo{{Name: "myapp", PID: 1234}},
		FileLocks:           []FileLock{},
		EstimatedSpaceBytes: 1024000,
		InstallType:         "deb",
		PackageManager:      "apt",
		Warnings:            []string{},
		Errors:              []string{},
	}

	if !result.IsInstalled {
		t.Error("IsInstalled should be true")
	}
	if result.CurrentVersion != "1.0.0" {
		t.Errorf("CurrentVersion = %s, want 1.0.0", result.CurrentVersion)
	}
	if len(result.RunningProcesses) != 1 {
		t.Errorf("RunningProcesses length = %d, want 1", len(result.RunningProcesses))
	}
}

func TestProcessInfo(t *testing.T) {
	proc := ProcessInfo{
		Name: "myapp",
		PID:  1234,
		User: "root",
		CPU:  "5%",
		Mem:  "10%",
	}

	if proc.Name != "myapp" {
		t.Errorf("Name = %s, want myapp", proc.Name)
	}
	if proc.PID != 1234 {
		t.Errorf("PID = %d, want 1234", proc.PID)
	}
}

func TestFileLock(t *testing.T) {
	lock := FileLock{
		Path:    "/var/lib/myapp/data.db",
		Process: "myapp",
		PID:     5678,
		Type:    "exclusive",
	}

	if lock.Path != "/var/lib/myapp/data.db" {
		t.Error("Path not set correctly")
	}
	if lock.Type != "exclusive" {
		t.Error("Type not set correctly")
	}
}

func TestValidationRequest(t *testing.T) {
	req := ValidationRequest{
		InstallationType:  "winget",
		PackageIdentifier: "Microsoft.VSCode",
		WingetPackageID:   "Microsoft.VisualStudioCode",
		CaskName:          "",
	}

	if req.InstallationType != "winget" {
		t.Error("InstallationType not set correctly")
	}
}

func TestDependencyAnalysis(t *testing.T) {
	analysis := DependencyAnalysis{
		Dependencies: []DependencyInfo{
			{Name: "libc6", Version: "2.35", Type: "required"},
		},
		DependentPackages: []DependencyInfo{},
		SafeToUninstall:   true,
		Warnings:          []string{},
	}

	if !analysis.SafeToUninstall {
		t.Error("SafeToUninstall should be true")
	}
	if len(analysis.Dependencies) != 1 {
		t.Error("Dependencies length should be 1")
	}
}

func TestStopServicesRequest(t *testing.T) {
	req := StopServicesRequest{
		Services:       []string{"myapp", "myapp-helper"},
		ForceKill:      true,
		TimeoutSeconds: 30,
	}

	if len(req.Services) != 2 {
		t.Error("Services should have 2 entries")
	}
	if !req.ForceKill {
		t.Error("ForceKill should be true")
	}
}

func TestStopServicesResult(t *testing.T) {
	result := StopServicesResult{
		StoppedServices: []string{"myapp"},
		FailedServices:  []string{"myapp-helper"},
		Errors:          []string{"myapp-helper: permission denied"},
	}

	if len(result.StoppedServices) != 1 {
		t.Error("StoppedServices should have 1 entry")
	}
	if len(result.FailedServices) != 1 {
		t.Error("FailedServices should have 1 entry")
	}
}

// MockValidator is a test validator
type MockValidator struct {
	canHandle   bool
	isAvailable bool
	result      *ValidationResult
	err         error
}

func (m *MockValidator) CanHandle(installationType string) bool {
	return m.canHandle
}

func (m *MockValidator) IsAvailable() bool {
	return m.isAvailable
}

func (m *MockValidator) Validate(ctx context.Context, req *ValidationRequest) (*ValidationResult, error) {
	return m.result, m.err
}

func TestNewValidationService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	validator := &MockValidator{canHandle: true, isAvailable: true}

	service := NewValidationService(logger, validator)
	if service == nil {
		t.Fatal("NewValidationService returned nil")
	}
	if len(service.validators) != 1 {
		t.Errorf("validators length = %d, want 1", len(service.validators))
	}
}

func TestValidationServiceValidate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	expectedResult := &ValidationResult{
		IsInstalled:    true,
		CurrentVersion: "1.0.0",
	}

	validator := &MockValidator{
		canHandle:   true,
		isAvailable: true,
		result:      expectedResult,
		err:         nil,
	}

	service := NewValidationService(logger, validator)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &ValidationRequest{
		InstallationType:  "test",
		PackageIdentifier: "test-pkg",
	}

	result, err := service.Validate(ctx, req)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if !result.IsInstalled {
		t.Error("IsInstalled should be true")
	}
	if result.CurrentVersion != "1.0.0" {
		t.Error("CurrentVersion should be 1.0.0")
	}
}

func TestValidationServiceNoValidator(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Validator that can't handle the request
	validator := &MockValidator{
		canHandle:   false,
		isAvailable: true,
	}

	service := NewValidationService(logger, validator)

	ctx := context.Background()
	req := &ValidationRequest{
		InstallationType:  "unsupported",
		PackageIdentifier: "test-pkg",
	}

	_, err := service.Validate(ctx, req)
	if err == nil {
		t.Error("Validate should fail when no validator available")
	}
}

func TestValidationServiceUnavailableValidator(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Validator that can handle but is not available
	validator := &MockValidator{
		canHandle:   true,
		isAvailable: false,
	}

	service := NewValidationService(logger, validator)

	ctx := context.Background()
	req := &ValidationRequest{
		InstallationType:  "test",
		PackageIdentifier: "test-pkg",
	}

	_, err := service.Validate(ctx, req)
	if err == nil {
		t.Error("Validate should fail when validator is unavailable")
	}
}

func TestAnalyzeDependencies(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	service := NewValidationService(logger)

	ctx := context.Background()

	tests := []struct {
		name             string
		installationType string
		packageID        string
	}{
		{"homebrew_cask", "homebrew_cask", "visual-studio-code"},
		{"winget", "winget", "Microsoft.VSCode"},
		{"msi", "msi", "{12345}"},
		{"pkg", "pkg", "myapp.pkg"},
		{"deb", "deb", "mypackage"},
		{"rpm", "rpm", "mypackage"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.AnalyzeDependencies(ctx, tt.installationType, tt.packageID)
			if err != nil {
				t.Fatalf("AnalyzeDependencies failed: %v", err)
			}

			if result == nil {
				t.Fatal("result should not be nil")
			}

			// These types typically don't have dependencies or are safe to uninstall
			if tt.installationType == "homebrew_cask" || tt.installationType == "winget" ||
				tt.installationType == "msi" || tt.installationType == "pkg" {
				if !result.SafeToUninstall {
					t.Error("SafeToUninstall should be true for this type")
				}
			}
		})
	}
}

func TestStopServices(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	service := NewValidationService(logger)

	ctx := context.Background()

	req := &StopServicesRequest{
		Services:       []string{"nonexistent-service-12345"},
		ForceKill:      false,
		TimeoutSeconds: 5,
	}

	result, err := service.StopServices(ctx, req)
	if err != nil {
		t.Fatalf("StopServices failed: %v", err)
	}

	// The nonexistent service should fail to stop
	if len(result.FailedServices) != 1 {
		t.Logf("FailedServices: %v, StoppedServices: %v", result.FailedServices, result.StoppedServices)
	}
}

func TestDependencyInfo(t *testing.T) {
	info := DependencyInfo{
		Name:    "libc6",
		Version: "2.35-0ubuntu3",
		Type:    "required",
	}

	if info.Name != "libc6" {
		t.Error("Name not set correctly")
	}
	if info.Version != "2.35-0ubuntu3" {
		t.Error("Version not set correctly")
	}
	if info.Type != "required" {
		t.Error("Type not set correctly")
	}
}
