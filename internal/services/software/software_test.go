package software

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/slimrmm/slimrmm-agent/internal/services/models"
)

// MockPlatformInstaller is a mock implementation of PlatformInstaller.
type MockPlatformInstaller struct {
	canHandle   bool
	isAvailable bool
	result      *models.InstallResult
	err         error
}

func (m *MockPlatformInstaller) CanHandle(installationType models.InstallationType) bool {
	return m.canHandle
}

func (m *MockPlatformInstaller) IsAvailable() bool {
	return m.isAvailable
}

func (m *MockPlatformInstaller) Install(ctx context.Context, req *models.InstallRequest) (*models.InstallResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

// MockPlatformUninstaller is a mock implementation of PlatformUninstaller.
type MockPlatformUninstaller struct {
	canHandle   bool
	isAvailable bool
	result      *models.UninstallResult
	err         error
}

func (m *MockPlatformUninstaller) CanHandle(installationType models.InstallationType) bool {
	return m.canHandle
}

func (m *MockPlatformUninstaller) IsAvailable() bool {
	return m.isAvailable
}

func (m *MockPlatformUninstaller) Uninstall(ctx context.Context, req *models.UninstallRequest) (*models.UninstallResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

func (m *MockPlatformUninstaller) Cleanup(ctx context.Context, req *models.UninstallRequest) (*models.CleanupResults, error) {
	return &models.CleanupResults{}, nil
}

func getTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNewInstallationService(t *testing.T) {
	logger := getTestLogger()
	svc := NewInstallationService(logger)

	if svc == nil {
		t.Fatal("NewInstallationService returned nil")
	}
	if svc.logger == nil {
		t.Error("logger should be set")
	}
	if svc.installations == nil {
		t.Error("installations map should be initialized")
	}
}

func TestNewInstallationServiceWithInstallers(t *testing.T) {
	logger := getTestLogger()
	mock := &MockPlatformInstaller{canHandle: true, isAvailable: true}
	svc := NewInstallationService(logger, mock)

	if svc == nil {
		t.Fatal("NewInstallationService returned nil")
	}
	if len(svc.installers) != 1 {
		t.Errorf("len(installers) = %d, want 1", len(svc.installers))
	}
}

func TestSetProgressCallback(t *testing.T) {
	logger := getTestLogger()
	svc := NewInstallationService(logger)

	svc.SetProgressCallback(func(progress interface{}) {
		_ = progress
	})

	if svc.progressCallback == nil {
		t.Error("progressCallback should be set")
	}
}

func TestInstallNoInstallationID(t *testing.T) {
	logger := getTestLogger()
	svc := NewInstallationService(logger)
	ctx := context.Background()

	req := &models.InstallRequest{
		InstallationType: models.InstallationTypeWinget,
		PackageID:        "test-package",
	}

	_, err := svc.Install(ctx, req)
	if err == nil {
		t.Error("Install should fail without installation_id")
	}
}

func TestInstallNoInstallerAvailable(t *testing.T) {
	logger := getTestLogger()
	svc := NewInstallationService(logger)
	ctx := context.Background()

	req := &models.InstallRequest{
		InstallationID:   "test-install-1",
		InstallationType: models.InstallationTypeWinget,
		PackageID:        "test-package",
	}

	result, err := svc.Install(ctx, req)
	if err != nil {
		t.Fatalf("Install returned unexpected error: %v", err)
	}
	if result.Status != models.StatusFailed {
		t.Errorf("Status = %s, want failed", result.Status)
	}
	if result.Error == "" {
		t.Error("Error should be set when no installer available")
	}
}

func TestInstallWithMockInstaller(t *testing.T) {
	logger := getTestLogger()
	mock := &MockPlatformInstaller{
		canHandle:   true,
		isAvailable: true,
		result: &models.InstallResult{
			InstallationID: "test-install-1",
			Status:         models.StatusCompleted,
		},
	}
	svc := NewInstallationService(logger, mock)
	ctx := context.Background()

	req := &models.InstallRequest{
		InstallationID:   "test-install-1",
		InstallationType: models.InstallationTypeWinget,
		PackageID:        "test-package",
		TimeoutSeconds:   60,
	}

	result, err := svc.Install(ctx, req)
	if err != nil {
		t.Fatalf("Install failed: %v", err)
	}
	if result.Status != models.StatusCompleted {
		t.Errorf("Status = %s, want completed", result.Status)
	}
}

func TestIsInstalling(t *testing.T) {
	logger := getTestLogger()
	svc := NewInstallationService(logger)

	// Not installing yet
	if svc.IsInstalling("nonexistent") {
		t.Error("should not be installing non-existent installation")
	}
}

func TestGetInstallationStatusNotFound(t *testing.T) {
	logger := getTestLogger()
	svc := NewInstallationService(logger)
	ctx := context.Background()

	_, err := svc.GetInstallationStatus(ctx, "nonexistent")
	if err == nil {
		t.Error("GetInstallationStatus should fail for non-existent installation")
	}
}

func TestCancelInstallationNotFound(t *testing.T) {
	logger := getTestLogger()
	svc := NewInstallationService(logger)
	ctx := context.Background()

	err := svc.CancelInstallation(ctx, "nonexistent")
	if err == nil {
		t.Error("CancelInstallation should fail for non-existent installation")
	}
}

func TestServicesStruct(t *testing.T) {
	services := Services{
		Installation:   nil,
		Uninstallation: nil,
		FileLock:       nil,
	}

	if services.Installation != nil {
		t.Error("Installation should be nil")
	}
}

func TestProgressCallbackType(t *testing.T) {
	var callback ProgressCallback = func(progress interface{}) {
		_ = progress
	}
	if callback == nil {
		t.Error("callback should not be nil")
	}
}

func TestInstallationServiceInterface(t *testing.T) {
	logger := getTestLogger()
	svc := NewInstallationService(logger)

	// Verify it implements InstallationService
	var _ InstallationService = svc
}

func TestUninstallationServiceInterface(t *testing.T) {
	logger := getTestLogger()
	svc := NewUninstallationService(logger, nil, nil)

	// Verify it implements UninstallationService
	var _ UninstallationService = svc
}

func TestMockPlatformInstaller(t *testing.T) {
	mock := &MockPlatformInstaller{
		canHandle:   true,
		isAvailable: true,
	}

	if !mock.CanHandle(models.InstallationTypeWinget) {
		t.Error("CanHandle should return true")
	}
	if !mock.IsAvailable() {
		t.Error("IsAvailable should return true")
	}
}

func TestMockPlatformInstallerNot(t *testing.T) {
	mock := &MockPlatformInstaller{
		canHandle:   false,
		isAvailable: false,
	}

	if mock.CanHandle(models.InstallationTypeWinget) {
		t.Error("CanHandle should return false")
	}
	if mock.IsAvailable() {
		t.Error("IsAvailable should return false")
	}
}
