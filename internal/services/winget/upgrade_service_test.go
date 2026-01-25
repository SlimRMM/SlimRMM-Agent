package winget

import (
	"os/exec"
	"testing"
)

func TestNewUpgradeService(t *testing.T) {
	service := NewUpgradeService(nil)
	if service == nil {
		t.Fatal("NewUpgradeService returned nil")
	}
}

func TestEvaluateExitStatus(t *testing.T) {
	service := NewUpgradeService(nil)

	tests := []struct {
		name       string
		err        error
		wantStatus string
		wantError  bool
	}{
		{
			name:       "nil error",
			err:        nil,
			wantStatus: "success",
			wantError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, errMsg := service.evaluateExitStatus(tt.err)
			if status != tt.wantStatus {
				t.Errorf("status = %s, want %s", status, tt.wantStatus)
			}
			if tt.wantError && errMsg == "" {
				t.Error("expected error message")
			}
			if !tt.wantError && errMsg != "" {
				t.Errorf("unexpected error message: %s", errMsg)
			}
		})
	}
}

func TestIsPackageNotFoundError(t *testing.T) {
	service := NewUpgradeService(nil)

	tests := []struct {
		name   string
		result *UpgradeResult
		want   bool
	}{
		{
			name:   "no installed package in output",
			result: &UpgradeResult{Output: "Error: No installed package found matching input criteria."},
			want:   true,
		},
		{
			name:   "success result",
			result: &UpgradeResult{Output: "Successfully installed", ExitCode: 0},
			want:   false,
		},
		{
			name:   "empty result",
			result: &UpgradeResult{},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.isPackageNotFoundError(tt.result)
			if result != tt.want {
				t.Errorf("isPackageNotFoundError() = %v, want %v", result, tt.want)
			}
		})
	}
}

func TestUpgradeConfig(t *testing.T) {
	config := UpgradeConfig{
		PackageID:       "Microsoft.WindowsTerminal",
		PackageName:     "Windows Terminal",
		TimeoutSeconds:  300,
		TryUserContext:  true,
		FallbackSystem:  true,
	}

	if config.PackageID != "Microsoft.WindowsTerminal" {
		t.Errorf("PackageID = %s, want Microsoft.WindowsTerminal", config.PackageID)
	}
	if config.TimeoutSeconds != 300 {
		t.Errorf("TimeoutSeconds = %d, want 300", config.TimeoutSeconds)
	}
}

func TestUpgradeResult(t *testing.T) {
	result := &UpgradeResult{
		PackageID:   "test.package",
		PackageName: "Test Package",
		OldVersion:  "1.0.0",
		NewVersion:  "2.0.0",
		Status:      "success",
		Context:     "system",
	}

	if result.PackageID != "test.package" {
		t.Errorf("PackageID = %s, want test.package", result.PackageID)
	}
	if result.Status != "success" {
		t.Errorf("Status = %s, want success", result.Status)
	}
}

func TestEvaluateExitStatusWithExitError(t *testing.T) {
	service := NewUpgradeService(nil)

	// Create a fake exit error - we can't easily test this without running a command
	// Just test that the function handles errors gracefully
	err := exec.Command("false").Run() // This will give us an exit error
	if err != nil {
		status, errMsg := service.evaluateExitStatus(err)
		if status != "failed" {
			t.Errorf("status = %s, want failed", status)
		}
		if errMsg == "" {
			t.Error("expected error message for failed command")
		}
	}
}
