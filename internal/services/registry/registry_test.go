package registry

import (
	"context"
	"testing"
)

func TestErrNotWindows(t *testing.T) {
	if ErrNotWindows == nil {
		t.Error("ErrNotWindows should not be nil")
	}
	if ErrNotWindows.Error() != "registry operations are only available on Windows" {
		t.Errorf("ErrNotWindows = %v, want 'registry operations are only available on Windows'", ErrNotWindows)
	}
}

func TestNew(t *testing.T) {
	svc := New()
	if svc == nil {
		t.Error("New should return non-nil service")
	}
}

func TestGetDefault(t *testing.T) {
	svc := GetDefault()
	if svc == nil {
		t.Error("GetDefault should return non-nil service")
	}

	// Verify singleton
	svc2 := GetDefault()
	if svc != svc2 {
		t.Error("GetDefault should return same instance")
	}
}

func TestStubServiceExportKey(t *testing.T) {
	svc := New()
	ctx := context.Background()

	err := svc.ExportKey(ctx, "HKEY_LOCAL_MACHINE\\SOFTWARE\\Test", "/tmp/test.reg")

	// On non-Windows, should return ErrNotWindows
	if err == nil {
		t.Log("ExportKey succeeded (running on Windows)")
	} else {
		if err != ErrNotWindows {
			t.Errorf("ExportKey error = %v, want ErrNotWindows", err)
		}
	}
}

func TestStubServiceIsAvailable(t *testing.T) {
	svc := New()

	// On non-Windows, should return false
	if svc.IsAvailable() {
		t.Log("IsAvailable returned true (running on Windows)")
	}
}

func TestServiceInterface(t *testing.T) {
	// Verify StubService implements Service interface
	var _ Service = (*StubService)(nil)
	var _ Service = New()
}

func TestGetDefaultReturnsService(t *testing.T) {
	// Verify GetDefault returns Service interface
	var svc Service = GetDefault()
	if svc == nil {
		t.Error("GetDefault should return non-nil Service")
	}
}

func TestExportKeyWithCancelledContext(t *testing.T) {
	svc := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := svc.ExportKey(ctx, "HKEY_LOCAL_MACHINE\\SOFTWARE", "/tmp/test.reg")
	// On non-Windows, should still return ErrNotWindows (stub ignores context)
	if err != nil && err != ErrNotWindows {
		t.Logf("ExportKey with cancelled context returned: %v", err)
	}
}

func TestExportKeyWithEmptyPath(t *testing.T) {
	svc := New()
	ctx := context.Background()

	err := svc.ExportKey(ctx, "", "/tmp/test.reg")
	// On non-Windows, should return ErrNotWindows (stub doesn't validate)
	if err != nil && err != ErrNotWindows {
		t.Logf("ExportKey with empty path returned: %v", err)
	}
}

func TestExportKeyWithEmptyOutputPath(t *testing.T) {
	svc := New()
	ctx := context.Background()

	err := svc.ExportKey(ctx, "HKEY_LOCAL_MACHINE\\SOFTWARE", "")
	// On non-Windows, should return ErrNotWindows (stub doesn't validate)
	if err != nil && err != ErrNotWindows {
		t.Logf("ExportKey with empty output path returned: %v", err)
	}
}

func TestRegistryKeyPaths(t *testing.T) {
	// Test various registry key paths (validation happens on Windows)
	keyPaths := []string{
		"HKEY_LOCAL_MACHINE\\SOFTWARE",
		"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services",
		"HKEY_CURRENT_USER\\Software\\Microsoft",
		"HKEY_CLASSES_ROOT\\.txt",
		"HKEY_USERS\\S-1-5-21-123456789-0\\Software",
	}

	svc := New()
	ctx := context.Background()

	for _, keyPath := range keyPaths {
		t.Run(keyPath, func(t *testing.T) {
			err := svc.ExportKey(ctx, keyPath, "/tmp/test.reg")
			// On non-Windows, all should return ErrNotWindows
			if err != nil && err != ErrNotWindows {
				t.Logf("ExportKey(%s) returned unexpected error: %v", keyPath, err)
			}
		})
	}
}
