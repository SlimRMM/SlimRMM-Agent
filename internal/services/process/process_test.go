package process

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

func TestProcessInfo(t *testing.T) {
	info := ProcessInfo{
		Name:    "test-process",
		PID:     1234,
		User:    "testuser",
		CPU:     "5.0",
		Mem:     "10.0",
		Command: "test-process --arg1",
	}

	if info.Name != "test-process" {
		t.Errorf("Name = %s, want test-process", info.Name)
	}
	if info.PID != 1234 {
		t.Errorf("PID = %d, want 1234", info.PID)
	}
	if info.User != "testuser" {
		t.Errorf("User = %s, want testuser", info.User)
	}
	if info.CPU != "5.0" {
		t.Errorf("CPU = %s, want 5.0", info.CPU)
	}
	if info.Mem != "10.0" {
		t.Errorf("Mem = %s, want 10.0", info.Mem)
	}
	if info.Command != "test-process --arg1" {
		t.Errorf("Command = %s, want test-process --arg1", info.Command)
	}
}

func TestSignalConstants(t *testing.T) {
	if SignalTerm != "TERM" {
		t.Errorf("SignalTerm = %s, want TERM", SignalTerm)
	}
	if SignalKill != "KILL" {
		t.Errorf("SignalKill = %s, want KILL", SignalKill)
	}
	if SignalInt != "INT" {
		t.Errorf("SignalInt = %s, want INT", SignalInt)
	}
}

func TestNewProcessService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewProcessService(logger)

	if svc == nil {
		t.Fatal("NewProcessService returned nil")
	}
	if svc.logger == nil {
		t.Error("logger should be set")
	}
}

func TestGetProcessInfoCurrentProcess(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewProcessService(logger)
	ctx := context.Background()

	// Get info for the current process - should always succeed
	pid := os.Getpid()
	info, err := svc.GetProcessInfo(ctx, pid)
	if err != nil {
		t.Fatalf("GetProcessInfo for current process failed: %v", err)
	}

	if info.PID != pid {
		t.Errorf("PID = %d, want %d", info.PID, pid)
	}
	if info.Name == "" {
		t.Error("Name should not be empty for current process")
	}
}

func TestGetProcessInfoNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewProcessService(logger)
	ctx := context.Background()

	// Use a PID that's very unlikely to exist
	_, err := svc.GetProcessInfo(ctx, 999999999)
	if err == nil {
		t.Error("GetProcessInfo should fail for non-existent PID")
	}
}

func TestIsProcessRunningCurrentProcess(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewProcessService(logger)
	ctx := context.Background()

	// Current process should always be running
	pid := os.Getpid()
	if !svc.IsProcessRunning(ctx, pid) {
		t.Error("current process should be running")
	}
}

func TestIsProcessRunningNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewProcessService(logger)
	ctx := context.Background()

	// Non-existent process should not be running
	if svc.IsProcessRunning(ctx, 999999999) {
		t.Error("non-existent process should not be running")
	}
}

func TestGetProcessTree(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewProcessService(logger)
	ctx := context.Background()

	// Get process tree for current process - should not error
	pid := os.Getpid()
	children, err := svc.GetProcessTree(ctx, pid)
	if err != nil {
		t.Fatalf("GetProcessTree failed: %v", err)
	}

	// Result can be empty if no children, but shouldn't error
	_ = children
}

func TestGetProcessTreeNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewProcessService(logger)
	ctx := context.Background()

	// Non-existent process - should return empty list
	children, err := svc.GetProcessTree(ctx, 999999999)
	if err != nil {
		t.Fatalf("GetProcessTree should not error: %v", err)
	}
	if len(children) > 0 {
		t.Error("non-existent process should have no children")
	}
}

func TestSendSignalNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewProcessService(logger)
	ctx := context.Background()

	// Send signal to non-existent process - should error
	err := svc.SendSignal(ctx, 999999999, SignalTerm)
	if err == nil {
		t.Error("SendSignal should fail for non-existent PID")
	}
}

func TestProcessServiceInterface(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewProcessService(logger)

	// Verify it implements ProcessService interface
	var _ ProcessService = svc
}

func TestKillProcessNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewProcessService(logger)
	ctx := context.Background()

	// Kill non-existent process - should error
	err := svc.KillProcess(ctx, 999999999, false)
	if err == nil {
		t.Error("KillProcess should fail for non-existent PID")
	}
}

func TestKillProcessTreeNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewProcessService(logger)
	ctx := context.Background()

	// Kill tree for non-existent process - should error
	err := svc.KillProcessTree(ctx, 999999999, false)
	if err == nil {
		t.Error("KillProcessTree should fail for non-existent PID")
	}
}

func TestProcessInfoWithZeroValues(t *testing.T) {
	// Test default zero values
	var info ProcessInfo

	if info.Name != "" {
		t.Error("default Name should be empty")
	}
	if info.PID != 0 {
		t.Error("default PID should be 0")
	}
	if info.User != "" {
		t.Error("default User should be empty")
	}
}

func TestSignalType(t *testing.T) {
	// Verify Signal is a string type
	var s Signal = "CUSTOM"
	if s != "CUSTOM" {
		t.Error("Signal should support custom values")
	}
}
