package safecmd

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestOutputBasic(t *testing.T) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "echo", "hello")
	} else {
		cmd = exec.Command("echo", "hello")
	}

	cfg := DefaultConfig()
	out, err := Output(cmd, cfg)
	if err != nil {
		t.Fatalf("Output failed: %v", err)
	}

	expected := "hello"
	if !strings.Contains(string(out), expected) {
		t.Errorf("Output = %q, want %q", string(out), expected)
	}
}

func TestOutputSizeLimit(t *testing.T) {
	// Generate output that exceeds the limit
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// Windows: use PowerShell to generate large output
		cmd = exec.Command("powershell", "-Command", "'A' * 2000")
	} else {
		// Unix: use yes with head to generate large output
		cmd = exec.Command("bash", "-c", "yes | head -c 2000")
	}

	cfg := Config{MaxOutput: 100} // Very small limit
	out, err := Output(cmd, cfg)

	if !errors.Is(err, ErrOutputTooLarge) {
		t.Errorf("expected ErrOutputTooLarge, got %v", err)
	}

	// Should still return truncated output
	if len(out) > 100 {
		t.Errorf("Output length = %d, want <= 100", len(out))
	}
}

func TestCombinedOutput(t *testing.T) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "echo", "test")
	} else {
		cmd = exec.Command("echo", "test")
	}

	cfg := DefaultConfig()
	out, err := CombinedOutput(cmd, cfg)
	if err != nil {
		t.Fatalf("CombinedOutput failed: %v", err)
	}

	if !strings.Contains(string(out), "test") {
		t.Errorf("Output = %q, want to contain 'test'", string(out))
	}
}

func TestOutputWithContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/c", "echo", "context test")
	} else {
		cmd = exec.CommandContext(ctx, "echo", "context test")
	}

	cfg := DefaultConfig()
	out, err := OutputContext(ctx, cmd, cfg)
	if err != nil {
		t.Fatalf("OutputContext failed: %v", err)
	}

	if !strings.Contains(string(out), "context test") {
		t.Errorf("Output = %q, want to contain 'context test'", string(out))
	}
}

func TestOutputContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "powershell", "-Command", "Start-Sleep -Seconds 10")
	} else {
		cmd = exec.CommandContext(ctx, "sleep", "10")
	}

	// Cancel immediately
	cancel()

	cfg := DefaultConfig()
	_, err := OutputContext(ctx, cmd, cfg)

	if err == nil {
		t.Error("expected error from cancelled context")
	}
}

func TestOutputString(t *testing.T) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "echo", "string test")
	} else {
		cmd = exec.Command("echo", "string test")
	}

	cfg := DefaultConfig()
	out, err := OutputString(cmd, cfg)
	if err != nil {
		t.Fatalf("OutputString failed: %v", err)
	}

	if !strings.Contains(out, "string test") {
		t.Errorf("Output = %q, want to contain 'string test'", out)
	}
}

func TestRun(t *testing.T) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "echo", "stdout message")
	} else {
		cmd = exec.Command("bash", "-c", "echo stdout message; echo stderr message >&2")
	}

	cfg := DefaultConfig()
	stdout, stderr, err := Run(cmd, cfg)

	// On Windows, stderr test is harder, so just check stdout
	if err != nil && runtime.GOOS != "windows" {
		t.Fatalf("Run failed: %v", err)
	}

	if !strings.Contains(string(stdout), "stdout") {
		t.Errorf("stdout = %q, want to contain 'stdout'", string(stdout))
	}

	// stderr check only on Unix
	if runtime.GOOS != "windows" {
		if !strings.Contains(string(stderr), "stderr") {
			t.Errorf("stderr = %q, want to contain 'stderr'", string(stderr))
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.MaxOutput != DefaultMaxOutputSize {
		t.Errorf("MaxOutput = %d, want %d", cfg.MaxOutput, DefaultMaxOutputSize)
	}
}

func TestConfigLimits(t *testing.T) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "echo", "test")
	} else {
		cmd = exec.Command("echo", "test")
	}

	// Test that MaxOutput is capped
	cfg := Config{MaxOutput: MaxOutputSize * 2}
	_, err := Output(cmd, cfg)
	if err != nil {
		t.Fatalf("Output failed: %v", err)
	}

	// Test that zero/negative MaxOutput uses default
	cmd = exec.Command("echo", "test")
	cfg = Config{MaxOutput: 0}
	_, err = Output(cmd, cfg)
	if err != nil {
		t.Fatalf("Output with zero MaxOutput failed: %v", err)
	}
}

func TestCommandFailure(t *testing.T) {
	// Test a command that fails
	cmd := exec.Command("nonexistent-command-12345")

	cfg := DefaultConfig()
	_, err := Output(cmd, cfg)

	if err == nil {
		t.Error("expected error for nonexistent command")
	}
}

func BenchmarkOutput(b *testing.B) {
	cfg := DefaultConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("cmd", "/c", "echo", "benchmark")
		} else {
			cmd = exec.Command("echo", "benchmark")
		}
		Output(cmd, cfg)
	}
}
