package selfhealing

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.ConnectionTimeout != DefaultConnectionTimeout {
		t.Errorf("ConnectionTimeout = %v, want %v", cfg.ConnectionTimeout, DefaultConnectionTimeout)
	}
	if cfg.HealthCheckInterval != DefaultHealthCheckInterval {
		t.Errorf("HealthCheckInterval = %v, want %v", cfg.HealthCheckInterval, DefaultHealthCheckInterval)
	}
	if !cfg.Enabled {
		t.Error("Enabled should default to true")
	}
}

func TestNew(t *testing.T) {
	cfg := DefaultConfig()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	w := New(cfg, logger)
	if w == nil {
		t.Fatal("New returned nil")
	}
	if w.logger != logger {
		t.Error("logger not set correctly")
	}

	// Check initial connection time is set
	lastConn := w.GetLastConnectionTime()
	if lastConn.IsZero() {
		t.Error("lastSuccessfulConnection should be initialized")
	}
}

func TestRecordConnectionSuccess(t *testing.T) {
	cfg := DefaultConfig()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	w := New(cfg, logger)

	before := w.GetLastConnectionTime()
	time.Sleep(10 * time.Millisecond)

	w.RecordConnectionSuccess()

	after := w.GetLastConnectionTime()
	if !after.After(before) {
		t.Error("last connection time should be updated")
	}

	if !w.isConnected.Load() {
		t.Error("isConnected should be true")
	}
}

func TestRecordConnectionFailure(t *testing.T) {
	cfg := DefaultConfig()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	w := New(cfg, logger)

	w.RecordConnectionSuccess()
	w.RecordConnectionFailure()

	if w.isConnected.Load() {
		t.Error("isConnected should be false after failure")
	}
}

func TestIsHealthy(t *testing.T) {
	cfg := Config{
		ConnectionTimeout:   100 * time.Millisecond,
		HealthCheckInterval: time.Second,
		Enabled:             true,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	w := New(cfg, logger)

	// Initially healthy
	if !w.IsHealthy() {
		t.Error("should be healthy initially")
	}

	// Wait for timeout to expire
	time.Sleep(150 * time.Millisecond)

	if w.IsHealthy() {
		t.Error("should be unhealthy after timeout")
	}

	// Record success
	w.RecordConnectionSuccess()
	if !w.IsHealthy() {
		t.Error("should be healthy after connection success")
	}
}

func TestStartDisabled(t *testing.T) {
	cfg := Config{Enabled: false}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	w := New(cfg, logger)

	ctx := context.Background()
	w.Start(ctx)

	// Should return immediately without starting goroutine
}

func TestStartAndStop(t *testing.T) {
	cfg := Config{
		ConnectionTimeout:   time.Hour,
		HealthCheckInterval: 50 * time.Millisecond,
		Enabled:             true,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	w := New(cfg, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w.Start(ctx)

	// Let it run for a bit
	time.Sleep(100 * time.Millisecond)

	// Stop should complete
	done := make(chan struct{})
	go func() {
		w.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Good
	case <-time.After(time.Second):
		t.Error("Stop should complete quickly")
	}
}

func TestStartWithContextCancel(t *testing.T) {
	cfg := Config{
		ConnectionTimeout:   time.Hour,
		HealthCheckInterval: 50 * time.Millisecond,
		Enabled:             true,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	w := New(cfg, logger)

	ctx, cancel := context.WithCancel(context.Background())
	w.Start(ctx)

	// Cancel context
	cancel()

	// Wait for goroutine to stop
	w.wg.Wait()
}

func TestGetLastConnectionTime(t *testing.T) {
	cfg := DefaultConfig()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	w := New(cfg, logger)

	t1 := w.GetLastConnectionTime()

	time.Sleep(10 * time.Millisecond)
	w.RecordConnectionSuccess()

	t2 := w.GetLastConnectionTime()
	if !t2.After(t1) {
		t.Error("connection time should be updated")
	}
}

func TestConstants(t *testing.T) {
	if DefaultConnectionTimeout != 30*time.Minute {
		t.Errorf("DefaultConnectionTimeout = %v, want 30 minutes", DefaultConnectionTimeout)
	}
	if DefaultHealthCheckInterval != time.Minute {
		t.Errorf("DefaultHealthCheckInterval = %v, want 1 minute", DefaultHealthCheckInterval)
	}
	if RestartCooldown != 5*time.Minute {
		t.Errorf("RestartCooldown = %v, want 5 minutes", RestartCooldown)
	}
	if MaxConsecutiveRestarts != 3 {
		t.Errorf("MaxConsecutiveRestarts = %d, want 3", MaxConsecutiveRestarts)
	}
}

func TestConsecutiveRestartReset(t *testing.T) {
	cfg := DefaultConfig()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	w := New(cfg, logger)

	// Simulate some restart attempts
	w.mu.Lock()
	w.consecutiveRestarts = 2
	w.mu.Unlock()

	// Record success should reset counter
	w.RecordConnectionSuccess()

	w.mu.Lock()
	count := w.consecutiveRestarts
	w.mu.Unlock()

	if count != 0 {
		t.Errorf("consecutiveRestarts = %d, want 0 after success", count)
	}
}

func TestCheckHealthNoRestart(t *testing.T) {
	cfg := Config{
		ConnectionTimeout:   time.Hour, // Long timeout
		HealthCheckInterval: time.Second,
		Enabled:             true,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	w := New(cfg, logger)

	// Should not trigger restart
	w.checkHealth()

	// Verify no restart was triggered
	w.mu.Lock()
	restarts := w.consecutiveRestarts
	w.mu.Unlock()

	if restarts != 0 {
		t.Errorf("consecutiveRestarts = %d, should be 0", restarts)
	}
}

func TestTriggerRestartCooldown(t *testing.T) {
	cfg := DefaultConfig()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	w := New(cfg, logger)

	// Set recent restart time
	w.mu.Lock()
	w.lastRestartAttempt = time.Now()
	w.mu.Unlock()

	// This should be skipped due to cooldown
	w.triggerRestart("test")

	w.mu.Lock()
	restarts := w.consecutiveRestarts
	w.mu.Unlock()

	if restarts != 0 {
		t.Error("restart should be skipped due to cooldown")
	}
}

func TestTriggerRestartMaxAttempts(t *testing.T) {
	cfg := DefaultConfig()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	w := New(cfg, logger)

	// Set max restarts reached
	w.mu.Lock()
	w.consecutiveRestarts = MaxConsecutiveRestarts
	w.lastRestartAttempt = time.Now().Add(-10 * time.Minute) // Past cooldown
	w.mu.Unlock()

	// This should be skipped due to max attempts
	w.triggerRestart("test")

	w.mu.Lock()
	restarts := w.consecutiveRestarts
	w.mu.Unlock()

	// Should not have incremented
	if restarts != MaxConsecutiveRestarts {
		t.Error("restart should be skipped due to max attempts")
	}
}

func TestWrapWithRecovery(t *testing.T) {
	cfg := DefaultConfig()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	w := New(cfg, logger)

	var executed atomic.Bool
	fn := w.WrapWithRecovery("test", func() {
		executed.Store(true)
	})

	fn()

	if !executed.Load() {
		t.Error("wrapped function should be executed")
	}
}

func TestRecoverFromPanicNoError(t *testing.T) {
	cfg := DefaultConfig()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	w := New(cfg, logger)

	var executed atomic.Bool
	w.RecoverFromPanic("test", func() {
		executed.Store(true)
	})

	if !executed.Load() {
		t.Error("function should be executed without panic")
	}
}

func TestConfigStruct(t *testing.T) {
	cfg := Config{
		ConnectionTimeout:   5 * time.Minute,
		HealthCheckInterval: 30 * time.Second,
		Enabled:             true,
	}

	if cfg.ConnectionTimeout != 5*time.Minute {
		t.Error("ConnectionTimeout not set correctly")
	}
	if cfg.HealthCheckInterval != 30*time.Second {
		t.Error("HealthCheckInterval not set correctly")
	}
	if !cfg.Enabled {
		t.Error("Enabled not set correctly")
	}
}
