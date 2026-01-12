package antireplay

import (
	"testing"
	"time"
)

func TestProtector(t *testing.T) {
	cfg := Config{
		MaxAge:          time.Minute,
		FutureWindow:    10 * time.Second,
		MaxCacheSize:    100,
		CleanupInterval: time.Second,
	}

	p := New(cfg)
	defer p.Stop()

	// First request should succeed
	err := p.ValidateRequest("req-001", time.Now())
	if err != nil {
		t.Errorf("first request should succeed: %v", err)
	}

	// Same request ID should fail (replay)
	err = p.ValidateRequest("req-001", time.Now())
	if err == nil {
		t.Error("duplicate request should fail")
	}
	if !IsReplayError(err) {
		t.Errorf("should be a replay error: %v", err)
	}

	// Different request ID should succeed
	err = p.ValidateRequest("req-002", time.Now())
	if err != nil {
		t.Errorf("different request should succeed: %v", err)
	}
}

func TestTimestampExpired(t *testing.T) {
	cfg := Config{
		MaxAge:          time.Second,
		FutureWindow:    time.Second,
		MaxCacheSize:    100,
		CleanupInterval: time.Hour, // Don't run cleanup during test
	}

	p := New(cfg)
	defer p.Stop()

	// Request with old timestamp should fail
	oldTime := time.Now().Add(-2 * time.Minute)
	err := p.ValidateRequest("old-req", oldTime)
	if err == nil {
		t.Error("expired timestamp should fail")
	}
	if !IsReplayError(err) {
		t.Errorf("should be a replay/timestamp error: %v", err)
	}
}

func TestTimestampFuture(t *testing.T) {
	cfg := Config{
		MaxAge:          time.Minute,
		FutureWindow:    time.Second,
		MaxCacheSize:    100,
		CleanupInterval: time.Hour,
	}

	p := New(cfg)
	defer p.Stop()

	// Request with future timestamp should fail
	futureTime := time.Now().Add(time.Minute)
	err := p.ValidateRequest("future-req", futureTime)
	if err == nil {
		t.Error("future timestamp should fail")
	}
}

func TestCacheSizeLimit(t *testing.T) {
	cfg := Config{
		MaxAge:          time.Hour,
		FutureWindow:    time.Second,
		MaxCacheSize:    5,
		CleanupInterval: time.Hour,
	}

	p := New(cfg)
	defer p.Stop()

	// Add more than MaxCacheSize requests
	for i := 0; i < 10; i++ {
		p.ValidateRequest("req-"+string(rune('A'+i)), time.Now())
	}

	// Cache should not exceed max size
	stats := p.Stats()
	if stats["cached_requests"].(int) > cfg.MaxCacheSize {
		t.Error("cache exceeded max size")
	}
}

func TestCleanup(t *testing.T) {
	cfg := Config{
		MaxAge:          100 * time.Millisecond,
		FutureWindow:    time.Second,
		MaxCacheSize:    100,
		CleanupInterval: 50 * time.Millisecond,
	}

	p := New(cfg)
	defer p.Stop()

	// Add requests
	for i := 0; i < 5; i++ {
		p.ValidateRequest("cleanup-"+string(rune('A'+i)), time.Now())
	}

	// Wait for expiry and cleanup
	time.Sleep(300 * time.Millisecond)

	// Old request IDs should now be accepted (cleared from cache)
	err := p.ValidateRequest("cleanup-A", time.Now())
	if err != nil {
		t.Errorf("should accept after cleanup: %v", err)
	}
}

func TestIsReplayError(t *testing.T) {
	tests := []struct {
		err    error
		isReplay bool
	}{
		{ErrReplayDetected, true},
		{ErrTimestampExpired, true},
		{ErrTimestampFuture, true},
		{ErrInvalidSignature, false},
		{nil, false},
	}

	for _, tt := range tests {
		got := IsReplayError(tt.err)
		if got != tt.isReplay {
			t.Errorf("IsReplayError(%v) = %v, want %v", tt.err, got, tt.isReplay)
		}
	}
}
