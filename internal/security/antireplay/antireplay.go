// Package antireplay provides protection against message replay attacks.
// It tracks seen request IDs and timestamps to prevent replay attacks.
package antireplay

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrReplayDetected indicates a potential replay attack.
	ErrReplayDetected = errors.New("replay attack detected: request already processed")

	// ErrTimestampExpired indicates the request timestamp is too old.
	ErrTimestampExpired = errors.New("request timestamp expired")

	// ErrTimestampFuture indicates the request timestamp is in the future.
	ErrTimestampFuture = errors.New("request timestamp is in the future")

	// ErrInvalidSignature indicates message signature verification failed.
	ErrInvalidSignature = errors.New("invalid message signature")
)

// Config holds anti-replay configuration.
type Config struct {
	// MaxAge is the maximum age of a valid request.
	MaxAge time.Duration

	// FutureWindow allows for small clock skew.
	FutureWindow time.Duration

	// MaxCacheSize is the maximum number of request IDs to cache.
	MaxCacheSize int

	// CleanupInterval is how often to clean old entries.
	CleanupInterval time.Duration

	// RequireSignature requires HMAC signature validation.
	RequireSignature bool

	// SignatureKey is the secret key for HMAC (derived from mTLS cert).
	SignatureKey []byte
}

// DefaultConfig returns secure default configuration.
func DefaultConfig() Config {
	return Config{
		MaxAge:          5 * time.Minute,  // Requests valid for 5 minutes
		FutureWindow:    30 * time.Second, // Allow 30s clock skew
		MaxCacheSize:    10000,            // Cache up to 10k request IDs
		CleanupInterval: time.Minute,      // Cleanup every minute
		RequireSignature: false,           // Disabled by default (mTLS provides auth)
	}
}

// seenRequest tracks a seen request ID.
type seenRequest struct {
	id        string
	timestamp time.Time
	seenAt    time.Time
}

// Protector provides anti-replay protection.
type Protector struct {
	config   Config
	seen     map[string]seenRequest
	mu       sync.RWMutex
	stopChan chan struct{}
	stopOnce sync.Once
}

// New creates a new anti-replay protector.
func New(cfg Config) *Protector {
	p := &Protector{
		config:   cfg,
		seen:     make(map[string]seenRequest),
		stopChan: make(chan struct{}),
	}

	// Start cleanup goroutine
	go p.cleanupLoop()

	return p
}

// ValidateRequest validates a request against replay attacks.
// Returns nil if the request is valid, or an error describing the issue.
func (p *Protector) ValidateRequest(requestID string, timestamp time.Time) error {
	now := time.Now()

	// Check timestamp validity
	age := now.Sub(timestamp)
	if age > p.config.MaxAge {
		return fmt.Errorf("%w: age %v exceeds max %v", ErrTimestampExpired, age, p.config.MaxAge)
	}

	// Check for future timestamp (clock skew)
	if timestamp.After(now.Add(p.config.FutureWindow)) {
		return fmt.Errorf("%w: timestamp %v is too far in the future", ErrTimestampFuture, timestamp)
	}

	// Check if request ID was already seen
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.seen[requestID]; exists {
		return fmt.Errorf("%w: request_id=%s", ErrReplayDetected, requestID)
	}

	// Record this request
	p.seen[requestID] = seenRequest{
		id:        requestID,
		timestamp: timestamp,
		seenAt:    now,
	}

	// Enforce cache size limit
	if len(p.seen) > p.config.MaxCacheSize {
		p.evictOldest()
	}

	return nil
}

// ValidateRequestWithSignature validates request with HMAC signature.
func (p *Protector) ValidateRequestWithSignature(requestID string, timestamp time.Time, payload []byte, signature string) error {
	// First validate timestamp and replay
	if err := p.ValidateRequest(requestID, timestamp); err != nil {
		return err
	}

	// If signature validation is not required, we're done
	if !p.config.RequireSignature || len(p.config.SignatureKey) == 0 {
		return nil
	}

	// Validate HMAC signature
	expectedSig := p.computeSignature(requestID, timestamp, payload)
	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return ErrInvalidSignature
	}

	return nil
}

// computeSignature computes HMAC-SHA256 signature.
func (p *Protector) computeSignature(requestID string, timestamp time.Time, payload []byte) string {
	h := hmac.New(sha256.New, p.config.SignatureKey)
	h.Write([]byte(requestID))
	h.Write([]byte(timestamp.Format(time.RFC3339Nano)))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// evictOldest removes the oldest entries from the cache.
func (p *Protector) evictOldest() {
	// Find and remove entries older than MaxAge
	cutoff := time.Now().Add(-p.config.MaxAge)
	for id, req := range p.seen {
		if req.seenAt.Before(cutoff) {
			delete(p.seen, id)
		}
	}

	// If still over limit, remove oldest by seenAt
	if len(p.seen) > p.config.MaxCacheSize {
		oldest := time.Now()
		var oldestID string
		for id, req := range p.seen {
			if req.seenAt.Before(oldest) {
				oldest = req.seenAt
				oldestID = id
			}
		}
		if oldestID != "" {
			delete(p.seen, oldestID)
		}
	}
}

// cleanupLoop periodically cleans up expired entries.
func (p *Protector) cleanupLoop() {
	ticker := time.NewTicker(p.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			p.cleanup()
		}
	}
}

// cleanup removes expired entries.
func (p *Protector) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()

	cutoff := time.Now().Add(-p.config.MaxAge)
	for id, req := range p.seen {
		if req.seenAt.Before(cutoff) {
			delete(p.seen, id)
		}
	}
}

// Stop stops the cleanup goroutine.
func (p *Protector) Stop() {
	p.stopOnce.Do(func() {
		close(p.stopChan)
	})
}

// Stats returns cache statistics.
func (p *Protector) Stats() map[string]interface{} {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return map[string]interface{}{
		"cached_requests": len(p.seen),
		"max_cache_size":  p.config.MaxCacheSize,
		"max_age_seconds": p.config.MaxAge.Seconds(),
	}
}

// IsReplayError returns true if the error is a replay detection error.
func IsReplayError(err error) bool {
	return errors.Is(err, ErrReplayDetected) ||
		errors.Is(err, ErrTimestampExpired) ||
		errors.Is(err, ErrTimestampFuture)
}
