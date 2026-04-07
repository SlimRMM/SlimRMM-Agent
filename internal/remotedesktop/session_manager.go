package remotedesktop

import (
	"fmt"
	"log/slog"
	"runtime"
	"sync"

	"github.com/slimrmm/slimrmm-agent/internal/helper"
)

// SessionManager manages the lifecycle of a remote desktop session.
// On Windows, it pins the helper process for the duration of the session.
type SessionManager struct {
	mu     sync.Mutex
	active bool
	pinned bool
	logger *slog.Logger
}

func NewSessionManager(logger *slog.Logger) *SessionManager {
	return &SessionManager{logger: logger}
}

func (sm *SessionManager) StartSession() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.active {
		return nil
	}

	if runtime.GOOS == "windows" {
		mgr := helper.GetManager()
		_, err := mgr.Acquire()
		if err != nil {
			return fmt.Errorf("failed to acquire helper for RD session: %w", err)
		}
		mgr.Pin()
		sm.pinned = true
		sm.logger.Info("helper pinned for RD session")
	}

	sm.active = true
	return nil
}

func (sm *SessionManager) StopSession() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.active {
		return
	}

	if runtime.GOOS == "windows" && sm.pinned {
		mgr := helper.GetManager()
		mgr.Unpin()
		mgr.Release()
		sm.pinned = false
		sm.logger.Info("helper unpinned after RD session")
	}

	sm.active = false
}

func (sm *SessionManager) IsActive() bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.active
}
