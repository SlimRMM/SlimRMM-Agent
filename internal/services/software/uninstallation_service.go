// Package software provides software installation and uninstallation services.
package software

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/services/models"
)

// uninstallationState tracks the state of a running uninstallation.
type uninstallationState struct {
	cancel    context.CancelFunc
	result    *models.UninstallResult
	startedAt time.Time
	snapshot  *models.Snapshot
}

// DefaultUninstallationService implements UninstallationService.
type DefaultUninstallationService struct {
	logger            *slog.Logger
	uninstallers      []PlatformUninstaller
	snapshotService   SnapshotService
	fileLockService   FileLockService
	progressCallback  ProgressCallback

	mu              sync.RWMutex
	uninstallations map[string]*uninstallationState
}

// NewUninstallationService creates a new uninstallation service.
func NewUninstallationService(
	logger *slog.Logger,
	snapshotService SnapshotService,
	fileLockService FileLockService,
	uninstallers ...PlatformUninstaller,
) *DefaultUninstallationService {
	return &DefaultUninstallationService{
		logger:          logger,
		uninstallers:    uninstallers,
		snapshotService: snapshotService,
		fileLockService: fileLockService,
		uninstallations: make(map[string]*uninstallationState),
	}
}

// SetProgressCallback sets the callback for progress updates.
func (s *DefaultUninstallationService) SetProgressCallback(callback ProgressCallback) {
	s.progressCallback = callback
}

// Uninstall uninstalls software based on the request type.
func (s *DefaultUninstallationService) Uninstall(ctx context.Context, req *models.UninstallRequest) (*models.UninstallResult, error) {
	if req.UninstallationID == "" {
		return nil, fmt.Errorf("uninstallation_id is required")
	}

	// Find appropriate uninstaller
	var uninstaller PlatformUninstaller
	for _, u := range s.uninstallers {
		if u.CanHandle(req.InstallationType) && u.IsAvailable() {
			uninstaller = u
			break
		}
	}

	if uninstaller == nil {
		return &models.UninstallResult{
			UninstallationID: req.UninstallationID,
			Status:           models.UninstallStatusFailed,
			Error:            fmt.Sprintf("no uninstaller available for type: %s", req.InstallationType),
			StartedAt:        time.Now(),
			CompletedAt:      time.Now(),
		}, nil
	}

	// Set timeout
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)

	// Track this uninstallation
	state := &uninstallationState{
		cancel:    cancel,
		startedAt: time.Now(),
		result: &models.UninstallResult{
			UninstallationID: req.UninstallationID,
			Status:           models.UninstallStatusUninstalling,
			StartedAt:        time.Now(),
		},
	}

	s.mu.Lock()
	s.uninstallations[req.UninstallationID] = state
	s.mu.Unlock()

	// Cleanup on completion
	defer func() {
		cancel()
		s.mu.Lock()
		delete(s.uninstallations, req.UninstallationID)
		s.mu.Unlock()
	}()

	s.logger.Info("starting software uninstallation",
		"uninstallation_id", req.UninstallationID,
		"type", req.InstallationType,
		"package_id", req.PackageID,
		"cleanup_mode", req.CleanupMode,
	)

	// Create snapshot if requested
	if req.CreateSnapshot && s.snapshotService != nil {
		s.reportProgress(&models.UninstallProgress{
			UninstallationID: req.UninstallationID,
			Status:           models.UninstallStatusPending,
			Phase:            "creating_snapshot",
			Output:           "Creating pre-uninstall snapshot...",
		})

		snapshot, err := s.snapshotService.CreateSnapshot(ctx, req)
		if err != nil {
			s.logger.Warn("failed to create snapshot, continuing with uninstallation",
				"uninstallation_id", req.UninstallationID,
				"error", err,
			)
		} else {
			state.snapshot = snapshot
			state.result.SnapshotID = snapshot.ID
		}
	}

	// Report progress
	s.reportProgress(&models.UninstallProgress{
		UninstallationID: req.UninstallationID,
		Status:           models.UninstallStatusUninstalling,
		Phase:            "uninstalling",
		Output:           fmt.Sprintf("Uninstalling %s...", req.PackageID),
	})

	// Delegate to platform-specific uninstaller
	result, err := uninstaller.Uninstall(ctx, req)
	if err != nil {
		result = &models.UninstallResult{
			UninstallationID: req.UninstallationID,
			Status:           models.UninstallStatusFailed,
			Error:            err.Error(),
			StartedAt:        state.startedAt,
			CompletedAt:      time.Now(),
		}
	}

	// Perform cleanup if uninstallation succeeded and cleanup mode is set
	if result.Status == models.UninstallStatusCompleted && req.CleanupMode != "" && req.CleanupMode != models.CleanupModeNone {
		s.reportProgress(&models.UninstallProgress{
			UninstallationID: req.UninstallationID,
			Status:           models.UninstallStatusCleaningUp,
			Phase:            "cleanup",
			Output:           "Performing cleanup...",
		})

		cleanupResult, cleanupErr := uninstaller.Cleanup(ctx, req)
		if cleanupErr != nil {
			s.logger.Warn("cleanup failed",
				"uninstallation_id", req.UninstallationID,
				"error", cleanupErr,
			)
		} else if cleanupResult != nil {
			result.CleanupResults = cleanupResult
		}
	}

	// Calculate duration
	result.Duration = time.Since(state.startedAt).Seconds()

	// Preserve snapshot ID
	if state.snapshot != nil {
		result.SnapshotID = state.snapshot.ID
	}

	// Update state
	s.mu.Lock()
	if st, ok := s.uninstallations[req.UninstallationID]; ok {
		st.result = result
	}
	s.mu.Unlock()

	s.logger.Info("software uninstallation completed",
		"uninstallation_id", req.UninstallationID,
		"status", result.Status,
		"duration", result.Duration,
	)

	return result, nil
}

// CancelUninstallation cancels a running uninstallation.
func (s *DefaultUninstallationService) CancelUninstallation(ctx context.Context, uninstallationID string) error {
	s.mu.RLock()
	state, exists := s.uninstallations[uninstallationID]
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("uninstallation not found: %s", uninstallationID)
	}

	s.logger.Info("cancelling uninstallation", "uninstallation_id", uninstallationID)
	state.cancel()

	s.mu.Lock()
	if st, ok := s.uninstallations[uninstallationID]; ok {
		st.result = &models.UninstallResult{
			UninstallationID: uninstallationID,
			Status:           models.UninstallStatusCancelled,
			Output:           "Uninstallation cancelled by user request",
			StartedAt:        st.startedAt,
			CompletedAt:      time.Now(),
			Duration:         time.Since(st.startedAt).Seconds(),
		}
	}
	s.mu.Unlock()

	return nil
}

// GetUninstallationStatus retrieves the status of an uninstallation.
func (s *DefaultUninstallationService) GetUninstallationStatus(ctx context.Context, uninstallationID string) (*models.UninstallResult, error) {
	s.mu.RLock()
	state, exists := s.uninstallations[uninstallationID]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("uninstallation not found: %s", uninstallationID)
	}

	return state.result, nil
}

// IsUninstalling checks if an uninstallation is currently running.
func (s *DefaultUninstallationService) IsUninstalling(uninstallationID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.uninstallations[uninstallationID]
	return exists
}

// CreateSnapshot creates a pre-uninstall snapshot for rollback.
func (s *DefaultUninstallationService) CreateSnapshot(ctx context.Context, req *models.UninstallRequest) (*models.Snapshot, error) {
	if s.snapshotService == nil {
		return nil, fmt.Errorf("snapshot service not available")
	}
	return s.snapshotService.CreateSnapshot(ctx, req)
}

// Rollback rolls back an uninstallation using a snapshot.
func (s *DefaultUninstallationService) Rollback(ctx context.Context, uninstallationID string, snapshotID string) error {
	if s.snapshotService == nil {
		return fmt.Errorf("snapshot service not available")
	}

	s.logger.Info("rolling back uninstallation",
		"uninstallation_id", uninstallationID,
		"snapshot_id", snapshotID,
	)

	if err := s.snapshotService.RestoreSnapshot(ctx, snapshotID); err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	return nil
}

// reportProgress sends progress updates via the callback.
func (s *DefaultUninstallationService) reportProgress(progress *models.UninstallProgress) {
	if s.progressCallback != nil {
		s.progressCallback(progress)
	}
}
