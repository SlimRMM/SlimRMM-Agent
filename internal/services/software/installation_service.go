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

// installationState tracks the state of a running installation.
type installationState struct {
	cancel    context.CancelFunc
	result    *models.InstallResult
	startedAt time.Time
}

// DefaultInstallationService implements InstallationService.
type DefaultInstallationService struct {
	logger           *slog.Logger
	installers       []PlatformInstaller
	progressCallback ProgressCallback

	mu             sync.RWMutex
	installations  map[string]*installationState
}

// NewInstallationService creates a new installation service.
func NewInstallationService(logger *slog.Logger, installers ...PlatformInstaller) *DefaultInstallationService {
	return &DefaultInstallationService{
		logger:        logger,
		installers:    installers,
		installations: make(map[string]*installationState),
	}
}

// SetProgressCallback sets the callback for progress updates.
func (s *DefaultInstallationService) SetProgressCallback(callback ProgressCallback) {
	s.progressCallback = callback
}

// Install installs software based on the request type.
func (s *DefaultInstallationService) Install(ctx context.Context, req *models.InstallRequest) (*models.InstallResult, error) {
	if req.InstallationID == "" {
		return nil, fmt.Errorf("installation_id is required")
	}

	// Find appropriate installer
	var installer PlatformInstaller
	for _, i := range s.installers {
		if i.CanHandle(req.InstallationType) && i.IsAvailable() {
			installer = i
			break
		}
	}

	if installer == nil {
		return &models.InstallResult{
			InstallationID: req.InstallationID,
			Status:         models.StatusFailed,
			Error:          fmt.Sprintf("no installer available for type: %s", req.InstallationType),
			StartedAt:      time.Now(),
			CompletedAt:    time.Now(),
		}, nil
	}

	// Set timeout
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)

	// Track this installation
	state := &installationState{
		cancel:    cancel,
		startedAt: time.Now(),
		result: &models.InstallResult{
			InstallationID: req.InstallationID,
			Status:         models.StatusInstalling,
			StartedAt:      time.Now(),
		},
	}

	s.mu.Lock()
	s.installations[req.InstallationID] = state
	s.mu.Unlock()

	// Cleanup on completion
	defer func() {
		cancel()
		s.mu.Lock()
		delete(s.installations, req.InstallationID)
		s.mu.Unlock()
	}()

	s.logger.Info("starting software installation",
		"installation_id", req.InstallationID,
		"type", req.InstallationType,
		"package_id", req.PackageID,
	)

	// Report progress
	s.reportProgress(&models.InstallProgress{
		InstallationID: req.InstallationID,
		Status:         models.StatusInstalling,
		Output:         fmt.Sprintf("Installing %s...", req.PackageID),
	})

	// Delegate to platform-specific installer
	result, err := installer.Install(ctx, req)
	if err != nil {
		result = &models.InstallResult{
			InstallationID: req.InstallationID,
			Status:         models.StatusFailed,
			Error:          err.Error(),
			StartedAt:      state.startedAt,
			CompletedAt:    time.Now(),
		}
	}

	// Calculate duration
	result.Duration = time.Since(state.startedAt).Seconds()

	// Update state
	s.mu.Lock()
	if st, ok := s.installations[req.InstallationID]; ok {
		st.result = result
	}
	s.mu.Unlock()

	s.logger.Info("software installation completed",
		"installation_id", req.InstallationID,
		"status", result.Status,
		"duration", result.Duration,
	)

	return result, nil
}

// CancelInstallation cancels a running installation.
func (s *DefaultInstallationService) CancelInstallation(ctx context.Context, installationID string) error {
	s.mu.RLock()
	state, exists := s.installations[installationID]
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("installation not found: %s", installationID)
	}

	s.logger.Info("cancelling installation", "installation_id", installationID)
	state.cancel()

	s.mu.Lock()
	if st, ok := s.installations[installationID]; ok {
		st.result = &models.InstallResult{
			InstallationID: installationID,
			Status:         models.StatusCancelled,
			Output:         "Installation cancelled by user request",
			StartedAt:      st.startedAt,
			CompletedAt:    time.Now(),
			Duration:       time.Since(st.startedAt).Seconds(),
		}
	}
	s.mu.Unlock()

	return nil
}

// GetInstallationStatus retrieves the status of an installation.
func (s *DefaultInstallationService) GetInstallationStatus(ctx context.Context, installationID string) (*models.InstallResult, error) {
	s.mu.RLock()
	state, exists := s.installations[installationID]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("installation not found: %s", installationID)
	}

	return state.result, nil
}

// IsInstalling checks if an installation is currently running.
func (s *DefaultInstallationService) IsInstalling(installationID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.installations[installationID]
	return exists
}

// reportProgress sends progress updates via the callback.
func (s *DefaultInstallationService) reportProgress(progress *models.InstallProgress) {
	if s.progressCallback != nil {
		s.progressCallback(progress)
	}
}
