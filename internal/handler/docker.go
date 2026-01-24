// Package handler provides Docker action handlers for heartbeat detection.
package handler

import (
	"context"

	"github.com/slimrmm/slimrmm-agent/internal/actions"
)

// DockerInfo contains Docker detection information for heartbeat.
type DockerInfo struct {
	Available         bool   `json:"available"`
	Version           string `json:"version,omitempty"`
	APIVersion        string `json:"api_version,omitempty"`
	Containers        int    `json:"containers"`
	ContainersRunning int    `json:"containers_running"`
	Images            int    `json:"images"`
}

// GetDockerInfo returns Docker information for heartbeat.
// Returns nil if Docker is not available.
func GetDockerInfo(ctx context.Context) *DockerInfo {
	if !actions.IsDockerAvailable() {
		return nil
	}

	info, err := actions.GetDockerInfo(ctx)
	if err != nil {
		return &DockerInfo{
			Available: false,
		}
	}

	return &DockerInfo{
		Available:         info.Available,
		Version:           info.Version,
		APIVersion:        info.APIVersion,
		Containers:        info.Containers,
		ContainersRunning: info.ContainersRunning,
		Images:            info.Images,
	}
}

// IsDockerHost returns true if Docker is available on this host.
func IsDockerHost() bool {
	return actions.IsDockerAvailable()
}
