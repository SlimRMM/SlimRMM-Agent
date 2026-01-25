// Package backup provides backup collection services for the RMM agent.
package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// DefaultDockerDeps provides the default implementation of DockerCollectorDeps.
// It wraps Docker CLI commands to provide container, volume, and image operations.
type DefaultDockerDeps struct{}

// NewDefaultDockerDeps creates a new default Docker dependencies implementation.
func NewDefaultDockerDeps() *DefaultDockerDeps {
	return &DefaultDockerDeps{}
}

// IsDockerAvailable checks if Docker is installed and running.
func (d *DefaultDockerDeps) IsDockerAvailable() bool {
	cmd := exec.Command("docker", "version", "--format", "{{.Server.Version}}")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// InspectContainer returns detailed information about a container.
func (d *DefaultDockerDeps) InspectContainer(ctx context.Context, containerID string) (map[string]interface{}, error) {
	cmd := exec.CommandContext(ctx, "docker", "inspect", containerID)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	var result []map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse inspect output: %w", err)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("container not found: %s", containerID)
	}

	return result[0], nil
}

// GetContainerStats returns resource statistics for a container.
func (d *DefaultDockerDeps) GetContainerStats(ctx context.Context, containerID string) (map[string]interface{}, error) {
	cmd := exec.CommandContext(ctx, "docker", "stats", "--no-stream", "--format", "{{json .}}", containerID)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get container stats: %w", err)
	}

	var stats map[string]interface{}
	if err := json.Unmarshal(output, &stats); err != nil {
		return nil, fmt.Errorf("failed to parse stats: %w", err)
	}

	return stats, nil
}

// GetContainerLogs returns logs from a container.
func (d *DefaultDockerDeps) GetContainerLogs(ctx context.Context, containerID string, lines int, timestamps bool) (string, error) {
	args := []string{"logs"}
	if lines > 0 {
		args = append(args, "--tail", fmt.Sprintf("%d", lines))
	}
	if timestamps {
		args = append(args, "--timestamps")
	}
	args = append(args, containerID)

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get logs: %w", err)
	}

	return string(output), nil
}

// ListContainers lists all containers.
func (d *DefaultDockerDeps) ListContainers(ctx context.Context, all bool) ([]ContainerInfo, error) {
	args := []string{"ps", "--format", "{{json .}}"}
	if all {
		args = append(args, "-a")
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var containers []ContainerInfo
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}

		container := ContainerInfo{
			ID:    getString(raw, "ID"),
			Name:  strings.TrimPrefix(getString(raw, "Names"), "/"),
			State: getString(raw, "State"),
		}
		containers = append(containers, container)
	}

	return containers, nil
}

// ContainerAction performs an action on a container.
func (d *DefaultDockerDeps) ContainerAction(ctx context.Context, containerID, action string) error {
	validActions := map[string]bool{
		"start":   true,
		"stop":    true,
		"restart": true,
		"pause":   true,
		"unpause": true,
		"kill":    true,
	}

	if !validActions[action] {
		return fmt.Errorf("invalid action: %s", action)
	}

	cmd := exec.CommandContext(ctx, "docker", action, containerID)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to %s container: %s", action, string(output))
	}
	return nil
}

// InspectVolume returns detailed information about a volume.
func (d *DefaultDockerDeps) InspectVolume(ctx context.Context, volumeName string) (map[string]interface{}, error) {
	cmd := exec.CommandContext(ctx, "docker", "volume", "inspect", volumeName)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to inspect volume: %w", err)
	}

	var result []map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse inspect output: %w", err)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("volume not found: %s", volumeName)
	}

	return result[0], nil
}

// InspectImage returns detailed information about an image.
func (d *DefaultDockerDeps) InspectImage(ctx context.Context, imageName string) (map[string]interface{}, error) {
	cmd := exec.CommandContext(ctx, "docker", "image", "inspect", imageName)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to inspect image: %w", err)
	}

	var result []map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse inspect output: %w", err)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("image not found: %s", imageName)
	}

	return result[0], nil
}

// getString safely extracts a string from a map.
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
