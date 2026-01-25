package backup

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// DockerCollectorDeps defines dependencies for Docker operations.
// This allows for easier testing by injecting mock implementations.
type DockerCollectorDeps interface {
	IsDockerAvailable() bool
	InspectContainer(ctx context.Context, containerID string) (map[string]interface{}, error)
	GetContainerStats(ctx context.Context, containerID string) (map[string]interface{}, error)
	GetContainerLogs(ctx context.Context, containerID string, lines int, timestamps bool) (string, error)
	ListContainers(ctx context.Context, all bool) ([]ContainerInfo, error)
	ContainerAction(ctx context.Context, containerID, action string) error
	InspectVolume(ctx context.Context, volumeName string) (map[string]interface{}, error)
	InspectImage(ctx context.Context, imageName string) (map[string]interface{}, error)
}

// ContainerInfo contains basic container information.
type ContainerInfo struct {
	ID    string
	Name  string
	State string
}

// DockerContainerCollector collects Docker container backups.
type DockerContainerCollector struct {
	deps   DockerCollectorDeps
	logger Logger
}

// Logger interface for logging.
type Logger interface {
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// NewDockerContainerCollector creates a new Docker container collector.
func NewDockerContainerCollector(deps DockerCollectorDeps, logger Logger) *DockerContainerCollector {
	return &DockerContainerCollector{deps: deps, logger: logger}
}

// Type returns the backup type.
func (c *DockerContainerCollector) Type() BackupType {
	return TypeDockerContainer
}

// Collect collects a Docker container backup.
func (c *DockerContainerCollector) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	if !c.deps.IsDockerAvailable() {
		return nil, &ErrFeatureUnavailable{Feature: "Docker"}
	}

	if config.ContainerID == "" {
		return nil, &ErrMissingParameter{
			Parameter: "container_id",
			Context:   "docker_container backup",
		}
	}

	backupData := map[string]interface{}{
		"backup_type":  "docker_container",
		"container_id": config.ContainerID,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"agent_uuid":   config.AgentUUID,
	}

	// Get container inspection data
	inspectData, err := c.deps.InspectContainer(ctx, config.ContainerID)
	if err != nil {
		return nil, &ErrCollectionFailed{
			Type:   TypeDockerContainer,
			Reason: "failed to inspect container",
			Err:    err,
		}
	}
	backupData["inspect"] = inspectData

	// Get container stats
	stats, err := c.deps.GetContainerStats(ctx, config.ContainerID)
	if err == nil {
		backupData["stats"] = stats
	}

	// Export container filesystem
	exportData, exportSize, err := c.exportContainer(ctx, config.ContainerID)
	if err != nil {
		return nil, err
	}
	backupData["export_data"] = exportData
	backupData["export_size"] = exportSize

	return json.Marshal(backupData)
}

// exportContainer exports a container's filesystem.
func (c *DockerContainerCollector) exportContainer(ctx context.Context, containerID string) (string, int, error) {
	cmd := exec.CommandContext(ctx, "docker", "export", containerID)
	exportData, err := cmd.Output()
	if err != nil {
		return "", 0, &ErrCollectionFailed{
			Type:   TypeDockerContainer,
			Reason: "failed to export container",
			Err:    err,
		}
	}
	return base64.StdEncoding.EncodeToString(exportData), len(exportData), nil
}

// DockerVolumeCollector collects Docker volume backups.
type DockerVolumeCollector struct {
	deps   DockerCollectorDeps
	logger Logger
}

// NewDockerVolumeCollector creates a new Docker volume collector.
func NewDockerVolumeCollector(deps DockerCollectorDeps, logger Logger) *DockerVolumeCollector {
	return &DockerVolumeCollector{deps: deps, logger: logger}
}

// Type returns the backup type.
func (c *DockerVolumeCollector) Type() BackupType {
	return TypeDockerVolume
}

// Collect collects a Docker volume backup.
func (c *DockerVolumeCollector) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	if !c.deps.IsDockerAvailable() {
		return nil, &ErrFeatureUnavailable{Feature: "Docker"}
	}

	if config.VolumeName == "" {
		return nil, &ErrMissingParameter{
			Parameter: "volume_name",
			Context:   "docker_volume backup",
		}
	}

	backupData := map[string]interface{}{
		"backup_type": "docker_volume",
		"volume_name": config.VolumeName,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"agent_uuid":  config.AgentUUID,
	}

	// Get volume inspection data
	inspectData, err := c.deps.InspectVolume(ctx, config.VolumeName)
	if err != nil {
		return nil, &ErrCollectionFailed{
			Type:   TypeDockerVolume,
			Reason: "failed to inspect volume",
			Err:    err,
		}
	}
	backupData["inspect"] = inspectData

	// Archive volume data using a temporary container
	volumeData, volumeSize, err := c.archiveVolume(ctx, config.VolumeName)
	if err != nil {
		return nil, err
	}
	backupData["volume_data"] = volumeData
	backupData["volume_size"] = volumeSize

	return json.Marshal(backupData)
}

// archiveVolume archives a Docker volume's data.
func (c *DockerVolumeCollector) archiveVolume(ctx context.Context, volumeName string) (string, int, error) {
	// Use a temporary alpine container to archive the volume
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm",
		"-v", volumeName+":/volume:ro",
		"alpine", "tar", "-czf", "-", "-C", "/volume", ".")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", 0, &ErrCollectionFailed{
			Type:   TypeDockerVolume,
			Reason: fmt.Sprintf("failed to archive volume: %s", stderr.String()),
			Err:    err,
		}
	}

	return base64.StdEncoding.EncodeToString(stdout.Bytes()), stdout.Len(), nil
}

// DockerImageCollector collects Docker image backups.
type DockerImageCollector struct {
	deps   DockerCollectorDeps
	logger Logger
}

// NewDockerImageCollector creates a new Docker image collector.
func NewDockerImageCollector(deps DockerCollectorDeps, logger Logger) *DockerImageCollector {
	return &DockerImageCollector{deps: deps, logger: logger}
}

// Type returns the backup type.
func (c *DockerImageCollector) Type() BackupType {
	return TypeDockerImage
}

// Collect collects a Docker image backup.
func (c *DockerImageCollector) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	if !c.deps.IsDockerAvailable() {
		return nil, &ErrFeatureUnavailable{Feature: "Docker"}
	}

	if config.ImageName == "" {
		return nil, &ErrMissingParameter{
			Parameter: "image_name",
			Context:   "docker_image backup",
		}
	}

	backupData := map[string]interface{}{
		"backup_type": "docker_image",
		"image_name":  config.ImageName,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"agent_uuid":  config.AgentUUID,
	}

	// Get image inspection data
	inspectData, err := c.deps.InspectImage(ctx, config.ImageName)
	if err != nil {
		return nil, &ErrCollectionFailed{
			Type:   TypeDockerImage,
			Reason: "failed to inspect image",
			Err:    err,
		}
	}
	backupData["inspect"] = inspectData

	// Save image
	imageData, imageSize, err := c.saveImage(ctx, config.ImageName)
	if err != nil {
		return nil, err
	}
	backupData["image_data"] = imageData
	backupData["image_size"] = imageSize

	return json.Marshal(backupData)
}

// saveImage saves a Docker image to a tar archive.
func (c *DockerImageCollector) saveImage(ctx context.Context, imageName string) (string, int, error) {
	cmd := exec.CommandContext(ctx, "docker", "save", imageName)
	imageData, err := cmd.Output()
	if err != nil {
		return "", 0, &ErrCollectionFailed{
			Type:   TypeDockerImage,
			Reason: "failed to save image",
			Err:    err,
		}
	}
	return base64.StdEncoding.EncodeToString(imageData), len(imageData), nil
}

// DockerComposeCollector collects Docker Compose backups.
type DockerComposeCollector struct {
	logger Logger
}

// NewDockerComposeCollector creates a new Docker Compose collector.
func NewDockerComposeCollector(logger Logger) *DockerComposeCollector {
	return &DockerComposeCollector{logger: logger}
}

// Type returns the backup type.
func (c *DockerComposeCollector) Type() BackupType {
	return TypeDockerCompose
}

// Collect collects a Docker Compose backup.
func (c *DockerComposeCollector) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	if config.ComposePath == "" {
		return nil, &ErrMissingParameter{
			Parameter: "compose_path",
			Context:   "docker_compose backup",
		}
	}

	backupData := map[string]interface{}{
		"backup_type":  "docker_compose",
		"compose_path": config.ComposePath,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"agent_uuid":   config.AgentUUID,
	}

	// Note: The actual compose file reading would be done here
	// For now, we just return the metadata structure
	// The handler should read the file and pass the content

	return json.Marshal(backupData)
}
