// Package backup provides backup collection services for the RMM agent.
package backup

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
)

// DockerContainerRestorer restores Docker containers from backups.
type DockerContainerRestorer struct {
	deps   DockerCollectorDeps
	logger Logger
}

// NewDockerContainerRestorer creates a new Docker container restorer.
func NewDockerContainerRestorer(deps DockerCollectorDeps, logger Logger) *DockerContainerRestorer {
	return &DockerContainerRestorer{deps: deps, logger: logger}
}

// Type returns the backup type.
func (r *DockerContainerRestorer) Type() BackupType {
	return TypeDockerContainer
}

// Restore restores a Docker container from backup data.
func (r *DockerContainerRestorer) Restore(ctx context.Context, data []byte, config RestoreConfig) (*RestoreResult, error) {
	result := &RestoreResult{
		Status: "in_progress",
	}

	if !r.deps.IsDockerAvailable() {
		result.Status = "failed"
		result.Error = "Docker is not available"
		return result, fmt.Errorf("docker not available")
	}

	// Parse backup data
	var backupData struct {
		ContainerID string `json:"container_id"`
		ExportData  string `json:"export_data"`
		Inspect     map[string]interface{} `json:"inspect"`
	}
	if err := json.Unmarshal(data, &backupData); err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to parse backup data: %v", err)
		return result, err
	}

	// Decode the exported container data
	exportData, err := base64.StdEncoding.DecodeString(backupData.ExportData)
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to decode export data: %v", err)
		return result, err
	}

	// Determine container name
	containerName := config.ContainerName
	if containerName == "" {
		containerName = backupData.ContainerID
	}

	// Import the container
	importCmd := exec.CommandContext(ctx, "docker", "import", "-", containerName)
	importCmd.Stdin = bytes.NewReader(exportData)

	output, err := importCmd.CombinedOutput()
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to import container: %v - %s", err, string(output))
		return result, err
	}

	result.Status = "completed"
	result.RestoredFiles = 1
	result.TotalFiles = 1

	if r.logger != nil {
		r.logger.Info("Docker container restored successfully", "container", containerName)
	}

	return result, nil
}

// DockerVolumeRestorer restores Docker volumes from backups.
type DockerVolumeRestorer struct {
	deps   DockerCollectorDeps
	logger Logger
}

// NewDockerVolumeRestorer creates a new Docker volume restorer.
func NewDockerVolumeRestorer(deps DockerCollectorDeps, logger Logger) *DockerVolumeRestorer {
	return &DockerVolumeRestorer{deps: deps, logger: logger}
}

// Type returns the backup type.
func (r *DockerVolumeRestorer) Type() BackupType {
	return TypeDockerVolume
}

// Restore restores a Docker volume from backup data.
func (r *DockerVolumeRestorer) Restore(ctx context.Context, data []byte, config RestoreConfig) (*RestoreResult, error) {
	result := &RestoreResult{
		Status: "in_progress",
	}

	if !r.deps.IsDockerAvailable() {
		result.Status = "failed"
		result.Error = "Docker is not available"
		return result, fmt.Errorf("docker not available")
	}

	// Parse backup data
	var backupData struct {
		VolumeName string `json:"volume_name"`
		VolumeData string `json:"volume_data"`
	}
	if err := json.Unmarshal(data, &backupData); err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to parse backup data: %v", err)
		return result, err
	}

	// Decode the volume data
	volumeData, err := base64.StdEncoding.DecodeString(backupData.VolumeData)
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to decode volume data: %v", err)
		return result, err
	}

	// Determine volume name
	volumeName := config.VolumeName
	if volumeName == "" {
		volumeName = backupData.VolumeName
	}

	// Create volume if it doesn't exist
	createCmd := exec.CommandContext(ctx, "docker", "volume", "create", volumeName)
	if output, err := createCmd.CombinedOutput(); err != nil {
		r.logger.Warn("Volume creation warning", "output", string(output), "error", err)
	}

	// Restore volume data using a temporary container
	restoreCmd := exec.CommandContext(ctx, "docker", "run", "--rm", "-i",
		"-v", volumeName+":/volume",
		"alpine", "tar", "-xzf", "-", "-C", "/volume")
	restoreCmd.Stdin = bytes.NewReader(volumeData)

	output, err := restoreCmd.CombinedOutput()
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to restore volume: %v - %s", err, string(output))
		return result, err
	}

	result.Status = "completed"
	result.RestoredFiles = 1
	result.TotalFiles = 1

	if r.logger != nil {
		r.logger.Info("Docker volume restored successfully", "volume", volumeName)
	}

	return result, nil
}

// DockerImageRestorer restores Docker images from backups.
type DockerImageRestorer struct {
	deps   DockerCollectorDeps
	logger Logger
}

// NewDockerImageRestorer creates a new Docker image restorer.
func NewDockerImageRestorer(deps DockerCollectorDeps, logger Logger) *DockerImageRestorer {
	return &DockerImageRestorer{deps: deps, logger: logger}
}

// Type returns the backup type.
func (r *DockerImageRestorer) Type() BackupType {
	return TypeDockerImage
}

// Restore restores a Docker image from backup data.
func (r *DockerImageRestorer) Restore(ctx context.Context, data []byte, config RestoreConfig) (*RestoreResult, error) {
	result := &RestoreResult{
		Status: "in_progress",
	}

	if !r.deps.IsDockerAvailable() {
		result.Status = "failed"
		result.Error = "Docker is not available"
		return result, fmt.Errorf("docker not available")
	}

	// Parse backup data
	var backupData struct {
		ImageName string `json:"image_name"`
		ImageData string `json:"image_data"`
	}
	if err := json.Unmarshal(data, &backupData); err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to parse backup data: %v", err)
		return result, err
	}

	// Decode the image data
	imageData, err := base64.StdEncoding.DecodeString(backupData.ImageData)
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to decode image data: %v", err)
		return result, err
	}

	// Load the image
	loadCmd := exec.CommandContext(ctx, "docker", "load")
	loadCmd.Stdin = bytes.NewReader(imageData)

	output, err := loadCmd.CombinedOutput()
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to load image: %v - %s", err, string(output))
		return result, err
	}

	result.Status = "completed"
	result.RestoredFiles = 1
	result.TotalFiles = 1

	if r.logger != nil {
		r.logger.Info("Docker image restored successfully", "image", backupData.ImageName, "output", string(output))
	}

	return result, nil
}
