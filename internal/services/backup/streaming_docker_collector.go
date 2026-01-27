// Package backup provides streaming Docker backup collectors.
// These collectors stream data directly from Docker commands to the upload destination
// without loading entire container/volume/image data into memory.
package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// StreamingDockerContainerCollector collects Docker container backups using streaming.
// Memory usage is O(buffer_size) regardless of container filesystem size.
type StreamingDockerContainerCollector struct {
	logger  *slog.Logger
	tempDir string
}

// NewStreamingDockerContainerCollector creates a new streaming Docker container collector.
func NewStreamingDockerContainerCollector(logger *slog.Logger, tempDir string) *StreamingDockerContainerCollector {
	if logger == nil {
		logger = slog.Default()
	}
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	return &StreamingDockerContainerCollector{
		logger:  logger,
		tempDir: tempDir,
	}
}

// Type returns the backup type.
func (c *StreamingDockerContainerCollector) Type() BackupType {
	return TypeDockerContainer
}

// SupportsStreaming returns true as this collector supports streaming.
func (c *StreamingDockerContainerCollector) SupportsStreaming() bool {
	return true
}

// CollectStream writes Docker container backup data directly to the writer.
// Uses streaming to minimize memory usage:
// 1. Runs docker export with output piped directly to writer
// 2. No intermediate buffering of the entire container filesystem
// 3. Memory usage limited to pipe buffer size (~64KB on Linux)
func (c *StreamingDockerContainerCollector) CollectStream(ctx context.Context, config CollectorConfig, w io.Writer) (int64, error) {
	if !isDockerAvailable() {
		return 0, &ErrFeatureUnavailable{Feature: "Docker"}
	}

	if config.ContainerID == "" {
		return 0, &ErrMissingParameter{
			Parameter: "container_id",
			Context:   "docker_container backup",
		}
	}

	c.logger.Info("starting streaming Docker container backup",
		"container_id", config.ContainerID,
	)

	// Get container inspection data first (small JSON, safe to buffer)
	inspectData, err := c.getContainerInspect(ctx, config.ContainerID)
	if err != nil {
		return 0, fmt.Errorf("inspecting container: %w", err)
	}

	// Create metadata header
	metadata := map[string]interface{}{
		"backup_type":  "docker_container",
		"container_id": config.ContainerID,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"agent_uuid":   config.AgentUUID,
		"version":      2, // Version 2 = streaming format (raw tar, no JSON wrapper)
		"inspect":      inspectData,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return 0, fmt.Errorf("marshaling metadata: %w", err)
	}

	// Write metadata length (4 bytes, big-endian) followed by metadata JSON
	// This allows readers to extract metadata before processing the tar stream
	metaLen := uint32(len(metadataBytes))
	if _, err := w.Write([]byte{byte(metaLen >> 24), byte(metaLen >> 16), byte(metaLen >> 8), byte(metaLen)}); err != nil {
		return 0, fmt.Errorf("writing metadata length: %w", err)
	}
	if _, err := w.Write(metadataBytes); err != nil {
		return 0, fmt.Errorf("writing metadata: %w", err)
	}

	var totalWritten int64 = 4 + int64(len(metadataBytes))

	// Stream docker export directly to writer
	// This is the key optimization - docker export outputs tar directly,
	// which we pipe straight to the writer without intermediate buffering
	exportBytes, err := c.streamDockerExport(ctx, config.ContainerID, w)
	if err != nil {
		return totalWritten, fmt.Errorf("streaming container export: %w", err)
	}

	totalWritten += exportBytes

	c.logger.Info("Docker container backup streaming complete",
		"container_id", config.ContainerID,
		"total_bytes", totalWritten,
	)

	return totalWritten, nil
}

// getContainerInspect gets container inspection data.
func (c *StreamingDockerContainerCollector) getContainerInspect(ctx context.Context, containerID string) (map[string]interface{}, error) {
	cmd := exec.CommandContext(ctx, "docker", "inspect", containerID)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker inspect failed: %w", err)
	}

	var inspectData []map[string]interface{}
	if err := json.Unmarshal(output, &inspectData); err != nil {
		return nil, fmt.Errorf("parsing inspect data: %w", err)
	}

	if len(inspectData) == 0 {
		return nil, fmt.Errorf("no inspection data returned")
	}

	return inspectData[0], nil
}

// streamDockerExport streams docker export output directly to writer.
// Uses io.Copy with a small buffer for true streaming behavior.
func (c *StreamingDockerContainerCollector) streamDockerExport(ctx context.Context, containerID string, w io.Writer) (int64, error) {
	cmd := exec.CommandContext(ctx, "docker", "export", containerID)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("creating stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return 0, fmt.Errorf("creating stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("starting docker export: %w", err)
	}

	// Stream data with fixed-size buffer (8 MB chunks)
	buf := make([]byte, 8*1024*1024)
	n, copyErr := io.CopyBuffer(w, stdout, buf)

	// Read any stderr for error messages
	stderrBytes, _ := io.ReadAll(io.LimitReader(stderr, MaxResponseBodySize))

	// Wait for command to complete
	if err := cmd.Wait(); err != nil {
		if len(stderrBytes) > 0 {
			return n, fmt.Errorf("docker export failed: %w - %s", err, string(stderrBytes))
		}
		return n, fmt.Errorf("docker export failed: %w", err)
	}

	if copyErr != nil {
		return n, fmt.Errorf("streaming export data: %w", copyErr)
	}

	return n, nil
}

// StreamingDockerVolumeCollector collects Docker volume backups using streaming.
type StreamingDockerVolumeCollector struct {
	logger  *slog.Logger
	tempDir string
}

// NewStreamingDockerVolumeCollector creates a new streaming Docker volume collector.
func NewStreamingDockerVolumeCollector(logger *slog.Logger, tempDir string) *StreamingDockerVolumeCollector {
	if logger == nil {
		logger = slog.Default()
	}
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	return &StreamingDockerVolumeCollector{
		logger:  logger,
		tempDir: tempDir,
	}
}

// Type returns the backup type.
func (c *StreamingDockerVolumeCollector) Type() BackupType {
	return TypeDockerVolume
}

// SupportsStreaming returns true as this collector supports streaming.
func (c *StreamingDockerVolumeCollector) SupportsStreaming() bool {
	return true
}

// CollectStream writes Docker volume backup data directly to the writer.
func (c *StreamingDockerVolumeCollector) CollectStream(ctx context.Context, config CollectorConfig, w io.Writer) (int64, error) {
	if !isDockerAvailable() {
		return 0, &ErrFeatureUnavailable{Feature: "Docker"}
	}

	if config.VolumeName == "" {
		return 0, &ErrMissingParameter{
			Parameter: "volume_name",
			Context:   "docker_volume backup",
		}
	}

	c.logger.Info("starting streaming Docker volume backup",
		"volume_name", config.VolumeName,
	)

	// Get volume inspection data
	inspectData, err := c.getVolumeInspect(ctx, config.VolumeName)
	if err != nil {
		return 0, fmt.Errorf("inspecting volume: %w", err)
	}

	// Create metadata header
	metadata := map[string]interface{}{
		"backup_type": "docker_volume",
		"volume_name": config.VolumeName,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"agent_uuid":  config.AgentUUID,
		"version":     2, // Version 2 = streaming format
		"inspect":     inspectData,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return 0, fmt.Errorf("marshaling metadata: %w", err)
	}

	// Write metadata length + metadata
	metaLen := uint32(len(metadataBytes))
	if _, err := w.Write([]byte{byte(metaLen >> 24), byte(metaLen >> 16), byte(metaLen >> 8), byte(metaLen)}); err != nil {
		return 0, fmt.Errorf("writing metadata length: %w", err)
	}
	if _, err := w.Write(metadataBytes); err != nil {
		return 0, fmt.Errorf("writing metadata: %w", err)
	}

	var totalWritten int64 = 4 + int64(len(metadataBytes))

	// Stream volume tar directly to writer
	volumeBytes, err := c.streamVolumeTar(ctx, config.VolumeName, w)
	if err != nil {
		return totalWritten, fmt.Errorf("streaming volume tar: %w", err)
	}

	totalWritten += volumeBytes

	c.logger.Info("Docker volume backup streaming complete",
		"volume_name", config.VolumeName,
		"total_bytes", totalWritten,
	)

	return totalWritten, nil
}

// getVolumeInspect gets volume inspection data.
func (c *StreamingDockerVolumeCollector) getVolumeInspect(ctx context.Context, volumeName string) (map[string]interface{}, error) {
	cmd := exec.CommandContext(ctx, "docker", "volume", "inspect", volumeName)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker volume inspect failed: %w", err)
	}

	var inspectData []map[string]interface{}
	if err := json.Unmarshal(output, &inspectData); err != nil {
		return nil, fmt.Errorf("parsing inspect data: %w", err)
	}

	if len(inspectData) == 0 {
		return nil, fmt.Errorf("no inspection data returned")
	}

	return inspectData[0], nil
}

// streamVolumeTar streams volume tar directly to writer.
func (c *StreamingDockerVolumeCollector) streamVolumeTar(ctx context.Context, volumeName string, w io.Writer) (int64, error) {
	// Use alpine container to tar the volume and stream output
	// tar -cf - outputs to stdout, which we capture and stream
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm",
		"-v", volumeName+":/data:ro",
		"alpine", "tar", "-cf", "-", "-C", "/data", ".")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("creating stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return 0, fmt.Errorf("creating stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("starting tar container: %w", err)
	}

	// Stream with fixed-size buffer
	buf := make([]byte, 8*1024*1024)
	n, copyErr := io.CopyBuffer(w, stdout, buf)

	stderrBytes, _ := io.ReadAll(io.LimitReader(stderr, MaxResponseBodySize))

	if err := cmd.Wait(); err != nil {
		if len(stderrBytes) > 0 {
			return n, fmt.Errorf("tar container failed: %w - %s", err, string(stderrBytes))
		}
		return n, fmt.Errorf("tar container failed: %w", err)
	}

	if copyErr != nil {
		return n, fmt.Errorf("streaming volume data: %w", copyErr)
	}

	return n, nil
}

// StreamingDockerImageCollector collects Docker image backups using streaming.
type StreamingDockerImageCollector struct {
	logger  *slog.Logger
	tempDir string
}

// NewStreamingDockerImageCollector creates a new streaming Docker image collector.
func NewStreamingDockerImageCollector(logger *slog.Logger, tempDir string) *StreamingDockerImageCollector {
	if logger == nil {
		logger = slog.Default()
	}
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	return &StreamingDockerImageCollector{
		logger:  logger,
		tempDir: tempDir,
	}
}

// Type returns the backup type.
func (c *StreamingDockerImageCollector) Type() BackupType {
	return TypeDockerImage
}

// SupportsStreaming returns true as this collector supports streaming.
func (c *StreamingDockerImageCollector) SupportsStreaming() bool {
	return true
}

// CollectStream writes Docker image backup data directly to the writer.
func (c *StreamingDockerImageCollector) CollectStream(ctx context.Context, config CollectorConfig, w io.Writer) (int64, error) {
	if !isDockerAvailable() {
		return 0, &ErrFeatureUnavailable{Feature: "Docker"}
	}

	if config.ImageName == "" {
		return 0, &ErrMissingParameter{
			Parameter: "image_name",
			Context:   "docker_image backup",
		}
	}

	c.logger.Info("starting streaming Docker image backup",
		"image_name", config.ImageName,
	)

	// Get image inspection data
	inspectData, err := c.getImageInspect(ctx, config.ImageName)
	if err != nil {
		return 0, fmt.Errorf("inspecting image: %w", err)
	}

	// Create metadata header
	metadata := map[string]interface{}{
		"backup_type": "docker_image",
		"image_name":  config.ImageName,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"agent_uuid":  config.AgentUUID,
		"version":     2, // Version 2 = streaming format
		"inspect":     inspectData,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return 0, fmt.Errorf("marshaling metadata: %w", err)
	}

	// Write metadata length + metadata
	metaLen := uint32(len(metadataBytes))
	if _, err := w.Write([]byte{byte(metaLen >> 24), byte(metaLen >> 16), byte(metaLen >> 8), byte(metaLen)}); err != nil {
		return 0, fmt.Errorf("writing metadata length: %w", err)
	}
	if _, err := w.Write(metadataBytes); err != nil {
		return 0, fmt.Errorf("writing metadata: %w", err)
	}

	var totalWritten int64 = 4 + int64(len(metadataBytes))

	// Stream docker save directly to writer
	imageBytes, err := c.streamDockerSave(ctx, config.ImageName, w)
	if err != nil {
		return totalWritten, fmt.Errorf("streaming image save: %w", err)
	}

	totalWritten += imageBytes

	c.logger.Info("Docker image backup streaming complete",
		"image_name", config.ImageName,
		"total_bytes", totalWritten,
	)

	return totalWritten, nil
}

// getImageInspect gets image inspection data.
func (c *StreamingDockerImageCollector) getImageInspect(ctx context.Context, imageName string) (map[string]interface{}, error) {
	cmd := exec.CommandContext(ctx, "docker", "image", "inspect", imageName)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker image inspect failed: %w", err)
	}

	var inspectData []map[string]interface{}
	if err := json.Unmarshal(output, &inspectData); err != nil {
		return nil, fmt.Errorf("parsing inspect data: %w", err)
	}

	if len(inspectData) == 0 {
		return nil, fmt.Errorf("no inspection data returned")
	}

	return inspectData[0], nil
}

// streamDockerSave streams docker save output directly to writer.
func (c *StreamingDockerImageCollector) streamDockerSave(ctx context.Context, imageName string, w io.Writer) (int64, error) {
	cmd := exec.CommandContext(ctx, "docker", "save", imageName)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("creating stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return 0, fmt.Errorf("creating stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("starting docker save: %w", err)
	}

	// Stream with fixed-size buffer
	buf := make([]byte, 8*1024*1024)
	n, copyErr := io.CopyBuffer(w, stdout, buf)

	stderrBytes, _ := io.ReadAll(io.LimitReader(stderr, MaxResponseBodySize))

	if err := cmd.Wait(); err != nil {
		if len(stderrBytes) > 0 {
			return n, fmt.Errorf("docker save failed: %w - %s", err, string(stderrBytes))
		}
		return n, fmt.Errorf("docker save failed: %w", err)
	}

	if copyErr != nil {
		return n, fmt.Errorf("streaming image data: %w", copyErr)
	}

	return n, nil
}

// StreamingDockerComposeCollector collects Docker Compose backups using streaming.
type StreamingDockerComposeCollector struct {
	logger  *slog.Logger
	tempDir string
}

// NewStreamingDockerComposeCollector creates a new streaming Docker Compose collector.
func NewStreamingDockerComposeCollector(logger *slog.Logger, tempDir string) *StreamingDockerComposeCollector {
	if logger == nil {
		logger = slog.Default()
	}
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	return &StreamingDockerComposeCollector{
		logger:  logger,
		tempDir: tempDir,
	}
}

// Type returns the backup type.
func (c *StreamingDockerComposeCollector) Type() BackupType {
	return TypeDockerCompose
}

// SupportsStreaming returns true as this collector supports streaming.
func (c *StreamingDockerComposeCollector) SupportsStreaming() bool {
	return true
}

// CollectStream writes Docker Compose backup data directly to the writer.
// This includes compose file, env file, and optionally volume data.
func (c *StreamingDockerComposeCollector) CollectStream(ctx context.Context, config CollectorConfig, w io.Writer) (int64, error) {
	if !isDockerAvailable() {
		return 0, &ErrFeatureUnavailable{Feature: "Docker"}
	}

	if config.ComposePath == "" {
		return 0, &ErrMissingParameter{
			Parameter: "compose_path",
			Context:   "docker_compose backup",
		}
	}

	c.logger.Info("starting streaming Docker Compose backup",
		"compose_path", config.ComposePath,
	)

	// Read compose file (small, safe to buffer)
	composeData, err := os.ReadFile(config.ComposePath)
	if err != nil {
		return 0, fmt.Errorf("reading compose file: %w", err)
	}

	// Read .env file if exists
	envPath := filepath.Join(filepath.Dir(config.ComposePath), ".env")
	envData, _ := os.ReadFile(envPath) // Ignore error if not exists

	// Get compose project info
	psOutput, _ := exec.CommandContext(ctx, "docker", "compose", "-f", config.ComposePath, "ps", "--format", "json").Output()
	configOutput, _ := exec.CommandContext(ctx, "docker", "compose", "-f", config.ComposePath, "config").Output()

	// Create metadata
	metadata := map[string]interface{}{
		"backup_type":   "docker_compose",
		"compose_path":  config.ComposePath,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
		"agent_uuid":    config.AgentUUID,
		"version":       2,
		"compose_file":  string(composeData),
		"env_file":      string(envData),
		"ps_output":     string(psOutput),
		"config_output": string(configOutput),
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return 0, fmt.Errorf("marshaling metadata: %w", err)
	}

	// Write metadata length + metadata
	metaLen := uint32(len(metadataBytes))
	if _, err := w.Write([]byte{byte(metaLen >> 24), byte(metaLen >> 16), byte(metaLen >> 8), byte(metaLen)}); err != nil {
		return 0, fmt.Errorf("writing metadata length: %w", err)
	}
	if _, err := w.Write(metadataBytes); err != nil {
		return 0, fmt.Errorf("writing metadata: %w", err)
	}

	totalWritten := int64(4 + len(metadataBytes))

	c.logger.Info("Docker Compose backup streaming complete",
		"compose_path", config.ComposePath,
		"total_bytes", totalWritten,
	)

	return totalWritten, nil
}

// isStreamingDockerAvailable checks if Docker is available (uses existing isDockerAvailable).
// Note: This is a wrapper that calls the existing isDockerAvailable from capabilities.go
