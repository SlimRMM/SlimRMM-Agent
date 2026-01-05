// Package actions provides Docker container management functionality.
package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// DockerContainer represents a Docker container.
type DockerContainer struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Image     string            `json:"image"`
	ImageID   string            `json:"image_id"`
	Command   string            `json:"command"`
	Created   int64             `json:"created"`
	CreatedAt string            `json:"created_at"`
	State     string            `json:"state"`
	Status    string            `json:"status"`
	Ports     []DockerPort      `json:"ports"`
	Labels    map[string]string `json:"labels"`
	Networks  []string          `json:"networks"`
	SizeRw    int64             `json:"size_rw,omitempty"`
	SizeRootFs int64            `json:"size_root_fs,omitempty"`
}

// DockerPort represents a port mapping.
type DockerPort struct {
	IP          string `json:"ip,omitempty"`
	PrivatePort int    `json:"private_port"`
	PublicPort  int    `json:"public_port,omitempty"`
	Type        string `json:"type"`
}

// DockerImage represents a Docker image.
type DockerImage struct {
	ID          string            `json:"id"`
	RepoTags    []string          `json:"repo_tags"`
	RepoDigests []string          `json:"repo_digests"`
	Created     int64             `json:"created"`
	CreatedAt   string            `json:"created_at"`
	Size        int64             `json:"size"`
	VirtualSize int64             `json:"virtual_size"`
	Labels      map[string]string `json:"labels"`
	Containers  int               `json:"containers"`
}

// DockerVolume represents a Docker volume.
type DockerVolume struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Mountpoint string            `json:"mountpoint"`
	CreatedAt  string            `json:"created_at"`
	Labels     map[string]string `json:"labels"`
	Scope      string            `json:"scope"`
	Options    map[string]string `json:"options"`
	UsageData  *VolumeUsageData  `json:"usage_data,omitempty"`
}

// VolumeUsageData represents volume usage statistics.
type VolumeUsageData struct {
	Size     int64 `json:"size"`
	RefCount int64 `json:"ref_count"`
}

// DockerNetwork represents a Docker network.
type DockerNetwork struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Scope      string            `json:"scope"`
	EnableIPv6 bool              `json:"enable_ipv6"`
	Internal   bool              `json:"internal"`
	Attachable bool              `json:"attachable"`
	Ingress    bool              `json:"ingress"`
	Options    map[string]string `json:"options"`
	Labels     map[string]string `json:"labels"`
	Containers map[string]string `json:"containers"`
}

// DockerInfo represents Docker system information.
type DockerInfo struct {
	Available         bool   `json:"available"`
	Version           string `json:"version"`
	APIVersion        string `json:"api_version"`
	OS                string `json:"os"`
	Arch              string `json:"arch"`
	KernelVersion     string `json:"kernel_version"`
	Containers        int    `json:"containers"`
	ContainersRunning int    `json:"containers_running"`
	ContainersPaused  int    `json:"containers_paused"`
	ContainersStopped int    `json:"containers_stopped"`
	Images            int    `json:"images"`
	Driver            string `json:"driver"`
	MemoryLimit       bool   `json:"memory_limit"`
	SwapLimit         bool   `json:"swap_limit"`
	CPUCfsPeriod      bool   `json:"cpu_cfs_period"`
	CPUCfsQuota       bool   `json:"cpu_cfs_quota"`
}

// DockerContainerStats represents container resource statistics.
type DockerContainerStats struct {
	ContainerID   string  `json:"container_id"`
	Name          string  `json:"name"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryUsage   int64   `json:"memory_usage"`
	MemoryLimit   int64   `json:"memory_limit"`
	MemoryPercent float64 `json:"memory_percent"`
	NetworkRx     int64   `json:"network_rx"`
	NetworkTx     int64   `json:"network_tx"`
	BlockRead     int64   `json:"block_read"`
	BlockWrite    int64   `json:"block_write"`
	PIDs          int     `json:"pids"`
}

// DockerContainerLogs represents container logs.
type DockerContainerLogs struct {
	ContainerID string   `json:"container_id"`
	Logs        []string `json:"logs"`
	Timestamps  bool     `json:"timestamps"`
	Tail        int      `json:"tail"`
}

// IsDockerAvailable checks if Docker is installed and running.
func IsDockerAvailable() bool {
	cmd := exec.Command("docker", "version", "--format", "{{.Server.Version}}")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// GetDockerInfo returns Docker system information.
func GetDockerInfo(ctx context.Context) (*DockerInfo, error) {
	if !IsDockerAvailable() {
		return &DockerInfo{Available: false}, nil
	}

	cmd := exec.CommandContext(ctx, "docker", "info", "--format", "{{json .}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker info: %w", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(output, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse docker info: %w", err)
	}

	info := &DockerInfo{
		Available:         true,
		Containers:        getInt(raw, "Containers"),
		ContainersRunning: getInt(raw, "ContainersRunning"),
		ContainersPaused:  getInt(raw, "ContainersPaused"),
		ContainersStopped: getInt(raw, "ContainersStopped"),
		Images:            getInt(raw, "Images"),
		Driver:            getString(raw, "Driver"),
		KernelVersion:     getString(raw, "KernelVersion"),
		OS:                getString(raw, "OperatingSystem"),
		Arch:              getString(raw, "Architecture"),
	}

	// Get version info
	versionCmd := exec.CommandContext(ctx, "docker", "version", "--format", "{{json .}}")
	versionOutput, err := versionCmd.Output()
	if err == nil {
		var versionRaw map[string]interface{}
		if json.Unmarshal(versionOutput, &versionRaw) == nil {
			if server, ok := versionRaw["Server"].(map[string]interface{}); ok {
				info.Version = getString(server, "Version")
				info.APIVersion = getString(server, "APIVersion")
			}
		}
	}

	return info, nil
}

// ListDockerContainers lists all Docker containers.
func ListDockerContainers(ctx context.Context, all bool) ([]DockerContainer, error) {
	args := []string{"ps", "--format", "{{json .}}"}
	if all {
		args = append(args, "-a")
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var containers []DockerContainer
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}

		container := DockerContainer{
			ID:      getString(raw, "ID"),
			Name:    strings.TrimPrefix(getString(raw, "Names"), "/"),
			Image:   getString(raw, "Image"),
			Command: getString(raw, "Command"),
			Status:  getString(raw, "Status"),
			State:   getString(raw, "State"),
		}

		// Parse ports
		portsStr := getString(raw, "Ports")
		if portsStr != "" {
			container.Ports = parsePorts(portsStr)
		}

		// Parse networks
		networksStr := getString(raw, "Networks")
		if networksStr != "" {
			container.Networks = strings.Split(networksStr, ",")
		}

		containers = append(containers, container)
	}

	return containers, nil
}

// DockerContainerAction performs an action on a container.
func DockerContainerAction(ctx context.Context, containerID, action string) error {
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

// RemoveDockerContainer removes a container.
func RemoveDockerContainer(ctx context.Context, containerID string, force bool) error {
	args := []string{"rm", containerID}
	if force {
		args = []string{"rm", "-f", containerID}
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to remove container: %s", string(output))
	}
	return nil
}

// GetDockerContainerLogs retrieves container logs.
func GetDockerContainerLogs(ctx context.Context, containerID string, tail int, timestamps bool) (*DockerContainerLogs, error) {
	args := []string{"logs"}
	if tail > 0 {
		args = append(args, "--tail", strconv.Itoa(tail))
	}
	if timestamps {
		args = append(args, "--timestamps")
	}
	args = append(args, containerID)

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get logs: %w", err)
	}

	logs := strings.Split(strings.TrimSpace(string(output)), "\n")
	return &DockerContainerLogs{
		ContainerID: containerID,
		Logs:        logs,
		Timestamps:  timestamps,
		Tail:        tail,
	}, nil
}

// GetDockerContainerStats retrieves container resource statistics.
func GetDockerContainerStats(ctx context.Context, containerID string) (*DockerContainerStats, error) {
	cmd := exec.CommandContext(ctx, "docker", "stats", "--no-stream", "--format", "{{json .}}", containerID)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(output, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse stats: %w", err)
	}

	stats := &DockerContainerStats{
		ContainerID: containerID,
		Name:        getString(raw, "Name"),
	}

	// Parse CPU percent
	cpuStr := getString(raw, "CPUPerc")
	cpuStr = strings.TrimSuffix(cpuStr, "%")
	stats.CPUPercent, _ = strconv.ParseFloat(cpuStr, 64)

	// Parse memory
	memStr := getString(raw, "MemPerc")
	memStr = strings.TrimSuffix(memStr, "%")
	stats.MemoryPercent, _ = strconv.ParseFloat(memStr, 64)

	// Parse PIDs
	stats.PIDs, _ = strconv.Atoi(getString(raw, "PIDs"))

	return stats, nil
}

// ListDockerImages lists all Docker images.
func ListDockerImages(ctx context.Context) ([]DockerImage, error) {
	cmd := exec.CommandContext(ctx, "docker", "images", "--format", "{{json .}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list images: %w", err)
	}

	var images []DockerImage
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}

		image := DockerImage{
			ID: getString(raw, "ID"),
		}

		// Build repo tags
		repo := getString(raw, "Repository")
		tag := getString(raw, "Tag")
		if repo != "<none>" && tag != "<none>" {
			image.RepoTags = []string{repo + ":" + tag}
		}

		// Parse size
		sizeStr := getString(raw, "Size")
		image.Size = parseSize(sizeStr)

		image.CreatedAt = getString(raw, "CreatedAt")

		images = append(images, image)
	}

	return images, nil
}

// RemoveDockerImage removes an image.
func RemoveDockerImage(ctx context.Context, imageID string, force bool) error {
	args := []string{"rmi", imageID}
	if force {
		args = []string{"rmi", "-f", imageID}
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to remove image: %s", string(output))
	}
	return nil
}

// PullDockerImage pulls an image from a registry.
func PullDockerImage(ctx context.Context, imageName string) error {
	cmd := exec.CommandContext(ctx, "docker", "pull", imageName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to pull image: %s", string(output))
	}
	return nil
}

// ListDockerVolumes lists all Docker volumes.
func ListDockerVolumes(ctx context.Context) ([]DockerVolume, error) {
	cmd := exec.CommandContext(ctx, "docker", "volume", "ls", "--format", "{{json .}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list volumes: %w", err)
	}

	var volumes []DockerVolume
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}

		volume := DockerVolume{
			Name:       getString(raw, "Name"),
			Driver:     getString(raw, "Driver"),
			Mountpoint: getString(raw, "Mountpoint"),
			Scope:      getString(raw, "Scope"),
		}

		volumes = append(volumes, volume)
	}

	return volumes, nil
}

// RemoveDockerVolume removes a volume.
func RemoveDockerVolume(ctx context.Context, volumeName string, force bool) error {
	args := []string{"volume", "rm", volumeName}
	if force {
		args = []string{"volume", "rm", "-f", volumeName}
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to remove volume: %s", string(output))
	}
	return nil
}

// ListDockerNetworks lists all Docker networks.
func ListDockerNetworks(ctx context.Context) ([]DockerNetwork, error) {
	cmd := exec.CommandContext(ctx, "docker", "network", "ls", "--format", "{{json .}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	var networks []DockerNetwork
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}

		network := DockerNetwork{
			ID:     getString(raw, "ID"),
			Name:   getString(raw, "Name"),
			Driver: getString(raw, "Driver"),
			Scope:  getString(raw, "Scope"),
		}

		networks = append(networks, network)
	}

	return networks, nil
}

// DockerComposeAction performs a Docker Compose action.
func DockerComposeAction(ctx context.Context, projectPath, action string) error {
	validActions := map[string][]string{
		"up":      {"up", "-d"},
		"down":    {"down"},
		"restart": {"restart"},
		"pull":    {"pull"},
		"logs":    {"logs", "--tail", "100"},
	}

	args, ok := validActions[action]
	if !ok {
		return fmt.Errorf("invalid compose action: %s", action)
	}

	// Prepend compose command and project path
	fullArgs := []string{"compose", "-f", projectPath}
	fullArgs = append(fullArgs, args...)

	cmd := exec.CommandContext(ctx, "docker", fullArgs...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to %s compose: %s", action, string(output))
	}
	return nil
}

// InspectDockerContainer returns detailed container information.
func InspectDockerContainer(ctx context.Context, containerID string) (map[string]interface{}, error) {
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
		return nil, fmt.Errorf("container not found")
	}

	return result[0], nil
}

// ExecInDockerContainer executes a command in a container.
func ExecInDockerContainer(ctx context.Context, containerID string, command []string, timeout time.Duration) (map[string]interface{}, error) {
	args := []string{"exec", containerID}
	args = append(args, command...)

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, "docker", args...)
	output, err := cmd.CombinedOutput()

	result := map[string]interface{}{
		"stdout":    string(output),
		"stderr":    "",
		"exit_code": 0,
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result["exit_code"] = exitErr.ExitCode()
		} else {
			result["exit_code"] = -1
			result["stderr"] = err.Error()
		}
	}

	return result, nil
}

// Helper functions

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
	}
	return 0
}

func parsePorts(portsStr string) []DockerPort {
	var ports []DockerPort
	parts := strings.Split(portsStr, ", ")
	for _, part := range parts {
		port := DockerPort{}
		if strings.Contains(part, "->") {
			// Has mapping: 0.0.0.0:8080->80/tcp
			mapping := strings.Split(part, "->")
			if len(mapping) == 2 {
				hostPart := mapping[0]
				containerPart := mapping[1]

				// Parse host part
				if strings.Contains(hostPart, ":") {
					hostParts := strings.Split(hostPart, ":")
					port.IP = hostParts[0]
					port.PublicPort, _ = strconv.Atoi(hostParts[1])
				}

				// Parse container part
				if strings.Contains(containerPart, "/") {
					containerParts := strings.Split(containerPart, "/")
					port.PrivatePort, _ = strconv.Atoi(containerParts[0])
					port.Type = containerParts[1]
				}
			}
		} else {
			// No mapping: 80/tcp
			if strings.Contains(part, "/") {
				parts := strings.Split(part, "/")
				port.PrivatePort, _ = strconv.Atoi(parts[0])
				port.Type = parts[1]
			}
		}
		if port.PrivatePort > 0 {
			ports = append(ports, port)
		}
	}
	return ports
}

func parseSize(sizeStr string) int64 {
	sizeStr = strings.TrimSpace(sizeStr)
	if sizeStr == "" {
		return 0
	}

	multipliers := map[string]int64{
		"B":  1,
		"KB": 1024,
		"MB": 1024 * 1024,
		"GB": 1024 * 1024 * 1024,
		"TB": 1024 * 1024 * 1024 * 1024,
	}

	for suffix, mult := range multipliers {
		if strings.HasSuffix(strings.ToUpper(sizeStr), suffix) {
			numStr := strings.TrimSuffix(strings.ToUpper(sizeStr), suffix)
			numStr = strings.TrimSpace(numStr)
			if num, err := strconv.ParseFloat(numStr, 64); err == nil {
				return int64(num * float64(mult))
			}
		}
	}

	return 0
}

// =============================================================================
// Docker Policy Actions
// =============================================================================

// DockerPruneResult represents the result of a prune operation.
type DockerPruneResult struct {
	Type           string   `json:"type"`
	ReclaimedSpace int64    `json:"reclaimed_space"`
	DeletedItems   []string `json:"deleted_items"`
}

// PruneDockerImages removes unused Docker images.
func PruneDockerImages(ctx context.Context, danglingOnly bool, olderThanHours int) (*DockerPruneResult, error) {
	args := []string{"image", "prune", "-f"}
	if !danglingOnly {
		args = append(args, "-a")
	}
	if olderThanHours > 0 {
		args = append(args, "--filter", fmt.Sprintf("until=%dh", olderThanHours))
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to prune images: %s", string(output))
	}

	return &DockerPruneResult{
		Type:         "images",
		DeletedItems: parseDeletedItems(string(output)),
	}, nil
}

// PruneDockerVolumes removes unused Docker volumes.
func PruneDockerVolumes(ctx context.Context) (*DockerPruneResult, error) {
	cmd := exec.CommandContext(ctx, "docker", "volume", "prune", "-f")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to prune volumes: %s", string(output))
	}

	return &DockerPruneResult{
		Type:         "volumes",
		DeletedItems: parseDeletedItems(string(output)),
	}, nil
}

// PruneDockerNetworks removes unused Docker networks.
func PruneDockerNetworks(ctx context.Context) (*DockerPruneResult, error) {
	cmd := exec.CommandContext(ctx, "docker", "network", "prune", "-f")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to prune networks: %s", string(output))
	}

	return &DockerPruneResult{
		Type:         "networks",
		DeletedItems: parseDeletedItems(string(output)),
	}, nil
}

// PruneDockerSystem removes all unused Docker resources.
func PruneDockerSystem(ctx context.Context, danglingOnly bool, olderThanHours int) (*DockerPruneResult, error) {
	args := []string{"system", "prune", "-f"}
	if !danglingOnly {
		args = append(args, "-a")
	}
	args = append(args, "--volumes")
	if olderThanHours > 0 {
		args = append(args, "--filter", fmt.Sprintf("until=%dh", olderThanHours))
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to prune system: %s", string(output))
	}

	return &DockerPruneResult{
		Type:         "system",
		DeletedItems: parseDeletedItems(string(output)),
	}, nil
}

// RestartUnhealthyContainers restarts containers with failed health checks.
func RestartUnhealthyContainers(ctx context.Context, timeout int, maxRetries int) ([]map[string]interface{}, error) {
	// Get all containers with health status
	cmd := exec.CommandContext(ctx, "docker", "ps", "-a", "--filter", "health=unhealthy", "--format", "{{.ID}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list unhealthy containers: %w", err)
	}

	var results []map[string]interface{}
	containerIDs := strings.Split(strings.TrimSpace(string(output)), "\n")

	for _, containerID := range containerIDs {
		if containerID == "" {
			continue
		}

		result := map[string]interface{}{
			"container_id": containerID,
			"action":       "restart",
		}

		// Try to restart with retries
		var lastErr error
		for attempt := 0; attempt < maxRetries; attempt++ {
			restartCmd := exec.CommandContext(ctx, "docker", "restart", "-t", strconv.Itoa(timeout), containerID)
			if _, err := restartCmd.CombinedOutput(); err == nil {
				result["success"] = true
				result["attempts"] = attempt + 1
				lastErr = nil
				break
			} else {
				lastErr = err
			}
		}

		if lastErr != nil {
			result["success"] = false
			result["error"] = lastErr.Error()
		}

		results = append(results, result)
	}

	return results, nil
}

// UpdateDockerImages pulls latest images and optionally recreates containers.
func UpdateDockerImages(ctx context.Context, pullLatest bool, recreateContainers bool) ([]map[string]interface{}, error) {
	var results []map[string]interface{}

	if !pullLatest {
		return results, nil
	}

	// Get list of running containers with their images
	cmd := exec.CommandContext(ctx, "docker", "ps", "--format", "{{.ID}}:{{.Image}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	pulledImages := make(map[string]bool)

	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		containerID := parts[0]
		imageName := parts[1]

		result := map[string]interface{}{
			"container_id": containerID,
			"image":        imageName,
		}

		// Pull the image if not already pulled
		if !pulledImages[imageName] {
			pullCmd := exec.CommandContext(ctx, "docker", "pull", imageName)
			if _, err := pullCmd.CombinedOutput(); err != nil {
				result["pull_success"] = false
				result["pull_error"] = err.Error()
				results = append(results, result)
				continue
			}
			pulledImages[imageName] = true
			result["pull_success"] = true
		}

		// Recreate container if requested
		if recreateContainers {
			// This would need docker-compose or manual recreation
			// For now just report that the image was updated
			result["recreated"] = false
			result["note"] = "container recreation requires docker-compose"
		}

		results = append(results, result)
	}

	return results, nil
}

// GetDockerHealthCheck checks health status of all containers.
func GetDockerHealthCheck(ctx context.Context) ([]map[string]interface{}, error) {
	cmd := exec.CommandContext(ctx, "docker", "ps", "-a", "--format", "{{json .}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var results []map[string]interface{}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}
		var raw map[string]interface{}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}

		status := getString(raw, "Status")
		health := "none"

		// Parse health from status string
		if strings.Contains(status, "(healthy)") {
			health = "healthy"
		} else if strings.Contains(status, "(unhealthy)") {
			health = "unhealthy"
		} else if strings.Contains(status, "(starting)") {
			health = "starting"
		}

		results = append(results, map[string]interface{}{
			"container_id": getString(raw, "ID"),
			"name":         strings.TrimPrefix(getString(raw, "Names"), "/"),
			"state":        getString(raw, "State"),
			"status":       status,
			"health":       health,
		})
	}

	return results, nil
}

func parseDeletedItems(output string) []string {
	var items []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip summary lines
		if line == "" || strings.HasPrefix(line, "Total") || strings.HasPrefix(line, "deleted") {
			continue
		}
		// SHA256 hashes are deleted items
		if len(line) == 64 || len(line) == 12 {
			items = append(items, line)
		}
	}
	return items
}
