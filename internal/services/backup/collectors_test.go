package backup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Mock implementations for testing

type mockAgentConfig struct {
	uuid        string
	mtlsEnabled bool
}

func (m *mockAgentConfig) GetUUID() string      { return m.uuid }
func (m *mockAgentConfig) IsMTLSEnabled() bool { return m.mtlsEnabled }

type mockLogger struct{}

func (m *mockLogger) Info(msg string, args ...interface{})  {}
func (m *mockLogger) Warn(msg string, args ...interface{})  {}
func (m *mockLogger) Error(msg string, args ...interface{}) {}
func (m *mockLogger) Debug(msg string, args ...interface{}) {}

type mockDockerDeps struct {
	available bool
}

func (m *mockDockerDeps) IsDockerAvailable() bool { return m.available }
func (m *mockDockerDeps) InspectContainer(ctx context.Context, containerID string) (map[string]interface{}, error) {
	return map[string]interface{}{"Id": containerID}, nil
}
func (m *mockDockerDeps) GetContainerStats(ctx context.Context, containerID string) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}
func (m *mockDockerDeps) GetContainerLogs(ctx context.Context, containerID string, lines int, timestamps bool) (string, error) {
	return "", nil
}
func (m *mockDockerDeps) ListContainers(ctx context.Context, all bool) ([]ContainerInfo, error) {
	return nil, nil
}
func (m *mockDockerDeps) ContainerAction(ctx context.Context, containerID, action string) error {
	return nil
}
func (m *mockDockerDeps) InspectVolume(ctx context.Context, volumeName string) (map[string]interface{}, error) {
	return map[string]interface{}{"Name": volumeName}, nil
}
func (m *mockDockerDeps) InspectImage(ctx context.Context, imageName string) (map[string]interface{}, error) {
	return map[string]interface{}{"Id": imageName}, nil
}

type mockOsqueryClient struct {
	available bool
}

func (m *mockOsqueryClient) IsAvailable() bool { return m.available }
func (m *mockOsqueryClient) GetSystemInfo(ctx context.Context) (*OsqueryResult, error) {
	return &OsqueryResult{Rows: []map[string]string{{"hostname": "test"}}}, nil
}
func (m *mockOsqueryClient) Query(ctx context.Context, query string) (*OsqueryResult, error) {
	return &OsqueryResult{Rows: []map[string]string{}}, nil
}

// Tests

func TestDockerContainerCollectorType(t *testing.T) {
	collector := NewDockerContainerCollector(&mockDockerDeps{}, &mockLogger{})
	if collector.Type() != TypeDockerContainer {
		t.Errorf("Type = %s, want docker_container", collector.Type())
	}
}

func TestDockerContainerCollectorDockerNotAvailable(t *testing.T) {
	collector := NewDockerContainerCollector(&mockDockerDeps{available: false}, &mockLogger{})
	_, err := collector.Collect(context.Background(), CollectorConfig{ContainerID: "test"})
	if err == nil {
		t.Error("expected error when Docker is not available")
	}
	if _, ok := err.(*ErrFeatureUnavailable); !ok {
		t.Errorf("expected ErrFeatureUnavailable, got %T", err)
	}
}

func TestDockerContainerCollectorMissingID(t *testing.T) {
	collector := NewDockerContainerCollector(&mockDockerDeps{available: true}, &mockLogger{})
	_, err := collector.Collect(context.Background(), CollectorConfig{})
	if err == nil {
		t.Error("expected error when container_id is missing")
	}
	if _, ok := err.(*ErrMissingParameter); !ok {
		t.Errorf("expected ErrMissingParameter, got %T", err)
	}
}

func TestDockerVolumeCollectorType(t *testing.T) {
	collector := NewDockerVolumeCollector(&mockDockerDeps{}, &mockLogger{})
	if collector.Type() != TypeDockerVolume {
		t.Errorf("Type = %s, want docker_volume", collector.Type())
	}
}

func TestDockerImageCollectorType(t *testing.T) {
	collector := NewDockerImageCollector(&mockDockerDeps{}, &mockLogger{})
	if collector.Type() != TypeDockerImage {
		t.Errorf("Type = %s, want docker_image", collector.Type())
	}
}

func TestDockerComposeCollectorType(t *testing.T) {
	collector := NewDockerComposeCollector(&mockLogger{})
	if collector.Type() != TypeDockerCompose {
		t.Errorf("Type = %s, want docker_compose", collector.Type())
	}
}

func TestAgentConfigCollectorType(t *testing.T) {
	collector := NewAgentConfigCollector(AgentPaths{}, &mockAgentConfig{})
	if collector.Type() != TypeAgentConfig {
		t.Errorf("Type = %s, want agent_config", collector.Type())
	}
}

func TestAgentConfigCollectorCollect(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	os.WriteFile(configPath, []byte(`{"test": true}`), 0644)

	paths := AgentPaths{ConfigFile: configPath}
	config := &mockAgentConfig{uuid: "test-uuid"}
	collector := NewAgentConfigCollector(paths, config)

	data, err := collector.Collect(context.Background(), CollectorConfig{})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty data")
	}
}

func TestAgentLogsCollectorType(t *testing.T) {
	collector := NewAgentLogsCollector(AgentPaths{}, &mockAgentConfig{}, &mockLogger{})
	if collector.Type() != TypeAgentLogs {
		t.Errorf("Type = %s, want agent_logs", collector.Type())
	}
}

func TestAgentLogsCollectorCollect(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	os.WriteFile(logFile, []byte("test log content"), 0644)

	paths := AgentPaths{LogDir: tmpDir}
	config := &mockAgentConfig{uuid: "test-uuid"}
	collector := NewAgentLogsCollector(paths, config, &mockLogger{})

	data, err := collector.Collect(context.Background(), CollectorConfig{})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty data")
	}
}

func TestSystemStateCollectorType(t *testing.T) {
	collector := NewSystemStateCollector(&mockAgentConfig{}, &mockOsqueryClient{})
	if collector.Type() != TypeSystemState {
		t.Errorf("Type = %s, want system_state", collector.Type())
	}
}

func TestSystemStateCollectorCollect(t *testing.T) {
	config := &mockAgentConfig{uuid: "test-uuid"}
	osquery := &mockOsqueryClient{available: true}
	collector := NewSystemStateCollector(config, osquery)

	data, err := collector.Collect(context.Background(), CollectorConfig{})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty data")
	}
}

func TestSoftwareInventoryCollectorType(t *testing.T) {
	collector := NewSoftwareInventoryCollector(&mockAgentConfig{}, &mockOsqueryClient{})
	if collector.Type() != TypeSoftwareInventory {
		t.Errorf("Type = %s, want software_inventory", collector.Type())
	}
}

func TestComplianceResultsCollectorType(t *testing.T) {
	collector := NewComplianceResultsCollector(&mockAgentConfig{}, "")
	if collector.Type() != TypeComplianceResults {
		t.Errorf("Type = %s, want compliance_results", collector.Type())
	}
}

func TestFilesAndFoldersCollectorType(t *testing.T) {
	collector := NewFilesAndFoldersCollector(&mockAgentConfig{}, &mockLogger{})
	if collector.Type() != TypeFilesAndFolders {
		t.Errorf("Type = %s, want files_and_folders", collector.Type())
	}
}

func TestFilesAndFoldersCollectorMissingPaths(t *testing.T) {
	collector := NewFilesAndFoldersCollector(&mockAgentConfig{}, &mockLogger{})
	_, err := collector.Collect(context.Background(), CollectorConfig{})
	if err == nil {
		t.Error("expected error when paths is missing")
	}
	if _, ok := err.(*ErrMissingParameter); !ok {
		t.Errorf("expected ErrMissingParameter, got %T", err)
	}
}

func TestFilesAndFoldersCollectorCollect(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(testFile, []byte("test content"), 0644)

	config := &mockAgentConfig{uuid: "test-uuid"}
	collector := NewFilesAndFoldersCollector(config, &mockLogger{})

	data, err := collector.Collect(context.Background(), CollectorConfig{
		Paths:     []string{tmpDir},
		AgentUUID: "test-uuid",
	})
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty data")
	}
}

func TestProxmoxVMCollectorType(t *testing.T) {
	collector := NewProxmoxVMCollector(nil, &mockAgentConfig{}, &mockLogger{})
	if collector.Type() != TypeProxmoxVM {
		t.Errorf("Type = %s, want proxmox_vm", collector.Type())
	}
}

func TestProxmoxLXCCollectorType(t *testing.T) {
	collector := NewProxmoxLXCCollector(nil, &mockAgentConfig{}, &mockLogger{})
	if collector.Type() != TypeProxmoxLXC {
		t.Errorf("Type = %s, want proxmox_lxc", collector.Type())
	}
}

func TestProxmoxConfigCollectorType(t *testing.T) {
	collector := NewProxmoxConfigCollector(nil, &mockAgentConfig{}, &mockLogger{})
	if collector.Type() != TypeProxmoxConfig {
		t.Errorf("Type = %s, want proxmox_config", collector.Type())
	}
}

func TestHyperVVMCollectorType(t *testing.T) {
	collector := NewHyperVVMCollector(&mockAgentConfig{}, &mockLogger{})
	if collector.Type() != TypeHyperVVM {
		t.Errorf("Type = %s, want hyperv_vm", collector.Type())
	}
}

func TestHyperVCheckpointCollectorType(t *testing.T) {
	collector := NewHyperVCheckpointCollector(&mockAgentConfig{}, &mockLogger{})
	if collector.Type() != TypeHyperVCheckpoint {
		t.Errorf("Type = %s, want hyperv_checkpoint", collector.Type())
	}
}

func TestHyperVConfigCollectorType(t *testing.T) {
	collector := NewHyperVConfigCollector(&mockAgentConfig{}, &mockLogger{})
	if collector.Type() != TypeHyperVConfig {
		t.Errorf("Type = %s, want hyperv_config", collector.Type())
	}
}

func TestIsPathSafe(t *testing.T) {
	tests := []struct {
		baseDir    string
		targetPath string
		expected   bool
	}{
		{"/base", "/base/file.txt", true},
		{"/base", "/base/subdir/file.txt", true},
		{"/base", "/other/file.txt", false},
		{"/base", "/base/../other/file.txt", false},
		{"/base", "/base", true},
	}

	for _, tt := range tests {
		result := isPathSafe(tt.baseDir, tt.targetPath)
		if result != tt.expected {
			t.Errorf("isPathSafe(%q, %q) = %v, want %v", tt.baseDir, tt.targetPath, result, tt.expected)
		}
	}
}

func TestIsSymlinkSafe(t *testing.T) {
	tests := []struct {
		baseDir     string
		symlinkPath string
		linkTarget  string
		expected    bool
	}{
		{"/base", "/base/link", "file.txt", true},
		{"/base", "/base/subdir/link", "../file.txt", true},
		{"/base", "/base/link", "/absolute/path", false},
		{"/base", "/base/link", "../../other/file.txt", false},
	}

	for _, tt := range tests {
		result := isSymlinkSafe(tt.baseDir, tt.symlinkPath, tt.linkTarget)
		if result != tt.expected {
			t.Errorf("isSymlinkSafe(%q, %q, %q) = %v, want %v", tt.baseDir, tt.symlinkPath, tt.linkTarget, result, tt.expected)
		}
	}
}

func TestEscapePowerShellString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"with'quote", "with''quote"},
		{"multiple'quotes'here", "multiple''quotes''here"},
		{"", ""},
	}

	for _, tt := range tests {
		result := escapePowerShellString(tt.input)
		if result != tt.expected {
			t.Errorf("escapePowerShellString(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestCollectorRegistryWithCollectors(t *testing.T) {
	registry := NewCollectorRegistry()

	// Register some collectors
	registry.Register(NewDockerContainerCollector(&mockDockerDeps{}, &mockLogger{}))
	registry.Register(NewAgentConfigCollector(AgentPaths{}, &mockAgentConfig{}))

	// Test Get
	if _, ok := registry.Get(TypeDockerContainer); !ok {
		t.Error("expected to find docker_container collector")
	}

	if _, ok := registry.Get(TypeAgentConfig); !ok {
		t.Error("expected to find agent_config collector")
	}

	if _, ok := registry.Get(TypeMySQL); ok {
		t.Error("expected NOT to find mysql collector (not registered)")
	}
}
