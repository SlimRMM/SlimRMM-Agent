package backup

import (
	"context"
	"encoding/json"
	"testing"
)

// mockCollector for testing
type mockCollector struct {
	backupType BackupType
	data       []byte
	err        error
}

func (m *mockCollector) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.data, nil
}

func (m *mockCollector) Type() BackupType {
	return m.backupType
}

// mockRestorer for testing
type mockRestorer struct {
	backupType BackupType
	result     *RestoreResult
	err        error
}

func (m *mockRestorer) Restore(ctx context.Context, data []byte, config RestoreConfig) (*RestoreResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

func (m *mockRestorer) Type() BackupType {
	return m.backupType
}

// mockProgress for testing
type mockProgress struct {
	phases   []string
	percents []int
	messages []string
}

func (m *mockProgress) ReportProgress(phase string, percent int, message string, level string) {
	m.phases = append(m.phases, phase)
	m.percents = append(m.percents, percent)
	m.messages = append(m.messages, message)
}

func (m *mockProgress) ReportError(err error) {}

func (m *mockProgress) ReportCompletion(result interface{}) {}

func TestOrchestratorCreateBackup(t *testing.T) {
	// Create registry with mock collector
	registry := NewCollectorRegistry()
	mockData := map[string]string{"test": "data"}
	jsonData, _ := json.Marshal(mockData)
	registry.Register(&mockCollector{
		backupType: TypeAgentConfig,
		data:       jsonData,
	})

	// Create orchestrator
	orchestrator := NewOrchestrator(registry, OrchestratorConfig{})

	// Create backup request
	req := BackupRequest{
		BackupID:   "test-backup",
		BackupType: TypeAgentConfig,
		Config: CollectorConfig{
			BackupType: TypeAgentConfig,
		},
	}

	// Execute
	progress := &mockProgress{}
	result, err := orchestrator.CreateBackup(context.Background(), req, progress)

	// Verify
	if err != nil {
		t.Fatalf("CreateBackup failed: %v", err)
	}

	if result.Status != "completed" {
		t.Errorf("Status = %s, want completed", result.Status)
	}

	if result.SizeBytes == 0 {
		t.Error("SizeBytes should be > 0")
	}

	if result.CompressedBytes == 0 {
		t.Error("CompressedBytes should be > 0")
	}

	if result.ContentHashSHA256 == "" {
		t.Error("ContentHashSHA256 should not be empty")
	}

	// Verify progress was reported
	if len(progress.phases) == 0 {
		t.Error("No progress was reported")
	}
}

func TestOrchestratorCreateBackupWithEncryption(t *testing.T) {
	// Create registry with mock collector
	registry := NewCollectorRegistry()
	mockData := map[string]string{"test": "data"}
	jsonData, _ := json.Marshal(mockData)
	registry.Register(&mockCollector{
		backupType: TypeAgentConfig,
		data:       jsonData,
	})

	// Create orchestrator
	orchestrator := NewOrchestrator(registry, OrchestratorConfig{})

	// Create backup request with encryption (32 bytes = 64 hex chars)
	req := BackupRequest{
		BackupID:   "test-backup",
		BackupType: TypeAgentConfig,
		Encrypt:    true,
		EncryptKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Config: CollectorConfig{
			BackupType: TypeAgentConfig,
		},
	}

	// Execute
	result, err := orchestrator.CreateBackup(context.Background(), req, nil)

	// Verify
	if err != nil {
		t.Fatalf("CreateBackup failed: %v", err)
	}

	if !result.Encrypted {
		t.Error("Encrypted should be true")
	}

	if result.EncryptionIV == "" {
		t.Error("EncryptionIV should not be empty")
	}
}

func TestOrchestratorSetCompressionLevel(t *testing.T) {
	registry := NewCollectorRegistry()
	orchestrator := NewOrchestrator(registry, OrchestratorConfig{})

	// Test setting compression level
	orchestrator.SetCompressionLevel(CompressionMaximum)
	if orchestrator.compressionLevel != CompressionMaximum {
		t.Errorf("compressionLevel = %s, want %s", orchestrator.compressionLevel, CompressionMaximum)
	}
}

func TestRestorerRegistry(t *testing.T) {
	registry := NewRestorerRegistry()

	// Register mock restorer
	restorer := &mockRestorer{
		backupType: TypeAgentConfig,
		result: &RestoreResult{
			Status:        "completed",
			RestoredFiles: 5,
		},
	}
	registry.Register(restorer)

	// Test Get
	r, ok := registry.Get(TypeAgentConfig)
	if !ok {
		t.Error("expected to find restorer")
	}
	if r.Type() != TypeAgentConfig {
		t.Errorf("Type = %s, want %s", r.Type(), TypeAgentConfig)
	}

	// Test Get for non-existent type
	_, ok = registry.Get(TypeDockerContainer)
	if ok {
		t.Error("expected not to find restorer for docker_container")
	}
}

func TestBackupRequestTypes(t *testing.T) {
	req := BackupRequest{
		BackupID:         "test-id",
		BackupType:       TypePostgreSQL,
		UploadURL:        "https://example.com/upload",
		Encrypt:          true,
		EncryptKey:       "key",
		CompressionLevel: 5,
	}

	if req.BackupID != "test-id" {
		t.Errorf("BackupID = %s, want test-id", req.BackupID)
	}
	if req.BackupType != TypePostgreSQL {
		t.Errorf("BackupType = %s, want postgresql", req.BackupType)
	}
}

func TestRestoreRequestTypes(t *testing.T) {
	req := RestoreRequest{
		BackupID:    "test-id",
		BackupType:  TypeFilesAndFolders,
		DownloadURL: "https://example.com/download",
		Encrypted:   true,
		EncryptKey:  "key",
		EncryptIV:   "iv",
		Config: RestoreConfig{
			RestoreTarget:     "/tmp/restore",
			OverwriteFiles:    true,
			PreserveStructure: true,
		},
	}

	if req.BackupID != "test-id" {
		t.Errorf("BackupID = %s, want test-id", req.BackupID)
	}
	if req.Config.RestoreTarget != "/tmp/restore" {
		t.Errorf("RestoreTarget = %s, want /tmp/restore", req.Config.RestoreTarget)
	}
}
