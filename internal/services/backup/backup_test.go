package backup

import (
	"context"
	"testing"
)

func TestBackupTypes(t *testing.T) {
	types := []BackupType{
		TypeAgentConfig,
		TypeAgentLogs,
		TypeSystemState,
		TypeSoftwareInventory,
		TypeComplianceResults,
		TypeFull,
		TypeFilesAndFolders,
		TypeDockerContainer,
		TypeDockerVolume,
		TypeDockerImage,
		TypeDockerCompose,
		TypeProxmoxVM,
		TypeProxmoxLXC,
		TypeProxmoxConfig,
		TypeHyperVVM,
		TypeHyperVCheckpoint,
		TypeHyperVConfig,
		TypePostgreSQL,
		TypeMySQL,
	}

	for _, bt := range types {
		if bt == "" {
			t.Error("BackupType should not be empty")
		}
	}
}

func TestCollectorRegistry(t *testing.T) {
	registry := NewCollectorRegistry()

	if registry == nil {
		t.Fatal("NewCollectorRegistry should not return nil")
	}

	// Test Get on empty registry
	_, ok := registry.Get(TypePostgreSQL)
	if ok {
		t.Error("Get should return false for unregistered type")
	}
}

func TestCollectorConfig(t *testing.T) {
	config := CollectorConfig{
		BackupType:   TypePostgreSQL,
		AgentUUID:    "test-uuid",
		Host:         "localhost",
		Port:         5432,
		Username:     "postgres",
		DatabaseName: "testdb",
	}

	if config.BackupType != TypePostgreSQL {
		t.Errorf("BackupType = %s, want postgresql", config.BackupType)
	}

	if config.Port != 5432 {
		t.Errorf("Port = %d, want 5432", config.Port)
	}
}

func TestCompressionLevels(t *testing.T) {
	levels := []CompressionLevel{
		CompressionNone,
		CompressionFast,
		CompressionBalanced,
		CompressionHigh,
		CompressionMaximum,
	}

	for _, level := range levels {
		gzipLevel := GetGzipLevel(level)
		if level != CompressionNone && gzipLevel == 0 {
			t.Errorf("GetGzipLevel(%s) should not return 0 for non-none level", level)
		}
	}
}

func TestGzipCompressor(t *testing.T) {
	compressor := NewGzipCompressor()

	testData := []byte("test data for compression")

	// Test compression
	compressed, err := compressor.Compress(testData, CompressionBalanced)
	if err != nil {
		t.Fatalf("Compress failed: %v", err)
	}

	// Compressed data should be different (unless very small)
	if len(compressed) == 0 {
		t.Error("Compressed data should not be empty")
	}

	// Test decompression
	decompressed, err := compressor.Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress failed: %v", err)
	}

	if string(decompressed) != string(testData) {
		t.Errorf("Decompressed data = %q, want %q", string(decompressed), string(testData))
	}
}

func TestGzipCompressorNoCompression(t *testing.T) {
	compressor := NewGzipCompressor()

	testData := []byte("test data")

	compressed, err := compressor.Compress(testData, CompressionNone)
	if err != nil {
		t.Fatalf("Compress failed: %v", err)
	}

	// With no compression, data should be returned as-is
	if string(compressed) != string(testData) {
		t.Errorf("No compression should return original data")
	}
}

func TestAESEncryptor(t *testing.T) {
	encryptor := NewAESEncryptor()

	testData := []byte("secret data to encrypt")
	key := make([]byte, 32) // 32 bytes for AES-256
	for i := range key {
		key[i] = byte(i)
	}

	// Test encryption
	ciphertext, nonce, err := encryptor.Encrypt(testData, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Error("Ciphertext should not be empty")
	}

	if len(nonce) == 0 {
		t.Error("Nonce should not be empty")
	}

	// Test decryption
	plaintext, err := encryptor.Decrypt(ciphertext, key, nonce)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(plaintext) != string(testData) {
		t.Errorf("Decrypted data = %q, want %q", string(plaintext), string(testData))
	}
}

func TestAESEncryptorInvalidKeyLength(t *testing.T) {
	encryptor := NewAESEncryptor()

	testData := []byte("test")
	shortKey := []byte("short")

	_, _, err := encryptor.Encrypt(testData, shortKey)
	if err == nil {
		t.Error("Encrypt should fail with short key")
	}
}

func TestAESEncryptorEmptyKey(t *testing.T) {
	encryptor := NewAESEncryptor()

	testData := []byte("test")

	_, _, err := encryptor.Encrypt(testData, nil)
	if err == nil {
		t.Error("Encrypt should fail with nil key")
	}

	_, _, err = encryptor.Encrypt(testData, []byte{})
	if err == nil {
		t.Error("Encrypt should fail with empty key")
	}
}

func TestAESEncryptorHash(t *testing.T) {
	encryptor := NewAESEncryptor()

	testData := []byte("test data")

	sha256Hash := encryptor.Hash(testData, HashSHA256)
	if len(sha256Hash) != 64 { // SHA256 produces 32 bytes = 64 hex chars
		t.Errorf("SHA256 hash length = %d, want 64", len(sha256Hash))
	}

	sha512Hash := encryptor.Hash(testData, HashSHA512)
	if len(sha512Hash) != 128 { // SHA512 produces 64 bytes = 128 hex chars
		t.Errorf("SHA512 hash length = %d, want 128", len(sha512Hash))
	}
}

func TestPostgreSQLCollector(t *testing.T) {
	collector := NewPostgreSQLCollector()

	if collector.Type() != TypePostgreSQL {
		t.Errorf("Type = %s, want postgresql", collector.Type())
	}

	platforms := collector.SupportedPlatforms()
	if len(platforms) == 0 {
		t.Error("SupportedPlatforms should not be empty")
	}
}

func TestMySQLCollector(t *testing.T) {
	collector := NewMySQLCollector()

	if collector.Type() != TypeMySQL {
		t.Errorf("Type = %s, want mysql", collector.Type())
	}

	platforms := collector.SupportedPlatforms()
	if len(platforms) == 0 {
		t.Error("SupportedPlatforms should not be empty")
	}
}

func TestErrorTypes(t *testing.T) {
	// Test ErrUnknownBackupType
	err1 := &ErrUnknownBackupType{Type: "invalid"}
	if err1.Error() != "unknown backup type: invalid" {
		t.Errorf("ErrUnknownBackupType.Error() = %q", err1.Error())
	}

	// Test ErrCollectionFailed
	err2 := &ErrCollectionFailed{Type: TypePostgreSQL, Reason: "connection failed"}
	if err2.Error() == "" {
		t.Error("ErrCollectionFailed.Error() should not be empty")
	}

	// Test ErrCompressionFailed
	err3 := &ErrCompressionFailed{Err: context.Canceled}
	if err3.Unwrap() != context.Canceled {
		t.Error("ErrCompressionFailed.Unwrap() should return wrapped error")
	}

	// Test ErrEncryptionFailed
	err4 := &ErrEncryptionFailed{Reason: "invalid key"}
	if err4.Error() == "" {
		t.Error("ErrEncryptionFailed.Error() should not be empty")
	}

	// Test ErrPlatformUnsupported
	err5 := &ErrPlatformUnsupported{Feature: "HyperV", Platform: "linux"}
	expected := "HyperV is not supported on linux"
	if err5.Error() != expected {
		t.Errorf("ErrPlatformUnsupported.Error() = %q, want %q", err5.Error(), expected)
	}

	// Test ErrMissingParameter
	err6 := &ErrMissingParameter{Parameter: "host", Context: "mysql backup"}
	if err6.Error() != "host is required for mysql backup" {
		t.Errorf("ErrMissingParameter.Error() = %q", err6.Error())
	}

	// Test ErrFeatureUnavailable
	err7 := &ErrFeatureUnavailable{Feature: "Docker"}
	if err7.Error() != "Docker is not available on this system" {
		t.Errorf("ErrFeatureUnavailable.Error() = %q", err7.Error())
	}
}

func TestNoOpProgressReporter(t *testing.T) {
	reporter := &NoOpProgressReporter{}

	// These should not panic
	reporter.ReportProgress("test", 50, "message", "info")
	reporter.ReportError(context.Canceled)
	reporter.ReportCompletion(nil)
}

func TestChannelProgressReporter(t *testing.T) {
	progressCh := make(chan ProgressUpdate, 10)
	errorCh := make(chan error, 1)
	resultCh := make(chan interface{}, 1)

	reporter := NewChannelProgressReporter(progressCh, errorCh, resultCh)

	reporter.ReportProgress("test", 50, "message", "info")

	select {
	case update := <-progressCh:
		if update.Phase != "test" {
			t.Errorf("Phase = %s, want test", update.Phase)
		}
		if update.Percent != 50 {
			t.Errorf("Percent = %d, want 50", update.Percent)
		}
	default:
		t.Error("Expected progress update on channel")
	}

	reporter.ReportError(context.Canceled)

	select {
	case err := <-errorCh:
		if err != context.Canceled {
			t.Errorf("Error = %v, want context.Canceled", err)
		}
	default:
		t.Error("Expected error on channel")
	}

	reporter.ReportCompletion("result")

	select {
	case result := <-resultCh:
		if result != "result" {
			t.Errorf("Result = %v, want result", result)
		}
	default:
		t.Error("Expected result on channel")
	}
}

func TestCallbackProgressReporter(t *testing.T) {
	var progressCalled bool
	var errorCalled bool
	var completionCalled bool

	reporter := NewCallbackProgressReporter(
		func(phase string, percent int, message string, level string) {
			progressCalled = true
		},
		func(err error) {
			errorCalled = true
		},
		func(result interface{}) {
			completionCalled = true
		},
	)

	reporter.ReportProgress("test", 50, "message", "info")
	if !progressCalled {
		t.Error("Progress callback should be called")
	}

	reporter.ReportError(context.Canceled)
	if !errorCalled {
		t.Error("Error callback should be called")
	}

	reporter.ReportCompletion(nil)
	if !completionCalled {
		t.Error("Completion callback should be called")
	}
}

func TestCallbackProgressReporterNilCallbacks(t *testing.T) {
	reporter := NewCallbackProgressReporter(nil, nil, nil)

	// These should not panic
	reporter.ReportProgress("test", 50, "message", "info")
	reporter.ReportError(context.Canceled)
	reporter.ReportCompletion(nil)
}
