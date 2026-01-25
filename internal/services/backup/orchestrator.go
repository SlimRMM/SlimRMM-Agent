// Package backup provides backup orchestration services.
package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// BackupRequest represents a request to create a backup.
type BackupRequest struct {
	BackupID         string
	BackupType       BackupType
	UploadURL        string
	Encrypt          bool
	EncryptKey       string
	CompressionLevel int

	// Collector-specific config
	Config CollectorConfig
}

// BackupResult represents the result of a backup operation.
type BackupResult struct {
	BackupID          string
	Status            string
	SizeBytes         int64
	CompressedBytes   int64
	ContentHashSHA256 string
	ContentHashSHA512 string
	Encrypted         bool
	EncryptionIV      string
	Error             string
}

// Orchestrator coordinates backup operations.
type Orchestrator struct {
	registry         *CollectorRegistry
	compressor       *GzipCompressor
	encryptor        *AESEncryptor
	compressionLevel CompressionLevel
	logger           *slog.Logger
	httpClient       *http.Client
}

// OrchestratorConfig holds configuration for the orchestrator.
type OrchestratorConfig struct {
	Logger           *slog.Logger
	HTTPClient       *http.Client
	CompressionLevel CompressionLevel
}

// NewOrchestrator creates a new backup orchestrator.
func NewOrchestrator(registry *CollectorRegistry, cfg OrchestratorConfig) *Orchestrator {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Minute,
		}
	}

	compressionLevel := cfg.CompressionLevel
	if compressionLevel == "" {
		compressionLevel = CompressionBalanced
	}

	return &Orchestrator{
		registry:         registry,
		compressor:       NewGzipCompressor(),
		encryptor:        NewAESEncryptor(),
		compressionLevel: compressionLevel,
		logger:           logger,
		httpClient:       httpClient,
	}
}

// SetCompressionLevel sets the compression level for the orchestrator.
func (o *Orchestrator) SetCompressionLevel(level CompressionLevel) {
	o.compressionLevel = level
}

// CreateBackup creates a backup using the configured collectors.
func (o *Orchestrator) CreateBackup(ctx context.Context, req BackupRequest, progress ProgressReporter) (*BackupResult, error) {
	result := &BackupResult{
		BackupID: req.BackupID,
		Status:   "in_progress",
	}

	// Report start
	if progress != nil {
		progress.ReportProgress("collecting", 0, "Starting backup collection", "info")
	}

	// Collect data using registry
	o.logger.Info("collecting backup data",
		"backup_id", req.BackupID,
		"backup_type", req.BackupType,
	)

	data, err := o.registry.Collect(ctx, req.Config)
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("collection failed: %v", err)
		if progress != nil {
			progress.ReportError(err)
		}
		return result, err
	}

	result.SizeBytes = int64(len(data))

	if progress != nil {
		progress.ReportProgress("compressing", 25, "Compressing backup data", "info")
	}

	// Compress data
	compressedData, err := o.compressor.Compress(data, o.compressionLevel)
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("compression failed: %v", err)
		if progress != nil {
			progress.ReportError(err)
		}
		return result, err
	}

	result.CompressedBytes = int64(len(compressedData))
	finalData := compressedData

	// Encrypt if requested
	if req.Encrypt && req.EncryptKey != "" {
		if progress != nil {
			progress.ReportProgress("encrypting", 50, "Encrypting backup data", "info")
		}

		encryptedData, iv, err := o.encryptor.EncryptWithIV(compressedData, req.EncryptKey)
		if err != nil {
			result.Status = "failed"
			result.Error = fmt.Sprintf("encryption failed: %v", err)
			if progress != nil {
				progress.ReportError(err)
			}
			return result, err
		}

		finalData = encryptedData
		result.Encrypted = true
		result.EncryptionIV = iv
	}

	// Calculate hashes
	sha256Hash := sha256.Sum256(finalData)
	sha512Hash := sha512.Sum512(finalData)
	result.ContentHashSHA256 = hex.EncodeToString(sha256Hash[:])
	result.ContentHashSHA512 = hex.EncodeToString(sha512Hash[:])

	// Upload if URL provided
	if req.UploadURL != "" {
		if progress != nil {
			progress.ReportProgress("uploading", 75, "Uploading backup data", "info")
		}

		if err := o.uploadData(ctx, req.UploadURL, finalData); err != nil {
			result.Status = "failed"
			result.Error = fmt.Sprintf("upload failed: %v", err)
			if progress != nil {
				progress.ReportError(err)
			}
			return result, err
		}
	}

	result.Status = "completed"

	if progress != nil {
		progress.ReportProgress("completed", 100, "Backup completed successfully", "info")
		progress.ReportCompletion(result)
	}

	o.logger.Info("backup completed",
		"backup_id", req.BackupID,
		"size_bytes", result.SizeBytes,
		"compressed_bytes", result.CompressedBytes,
		"encrypted", result.Encrypted,
	)

	return result, nil
}

// uploadData uploads data to the specified URL.
func (o *Orchestrator) uploadData(ctx context.Context, url string, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(data))

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("uploading: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// RestoreRequest represents a request to restore a backup.
type RestoreRequest struct {
	BackupID    string
	BackupType  BackupType
	DownloadURL string
	Encrypted   bool
	EncryptKey  string
	EncryptIV   string

	// Restore-specific config
	Config RestoreConfig
}

// RestoreConfig contains configuration for restore operations.
type RestoreConfig struct {
	// Files and folders restore
	RestorePaths      []string
	RestoreTarget     string
	OverwriteFiles    bool
	PreserveStructure bool

	// Docker restore
	ContainerName  string
	VolumeName     string
	ImageName      string
	ComposePath    string
	RestoreVolumes bool

	// Agent restore
	ConfigPath      string
	CompliancePath  string
}

// RestoreResult represents the result of a restore operation.
type RestoreResult struct {
	BackupID      string
	Status        string
	TotalFiles    int
	RestoredFiles int
	SkippedFiles  int
	FailedFiles   int
	TotalSize     int64
	RestoredSize  int64
	Error         string
}

// Restorer defines the interface for backup restorers.
type Restorer interface {
	// Restore restores data from a backup.
	Restore(ctx context.Context, data []byte, config RestoreConfig) (*RestoreResult, error)

	// Type returns the backup type this restorer handles.
	Type() BackupType
}

// RestorerRegistry manages backup restorers.
type RestorerRegistry struct {
	restorers map[BackupType]Restorer
}

// NewRestorerRegistry creates a new restorer registry.
func NewRestorerRegistry() *RestorerRegistry {
	return &RestorerRegistry{
		restorers: make(map[BackupType]Restorer),
	}
}

// Register registers a restorer for a backup type.
func (r *RestorerRegistry) Register(restorer Restorer) {
	r.restorers[restorer.Type()] = restorer
}

// Get returns the restorer for a backup type.
func (r *RestorerRegistry) Get(t BackupType) (Restorer, bool) {
	restorer, ok := r.restorers[t]
	return restorer, ok
}

// RestoreOrchestrator coordinates restore operations.
type RestoreOrchestrator struct {
	registry   *RestorerRegistry
	compressor *GzipCompressor
	encryptor  *AESEncryptor
	logger     *slog.Logger
	httpClient *http.Client
}

// NewRestoreOrchestrator creates a new restore orchestrator.
func NewRestoreOrchestrator(registry *RestorerRegistry, cfg OrchestratorConfig) *RestoreOrchestrator {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Minute,
		}
	}

	return &RestoreOrchestrator{
		registry:   registry,
		compressor: NewGzipCompressor(),
		encryptor:  NewAESEncryptor(),
		logger:     logger,
		httpClient: httpClient,
	}
}

// RestoreBackup restores a backup using the configured restorers.
func (o *RestoreOrchestrator) RestoreBackup(ctx context.Context, req RestoreRequest, progress ProgressReporter) (*RestoreResult, error) {
	result := &RestoreResult{
		BackupID: req.BackupID,
		Status:   "in_progress",
	}

	// Report start
	if progress != nil {
		progress.ReportProgress("downloading", 0, "Starting backup download", "info")
	}

	// Download data
	data, err := o.downloadData(ctx, req.DownloadURL)
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("download failed: %v", err)
		if progress != nil {
			progress.ReportError(err)
		}
		return result, err
	}

	// Decrypt if needed
	if req.Encrypted && req.EncryptKey != "" {
		if progress != nil {
			progress.ReportProgress("decrypting", 25, "Decrypting backup data", "info")
		}

		decryptedData, err := o.encryptor.DecryptWithIV(data, req.EncryptKey, req.EncryptIV)
		if err != nil {
			result.Status = "failed"
			result.Error = fmt.Sprintf("decryption failed: %v", err)
			if progress != nil {
				progress.ReportError(err)
			}
			return result, err
		}
		data = decryptedData
	}

	// Decompress
	if progress != nil {
		progress.ReportProgress("decompressing", 50, "Decompressing backup data", "info")
	}

	decompressedData, err := o.compressor.Decompress(data)
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("decompression failed: %v", err)
		if progress != nil {
			progress.ReportError(err)
		}
		return result, err
	}

	// Get restorer
	restorer, ok := o.registry.Get(req.BackupType)
	if !ok {
		result.Status = "failed"
		result.Error = fmt.Sprintf("no restorer for backup type: %s", req.BackupType)
		return result, fmt.Errorf("no restorer for backup type: %s", req.BackupType)
	}

	// Restore
	if progress != nil {
		progress.ReportProgress("restoring", 75, "Restoring backup data", "info")
	}

	restoreResult, err := restorer.Restore(ctx, decompressedData, req.Config)
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("restore failed: %v", err)
		if progress != nil {
			progress.ReportError(err)
		}
		return result, err
	}

	// Copy results
	result.Status = "completed"
	result.TotalFiles = restoreResult.TotalFiles
	result.RestoredFiles = restoreResult.RestoredFiles
	result.SkippedFiles = restoreResult.SkippedFiles
	result.FailedFiles = restoreResult.FailedFiles
	result.TotalSize = restoreResult.TotalSize
	result.RestoredSize = restoreResult.RestoredSize

	if progress != nil {
		progress.ReportProgress("completed", 100, "Restore completed successfully", "info")
		progress.ReportCompletion(result)
	}

	o.logger.Info("restore completed",
		"backup_id", req.BackupID,
		"restored_files", result.RestoredFiles,
		"skipped_files", result.SkippedFiles,
		"failed_files", result.FailedFiles,
	)

	return result, nil
}

// downloadData downloads data from the specified URL.
func (o *RestoreOrchestrator) downloadData(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("download failed with status %d: %s", resp.StatusCode, string(body))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return data, nil
}
