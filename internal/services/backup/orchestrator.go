// Package backup provides backup orchestration services.
package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
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

	// Incremental backup fields
	Strategy            BackupStrategy `json:"strategy,omitempty"`
	BaseBackupID        string         `json:"base_backup_id,omitempty"`
	ParentBackupID      string         `json:"parent_backup_id,omitempty"`
	PreviousManifestURL string         `json:"previous_manifest_url,omitempty"`
	ManifestUploadURL   string         `json:"manifest_upload_url,omitempty"`

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

	// Incremental backup fields
	Strategy          BackupStrategy `json:"strategy,omitempty"`
	BaseBackupID      string         `json:"base_backup_id,omitempty"`
	ParentBackupID    string         `json:"parent_backup_id,omitempty"`
	DeltaSizeBytes    int64          `json:"delta_size_bytes,omitempty"`
	NewFilesCount     int            `json:"new_files_count,omitempty"`
	ModifiedFilesCount int           `json:"modified_files_count,omitempty"`
	DeletedFilesCount int            `json:"deleted_files_count,omitempty"`
	UnchangedFilesCount int          `json:"unchanged_files_count,omitempty"`
	ManifestHash      string         `json:"manifest_hash,omitempty"`
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
		BackupID:       req.BackupID,
		Status:         "in_progress",
		Strategy:       req.Strategy,
		BaseBackupID:   req.BaseBackupID,
		ParentBackupID: req.ParentBackupID,
	}

	// Default strategy to full if not specified
	if req.Strategy == "" {
		req.Strategy = StrategyFull
	}

	// Report start
	if progress != nil {
		progress.ReportProgress("collecting", 0, "Starting backup collection", "info")
	}

	// Collect data using registry
	o.logger.Info("collecting backup data",
		"backup_id", req.BackupID,
		"backup_type", req.BackupType,
		"strategy", req.Strategy,
	)

	// Prepare config with incremental settings
	config := req.Config
	config.Strategy = req.Strategy
	config.BaseBackupID = req.BaseBackupID
	config.ParentBackupID = req.ParentBackupID
	config.PreviousManifestURL = req.PreviousManifestURL

	var data []byte
	var manifest *FileManifest
	var deltaInfo *DeltaInfo

	// Use incremental collection if supported and requested
	isIncremental := req.Strategy == StrategyIncremental || req.Strategy == StrategyDifferential
	if isIncremental && o.registry.SupportsIncremental(req.BackupType) {
		// Download previous manifest if URL provided
		if req.PreviousManifestURL != "" {
			if progress != nil {
				progress.ReportProgress("fetching_manifest", 5, "Fetching previous backup manifest", "info")
			}

			previousManifest, err := o.downloadManifest(ctx, req.PreviousManifestURL)
			if err != nil {
				o.logger.Warn("failed to download previous manifest, falling back to full backup",
					"error", err,
				)
				config.Strategy = StrategyFull
				result.Strategy = StrategyFull
			} else {
				config.PreviousManifest = previousManifest
			}
		}

		// Collect with incremental support
		collectorResult, err := o.registry.CollectIncremental(ctx, config)
		if err != nil {
			result.Status = "failed"
			result.Error = fmt.Sprintf("collection failed: %v", err)
			if progress != nil {
				progress.ReportError(err)
			}
			return result, err
		}

		data = collectorResult.Data
		manifest = collectorResult.Manifest
		deltaInfo = collectorResult.DeltaInfo

		// Populate delta metrics
		if deltaInfo != nil {
			result.NewFilesCount = deltaInfo.NewFiles
			result.ModifiedFilesCount = deltaInfo.ModifiedFiles
			result.DeletedFilesCount = deltaInfo.DeletedFiles
			result.UnchangedFilesCount = deltaInfo.UnchangedFiles
			result.DeltaSizeBytes = deltaInfo.DeltaSize
		}
	} else {
		// Regular collection
		var err error
		data, err = o.registry.Collect(ctx, config)
		if err != nil {
			result.Status = "failed"
			result.Error = fmt.Sprintf("collection failed: %v", err)
			if progress != nil {
				progress.ReportError(err)
			}
			return result, err
		}
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

	// Upload manifest if URL provided and manifest exists
	if req.ManifestUploadURL != "" && manifest != nil {
		if progress != nil {
			progress.ReportProgress("uploading_manifest", 90, "Uploading backup manifest", "info")
		}

		manifestData, err := json.Marshal(manifest)
		if err != nil {
			o.logger.Error("failed to marshal manifest", "error", err)
		} else {
			if err := o.uploadData(ctx, req.ManifestUploadURL, manifestData); err != nil {
				o.logger.Warn("failed to upload manifest", "error", err)
			} else {
				// Calculate manifest hash
				manifestHash := sha256.Sum256(manifestData)
				result.ManifestHash = hex.EncodeToString(manifestHash[:])
			}
		}
	}

	result.Status = "completed"

	if progress != nil {
		progress.ReportProgress("completed", 100, "Backup completed successfully", "info")
		progress.ReportCompletion(result)
	}

	o.logger.Info("backup completed",
		"backup_id", req.BackupID,
		"strategy", result.Strategy,
		"size_bytes", result.SizeBytes,
		"compressed_bytes", result.CompressedBytes,
		"delta_size_bytes", result.DeltaSizeBytes,
		"new_files", result.NewFilesCount,
		"modified_files", result.ModifiedFilesCount,
		"deleted_files", result.DeletedFilesCount,
		"encrypted", result.Encrypted,
	)

	return result, nil
}

// downloadManifest downloads and parses a manifest from the given URL.
func (o *Orchestrator) downloadManifest(ctx context.Context, url string) (*FileManifest, error) {
	data, err := o.downloadData(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("downloading manifest: %w", err)
	}

	var manifest FileManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}

	return &manifest, nil
}

// downloadData downloads data from the specified URL (for manifest download).
func (o *Orchestrator) downloadData(ctx context.Context, url string) ([]byte, error) {
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

	return io.ReadAll(resp.Body)
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

	// Incremental restore fields
	Strategy        BackupStrategy           `json:"strategy,omitempty"`
	RestoreChain    []RestoreChainEntry      `json:"restore_chain,omitempty"`

	// Restore-specific config
	Config RestoreConfig
}

// RestoreChainEntry represents a backup in the restore chain.
type RestoreChainEntry struct {
	BackupID    string `json:"backup_id"`
	DownloadURL string `json:"download_url"`
	Encrypted   bool   `json:"encrypted"`
	EncryptKey  string `json:"encrypt_key,omitempty"`
	EncryptIV   string `json:"encrypt_iv,omitempty"`
	Strategy    BackupStrategy `json:"strategy"`
}

// RestoreConfig contains configuration for restore operations.
type RestoreConfig struct {
	// Files and folders restore
	RestorePaths      []string
	RestoreTarget     string
	OverwriteFiles    bool
	PreserveStructure bool

	// Incremental restore options
	ApplyDeltas       bool     // Apply incremental deltas in sequence
	SkipDeletedFiles  bool     // Don't delete files marked as deleted

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

	// Incremental restore metrics
	ChainLength       int   `json:"chain_length,omitempty"`
	DeltasApplied     int   `json:"deltas_applied,omitempty"`
	DeletedFilesCount int   `json:"deleted_files_count,omitempty"`
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

	// Check if we have a restore chain (incremental restore)
	if len(req.RestoreChain) > 0 {
		return o.restoreChain(ctx, req, progress)
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

// restoreChain handles incremental restore by applying backups in chain order.
func (o *RestoreOrchestrator) restoreChain(ctx context.Context, req RestoreRequest, progress ProgressReporter) (*RestoreResult, error) {
	result := &RestoreResult{
		BackupID:    req.BackupID,
		Status:      "in_progress",
		ChainLength: len(req.RestoreChain),
	}

	o.logger.Info("starting chain restore",
		"backup_id", req.BackupID,
		"chain_length", len(req.RestoreChain),
	)

	// Get restorer
	restorer, ok := o.registry.Get(req.BackupType)
	if !ok {
		result.Status = "failed"
		result.Error = fmt.Sprintf("no restorer for backup type: %s", req.BackupType)
		return result, fmt.Errorf("no restorer for backup type: %s", req.BackupType)
	}

	// Apply each backup in the chain
	for i, entry := range req.RestoreChain {
		select {
		case <-ctx.Done():
			result.Status = "cancelled"
			result.Error = "context cancelled"
			return result, ctx.Err()
		default:
		}

		progressPct := int(float64(i) / float64(len(req.RestoreChain)) * 80)
		if progress != nil {
			progress.ReportProgress("restoring_chain",
				progressPct,
				fmt.Sprintf("Restoring backup %d of %d (%s)", i+1, len(req.RestoreChain), entry.Strategy),
				"info",
			)
		}

		o.logger.Info("applying backup from chain",
			"chain_index", i,
			"backup_id", entry.BackupID,
			"strategy", entry.Strategy,
		)

		// Download this backup
		data, err := o.downloadData(ctx, entry.DownloadURL)
		if err != nil {
			result.Status = "failed"
			result.Error = fmt.Sprintf("download failed for chain entry %d: %v", i, err)
			if progress != nil {
				progress.ReportError(err)
			}
			return result, err
		}

		// Decrypt if needed
		if entry.Encrypted && entry.EncryptKey != "" {
			data, err = o.encryptor.DecryptWithIV(data, entry.EncryptKey, entry.EncryptIV)
			if err != nil {
				result.Status = "failed"
				result.Error = fmt.Sprintf("decryption failed for chain entry %d: %v", i, err)
				if progress != nil {
					progress.ReportError(err)
				}
				return result, err
			}
		}

		// Decompress
		data, err = o.compressor.Decompress(data)
		if err != nil {
			result.Status = "failed"
			result.Error = fmt.Sprintf("decompression failed for chain entry %d: %v", i, err)
			if progress != nil {
				progress.ReportError(err)
			}
			return result, err
		}

		// Configure for incremental apply
		config := req.Config
		if i > 0 {
			// For subsequent entries, we're applying deltas
			config.ApplyDeltas = true
		}

		// Restore/apply this backup
		chainResult, err := restorer.Restore(ctx, data, config)
		if err != nil {
			result.Status = "failed"
			result.Error = fmt.Sprintf("restore failed for chain entry %d: %v", i, err)
			if progress != nil {
				progress.ReportError(err)
			}
			return result, err
		}

		// Accumulate results
		if i == 0 {
			// Base backup sets the initial counts
			result.TotalFiles = chainResult.TotalFiles
			result.RestoredFiles = chainResult.RestoredFiles
			result.SkippedFiles = chainResult.SkippedFiles
			result.FailedFiles = chainResult.FailedFiles
			result.TotalSize = chainResult.TotalSize
			result.RestoredSize = chainResult.RestoredSize
		} else {
			// Incremental backups add to the counts
			result.DeltasApplied++
			result.RestoredFiles += chainResult.RestoredFiles
			result.SkippedFiles += chainResult.SkippedFiles
			result.FailedFiles += chainResult.FailedFiles
			result.RestoredSize += chainResult.RestoredSize
			result.DeletedFilesCount += chainResult.DeletedFilesCount
		}

		o.logger.Info("applied backup from chain",
			"chain_index", i,
			"backup_id", entry.BackupID,
			"restored_files", chainResult.RestoredFiles,
		)
	}

	result.Status = "completed"

	if progress != nil {
		progress.ReportProgress("completed", 100, "Chain restore completed successfully", "info")
		progress.ReportCompletion(result)
	}

	o.logger.Info("chain restore completed",
		"backup_id", req.BackupID,
		"chain_length", result.ChainLength,
		"deltas_applied", result.DeltasApplied,
		"total_restored_files", result.RestoredFiles,
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
