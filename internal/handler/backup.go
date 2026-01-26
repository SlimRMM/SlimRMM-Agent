// Package handler provides backup handling for the agent.
package handler

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/actions"
	"github.com/slimrmm/slimrmm-agent/internal/i18n"
	"github.com/slimrmm/slimrmm-agent/internal/osquery"
	"github.com/slimrmm/slimrmm-agent/internal/proxmox"
	"github.com/slimrmm/slimrmm-agent/internal/security/audit"
	"github.com/slimrmm/slimrmm-agent/internal/services/backup"
)

// Backup request types

// CompressionLevel defines the compression levels supported by the agent.
type CompressionLevel string

const (
	CompressionNone     CompressionLevel = "none"
	CompressionFast     CompressionLevel = "fast"
	CompressionBalanced CompressionLevel = "balanced"
	CompressionHigh     CompressionLevel = "high"
	CompressionMaximum  CompressionLevel = "maximum"
)

// compressionLevelToGzip maps compression levels to gzip compression levels.
// gzip levels: 1 (fastest) to 9 (best compression)
var compressionLevelToGzip = map[CompressionLevel]int{
	CompressionNone:     0, // No compression
	CompressionFast:     1, // Fastest
	CompressionBalanced: 5, // Default
	CompressionHigh:     7, // Good balance
	CompressionMaximum:  9, // Best compression
}

// isPathSafe validates that a file path is safely contained within the target directory.
// This prevents path traversal attacks via malicious tar entries containing "../" or absolute paths.
func isPathSafe(baseDir, targetPath string) bool {
	// Get absolute paths for comparison
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return false
	}
	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return false
	}

	// Clean the paths to normalize them
	absBase = filepath.Clean(absBase)
	absTarget = filepath.Clean(absTarget)

	// Check if target is within base directory
	// Use filepath.Separator to ensure we match directory boundaries
	if !strings.HasPrefix(absTarget, absBase+string(filepath.Separator)) && absTarget != absBase {
		return false
	}

	return true
}

// isSymlinkSafe validates that a symlink target doesn't escape the base directory.
func isSymlinkSafe(baseDir, symlinkPath, linkTarget string) bool {
	// Resolve the symlink target relative to the symlink's location
	var targetPath string
	if filepath.IsAbs(linkTarget) {
		// Absolute symlink targets are not safe
		return false
	}

	// Compute the actual path the symlink would point to
	symlinkDir := filepath.Dir(symlinkPath)
	targetPath = filepath.Join(symlinkDir, linkTarget)

	return isPathSafe(baseDir, targetPath)
}

// escapePowerShellString escapes a string for safe use in PowerShell single-quoted strings.
// Single quotes in PowerShell are escaped by doubling them: ' becomes ''
// This prevents command injection via user-supplied strings like VM names.
func escapePowerShellString(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// isValidVMName validates a VM name to contain only safe characters.
// Allowed: alphanumeric, spaces, hyphens, underscores, and periods.
func isValidVMName(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == ' ' || r == '-' ||
			r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// isValidDatabaseName validates a database name to contain only safe characters.
// Allowed: alphanumeric, underscores, and hyphens.
func isValidDatabaseName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// isValidSocketPath validates a Unix socket path to prevent command injection.
// Allowed: alphanumeric, underscores, hyphens, dots, and forward slashes.
func isValidSocketPath(path string) bool {
	if path == "" || len(path) > 256 {
		return false
	}
	// Must start with / for Unix sockets
	if path[0] != '/' {
		return false
	}
	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return false
	}
	for _, r := range path {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' || r == '/') {
			return false
		}
	}
	return true
}

// isValidDBHost validates a database host to prevent command injection.
// Allowed: alphanumeric, hyphens, dots, colons (for IPv6), and square brackets.
func isValidDBHost(host string) bool {
	if host == "" || len(host) > 255 {
		return false
	}
	for _, r := range host {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '.' || r == ':' || r == '[' || r == ']') {
			return false
		}
	}
	return true
}

// isValidDBUsername validates a database username to prevent command injection.
// Allowed: alphanumeric, underscores, hyphens, and dots.
func isValidDBUsername(username string) bool {
	if username == "" || len(username) > 64 {
		return false
	}
	for _, r := range username {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// getMinimalDBEnv returns a minimal, filtered environment for database commands.
// This prevents leaking sensitive environment variables to external processes.
// Only includes essential variables needed for database commands to function.
func getMinimalDBEnv(additionalVars ...string) []string {
	// Essential environment variables for database commands
	allowedVars := []string{
		"PATH",       // Required to find executables
		"HOME",       // Required for config files (.pgpass, .my.cnf)
		"USER",       // User identification
		"LANG",       // Locale settings for proper encoding
		"LC_ALL",     // Locale override
		"LC_CTYPE",   // Character classification
		"TZ",         // Timezone for timestamps
		"TMPDIR",     // Temporary directory for dumps
		"TEMP",       // Windows temp directory
		"TMP",        // Alternative temp directory
	}

	env := make([]string, 0, len(allowedVars)+len(additionalVars))

	// Copy only allowed variables from current environment
	for _, key := range allowedVars {
		if val := os.Getenv(key); val != "" {
			env = append(env, key+"="+val)
		}
	}

	// Add any additional variables (e.g., PGPASSWORD, MYSQL_PWD)
	env = append(env, additionalVars...)

	return env
}

type createBackupRequest struct {
	BackupID         string           `json:"backup_id"`
	BackupType       string           `json:"backup_type"` // config, logs, system_state, software_inventory, compliance_results, docker_*, proxmox_*, hyperv_*, files_and_folders
	UploadURL        string           `json:"upload_url"`  // Pre-signed URL for upload
	Encrypt          bool             `json:"encrypt"`
	EncryptKey       string           `json:"encrypt_key,omitempty"`       // DEK for client-side encryption (base64)
	CompressionLevel CompressionLevel `json:"compression_level,omitempty"` // Compression level: none, fast, balanced, high, maximum

	// Incremental backup parameters
	Strategy            string `json:"strategy,omitempty"`              // full, incremental, differential, synthetic_full
	BaseBackupID        string `json:"base_backup_id,omitempty"`        // Base backup ID for differential/incremental
	ParentBackupID      string `json:"parent_backup_id,omitempty"`      // Parent backup ID for incremental
	PreviousManifestURL string `json:"previous_manifest_url,omitempty"` // URL to download previous manifest
	ManifestUploadURL   string `json:"manifest_upload_url,omitempty"`   // URL to upload current manifest

	// Files and Folders specific parameters
	IncludePaths    []string `json:"include_paths,omitempty"`    // Paths to include in backup
	ExcludePatterns []string `json:"exclude_patterns,omitempty"` // Glob patterns to exclude

	// Docker-specific parameters
	ContainerID   string `json:"container_id,omitempty"`
	VolumeName    string `json:"volume_name,omitempty"`
	ImageName     string `json:"image_name,omitempty"`
	ComposePath   string `json:"compose_path,omitempty"`
	IncludeLogs   bool   `json:"include_logs,omitempty"`
	StopContainer bool   `json:"stop_container,omitempty"` // Stop container for consistent backup

	// Proxmox-specific parameters
	VMID           uint64 `json:"vmid,omitempty"`
	ProxmoxStorage string `json:"proxmox_storage,omitempty"`
	BackupMode     string `json:"backup_mode,omitempty"` // snapshot, stop, suspend
	IncludeRAM     bool   `json:"include_ram,omitempty"`

	// Hyper-V-specific parameters
	VMName             string `json:"vm_name,omitempty"`
	CheckpointName     string `json:"checkpoint_name,omitempty"`
	IncludeCheckpoints bool   `json:"include_checkpoints,omitempty"`
	UseVSS             bool   `json:"use_vss,omitempty"` // Volume Shadow Copy for consistent backup

	// PostgreSQL-specific parameters
	PostgreSQL *postgresqlBackupParams `json:"postgresql,omitempty"`

	// MySQL-specific parameters
	MySQL *mysqlBackupParams `json:"mysql,omitempty"`
}

// postgresqlBackupParams contains parameters for PostgreSQL database backups.
type postgresqlBackupParams struct {
	ConnectionType string `json:"connection_type"` // host, socket
	Host           string `json:"host,omitempty"`
	Port           int    `json:"port,omitempty"`
	SocketPath     string `json:"socket_path,omitempty"`
	Username       string `json:"username,omitempty"`
	Password       string `json:"password,omitempty"`
	DatabaseName   string `json:"database_name,omitempty"`
	SchemaOnly     bool   `json:"schema_only,omitempty"`
	DataOnly       bool   `json:"data_only,omitempty"`
}

// mysqlBackupParams contains parameters for MySQL/MariaDB database backups.
type mysqlBackupParams struct {
	ConnectionType    string `json:"connection_type"` // host, socket
	Host              string `json:"host,omitempty"`
	Port              int    `json:"port,omitempty"`
	SocketPath        string `json:"socket_path,omitempty"`
	Username          string `json:"username,omitempty"`
	Password          string `json:"password,omitempty"`
	DatabaseName      string `json:"database_name,omitempty"`
	AllDatabases      bool   `json:"all_databases,omitempty"`
	SingleTransaction bool   `json:"single_transaction,omitempty"`
}

type createBackupResponse struct {
	BackupID          string `json:"backup_id"`
	Status            string `json:"status"`
	SizeBytes         int64  `json:"size_bytes"`
	CompressedBytes   int64  `json:"compressed_bytes"`
	ContentHashSHA256 string `json:"content_hash_sha256"`
	ContentHashSHA512 string `json:"content_hash_sha512"`
	Encrypted         bool   `json:"encrypted"`
	EncryptionIV      string `json:"encryption_iv,omitempty"`
	Error             string `json:"error,omitempty"`

	// Incremental backup metrics
	Strategy           string `json:"strategy,omitempty"`
	BaseBackupID       string `json:"base_backup_id,omitempty"`
	ParentBackupID     string `json:"parent_backup_id,omitempty"`
	DeltaSizeBytes     int64  `json:"delta_size_bytes,omitempty"`
	NewFilesCount      int    `json:"new_files_count,omitempty"`
	ModifiedFilesCount int    `json:"modified_files_count,omitempty"`
	DeletedFilesCount  int    `json:"deleted_files_count,omitempty"`
	UnchangedFilesCount int   `json:"unchanged_files_count,omitempty"`
	ManifestHash       string `json:"manifest_hash,omitempty"`
}

// createBackupViaOrchestrator creates a backup using the injected backup orchestrator service.
// This method is used for backup types that have registered collectors (Docker, Agent, System, etc.).
// Returns nil, nil if the backup type is not handled by the orchestrator.
func (h *Handler) createBackupViaOrchestrator(ctx context.Context, req createBackupRequest) (*createBackupResponse, error) {
	// Map backup type string to BackupType enum
	backupType := backup.BackupType(req.BackupType)

	// Check if we have a collector for this backup type
	if _, ok := h.collectorRegistry.Get(backupType); !ok {
		return nil, nil // Not handled by orchestrator
	}

	// Build collector config
	collectorConfig := backup.CollectorConfig{
		BackupType:      backupType,
		AgentUUID:       h.cfg.GetUUID(),
		ContainerID:     req.ContainerID,
		VolumeName:      req.VolumeName,
		ImageName:       req.ImageName,
		ComposePath:     req.ComposePath,
		Paths:           req.IncludePaths,
		ExcludePatterns: req.ExcludePatterns,
	}

	// Add PostgreSQL-specific parameters
	if req.PostgreSQL != nil {
		collectorConfig.DatabaseType = "postgresql"
		collectorConfig.ConnectionType = req.PostgreSQL.ConnectionType
		collectorConfig.Host = req.PostgreSQL.Host
		collectorConfig.Port = req.PostgreSQL.Port
		collectorConfig.SocketPath = req.PostgreSQL.SocketPath
		collectorConfig.Username = req.PostgreSQL.Username
		collectorConfig.Password = req.PostgreSQL.Password
		collectorConfig.DatabaseName = req.PostgreSQL.DatabaseName
		collectorConfig.SchemaOnly = req.PostgreSQL.SchemaOnly
		collectorConfig.DataOnly = req.PostgreSQL.DataOnly
	}

	// Add MySQL-specific parameters
	if req.MySQL != nil {
		collectorConfig.DatabaseType = "mysql"
		collectorConfig.ConnectionType = req.MySQL.ConnectionType
		collectorConfig.Host = req.MySQL.Host
		collectorConfig.Port = req.MySQL.Port
		collectorConfig.SocketPath = req.MySQL.SocketPath
		collectorConfig.Username = req.MySQL.Username
		collectorConfig.Password = req.MySQL.Password
		collectorConfig.DatabaseName = req.MySQL.DatabaseName
		collectorConfig.AllDatabases = req.MySQL.AllDatabases
	}

	// Map compression level
	compressionLevel := backup.CompressionBalanced
	switch req.CompressionLevel {
	case CompressionNone:
		compressionLevel = backup.CompressionNone
	case CompressionFast:
		compressionLevel = backup.CompressionFast
	case CompressionHigh:
		compressionLevel = backup.CompressionHigh
	case CompressionMaximum:
		compressionLevel = backup.CompressionMaximum
	}

	// Map backup strategy
	var backupStrategy backup.BackupStrategy
	switch req.Strategy {
	case "incremental":
		backupStrategy = backup.StrategyIncremental
	case "differential":
		backupStrategy = backup.StrategyDifferential
	case "synthetic_full":
		backupStrategy = backup.StrategySynthetic
	default:
		backupStrategy = backup.StrategyFull
	}

	// Build backup request
	backupReq := backup.BackupRequest{
		BackupID:            req.BackupID,
		BackupType:          backupType,
		UploadURL:           req.UploadURL,
		Encrypt:             req.Encrypt,
		EncryptKey:          req.EncryptKey,
		Strategy:            backupStrategy,
		BaseBackupID:        req.BaseBackupID,
		ParentBackupID:      req.ParentBackupID,
		PreviousManifestURL: req.PreviousManifestURL,
		ManifestUploadURL:   req.ManifestUploadURL,
		Config:              collectorConfig,
	}

	// Set compression level
	h.backupOrchestrator.SetCompressionLevel(compressionLevel)

	// Create progress reporter
	progress := backup.NewWebSocketProgressReporter(req.BackupID, func(msg map[string]interface{}) {
		h.SendRaw(msg)
	})

	// Execute backup via orchestrator
	result, err := h.backupOrchestrator.CreateBackup(ctx, backupReq, progress)
	if err != nil {
		return &createBackupResponse{
			BackupID: req.BackupID,
			Status:   "failed",
			Error:    err.Error(),
		}, nil
	}

	return &createBackupResponse{
		BackupID:            result.BackupID,
		Status:              result.Status,
		SizeBytes:           result.SizeBytes,
		CompressedBytes:     result.CompressedBytes,
		ContentHashSHA256:   result.ContentHashSHA256,
		ContentHashSHA512:   result.ContentHashSHA512,
		Encrypted:           result.Encrypted,
		EncryptionIV:        result.EncryptionIV,
		Error:               result.Error,
		Strategy:            string(result.Strategy),
		BaseBackupID:        result.BaseBackupID,
		ParentBackupID:      result.ParentBackupID,
		DeltaSizeBytes:      result.DeltaSizeBytes,
		NewFilesCount:       result.NewFilesCount,
		ModifiedFilesCount:  result.ModifiedFilesCount,
		DeletedFilesCount:   result.DeletedFilesCount,
		UnchangedFilesCount: result.UnchangedFilesCount,
		ManifestHash:        result.ManifestHash,
	}, nil
}

// restoreChainEntry represents a backup in the restore chain for incremental restore.
type restoreChainEntry struct {
	BackupID    string `json:"backup_id"`
	DownloadURL string `json:"download_url"`
	Encrypted   bool   `json:"encrypted"`
	EncryptKey  string `json:"encrypt_key,omitempty"`
	EncryptIV   string `json:"encrypt_iv,omitempty"`
	Strategy    string `json:"strategy"` // full, incremental, differential
}

type restoreBackupRequest struct {
	BackupID      string `json:"backup_id"`
	RestoreJobID  string `json:"restore_job_id,omitempty"` // For progress tracking
	BackupType    string `json:"backup_type"`
	DownloadURL   string `json:"download_url"` // Pre-signed URL for download
	Encrypted     bool   `json:"encrypted"`
	EncryptKey    string `json:"encrypt_key,omitempty"` // DEK for decryption (base64)
	EncryptIV     string `json:"encryption_iv,omitempty"`
	ProgressURL   string `json:"progress_url,omitempty"` // URL to report progress to

	// Incremental restore parameters
	Strategy         string              `json:"strategy,omitempty"`          // full, incremental, differential
	RestoreChain     []restoreChainEntry `json:"restore_chain,omitempty"`     // Ordered chain of backups to restore
	SkipDeletedFiles bool                `json:"skip_deleted_files,omitempty"` // Don't delete files marked as deleted

	// Files and Folders specific restore parameters
	RestorePaths      []string `json:"restore_paths,omitempty"`      // Specific paths to restore (empty = all)
	RestoreTarget     string   `json:"restore_target,omitempty"`     // Target directory for restore
	OverwriteFiles    bool     `json:"overwrite_files,omitempty"`    // Overwrite existing files
	PreserveStructure bool     `json:"preserve_structure,omitempty"` // Keep original directory structure

	// Docker-specific restore parameters
	ContainerName  string `json:"container_name,omitempty"`  // New container name for restore
	VolumeName     string `json:"volume_name,omitempty"`     // Volume name for restore
	ImageName      string `json:"image_name,omitempty"`      // Image name/tag for restore
	ComposePath    string `json:"compose_path,omitempty"`    // Compose file path for restore
	RestoreVolumes bool   `json:"restore_volumes,omitempty"` // Restore compose volumes

	// Proxmox-specific restore parameters
	VMID           uint64 `json:"vmid,omitempty"`
	ProxmoxStorage string `json:"proxmox_storage,omitempty"`
	TargetNode     string `json:"target_node,omitempty"`

	// Hyper-V-specific restore parameters
	VMName        string `json:"vm_name,omitempty"`
	TargetPath    string `json:"target_path,omitempty"`     // Path for restored VM
	RegisterVM    bool   `json:"register_vm,omitempty"`     // Register VM after restore
	GenerateNewID bool   `json:"generate_new_id,omitempty"` // Generate new VM ID
}

type restoreBackupResponse struct {
	BackupID      string `json:"backup_id"`
	RestoreJobID  string `json:"restore_job_id,omitempty"`
	Status        string `json:"status"`
	Success       bool   `json:"success"`
	TotalFiles    int    `json:"total_files"`
	RestoredFiles int    `json:"restored_files"`
	SkippedFiles  int    `json:"skipped_files"`
	FailedFiles   int    `json:"failed_files"`
	TotalSize     int64  `json:"total_size"`
	RestoredSize  int64  `json:"restored_size"`
	Error         string `json:"error,omitempty"`
}

// restoreProgress represents progress update for restore operations.
type restoreProgress struct {
	RestoreJobID  string `json:"job_id"`
	Status        string `json:"status"`
	Progress      int    `json:"progress"`       // 0-100
	CurrentPhase  string `json:"current_phase"`
	LogMessage    string `json:"log_message,omitempty"`
	LogLevel      string `json:"log_level,omitempty"` // info, warning, error
	TotalFiles    int    `json:"total_files,omitempty"`
	RestoredFiles int    `json:"restored_files,omitempty"`
	TotalSize     int64  `json:"total_size,omitempty"`
	RestoredSize  int64  `json:"restored_size,omitempty"`
	SkippedFiles  int    `json:"skipped_files,omitempty"`
	FailedFiles   int    `json:"failed_files,omitempty"`
	ErrorMessage  string `json:"error_message,omitempty"`
}

type getBackupStatusRequest struct {
	BackupID string `json:"backup_id"`
}

type verifyBackupRequest struct {
	BackupID       string `json:"backup_id"`
	DownloadURL    string `json:"download_url"`
	ExpectedSHA256 string `json:"expected_sha256"`
	ExpectedSHA512 string `json:"expected_sha512"`
}

type verifyBackupResponse struct {
	BackupID     string `json:"backup_id"`
	Valid        bool   `json:"valid"`
	SHA256Match  bool   `json:"sha256_match"`
	SHA512Match  bool   `json:"sha512_match"`
	ActualSHA256 string `json:"actual_sha256"`
	ActualSHA512 string `json:"actual_sha512"`
	Error        string `json:"error,omitempty"`
}

// registerBackupHandlers registers backup-related action handlers.
func (h *Handler) registerBackupHandlers() {
	h.handlers["create_agent_backup"] = h.handleCreateAgentBackup
	h.handlers["restore_agent_backup"] = h.handleRestoreAgentBackup
	h.handlers["get_backup_status"] = h.handleGetBackupStatus
	h.handlers["verify_agent_backup"] = h.handleVerifyAgentBackup
	h.handlers["backup_paths"] = h.handleBackupPaths
	h.handlers["list_backup_contents"] = h.handleListBackupContents
	h.handlers["test_database_connection"] = h.handleTestDatabaseConnection
}

// handleCreateAgentBackup handles backup creation requests.
func (h *Handler) handleCreateAgentBackup(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req createBackupRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.MsgInvalidRequest, err)
	}

	h.logger.Info("creating agent backup",
		"backup_id", req.BackupID,
		"backup_type", req.BackupType,
		"encrypt", req.Encrypt,
	)

	// Audit log backup start
	startTime := time.Now()
	audit.GetLogger().LogBackupStart(ctx, req.BackupType, req.BackupID, map[string]interface{}{
		"encrypt": req.Encrypt,
	})

	// Try to use the orchestrator for supported backup types (MVC pattern)
	if response, err := h.createBackupViaOrchestrator(ctx, req); response != nil {
		// Audit log completion
		if response.Status == "completed" {
			audit.GetLogger().LogBackupComplete(ctx, req.BackupType, req.BackupID, time.Since(startTime), map[string]interface{}{
				"original_size":   response.SizeBytes,
				"compressed_size": response.CompressedBytes,
				"encrypted":       response.Encrypted,
			})
		} else {
			audit.GetLogger().LogBackupFailed(ctx, req.BackupType, req.BackupID, fmt.Errorf("%s", response.Error), nil)
		}
		return response, err
	}

	// Fall back to legacy implementation for unsupported backup types
	// Collect data based on backup type (use extended function for virtualization types)
	var backupData []byte
	var err error
	if isVirtualizationBackup(req.BackupType) {
		backupData, err = h.collectBackupDataWithRequest(ctx, req)
	} else {
		backupData, err = h.collectBackupData(ctx, req.BackupType)
	}
	if err != nil {
		audit.GetLogger().LogBackupFailed(ctx, req.BackupType, req.BackupID, err, nil)
		return createBackupResponse{
			BackupID: req.BackupID,
			Status:   "failed",
			Error:    err.Error(),
		}, nil
	}

	originalSize := int64(len(backupData))

	// Determine compression level
	compressionLevel := req.CompressionLevel
	if compressionLevel == "" {
		compressionLevel = CompressionBalanced
	}

	var compressedData []byte
	var compressedSize int64

	if compressionLevel == CompressionNone {
		// No compression
		compressedData = backupData
		compressedSize = originalSize
	} else {
		// Compress with gzip using the specified level
		gzipLevel := compressionLevelToGzip[compressionLevel]
		if gzipLevel == 0 {
			gzipLevel = gzip.DefaultCompression
		}

		var compressedBuf bytes.Buffer
		gzWriter, err := gzip.NewWriterLevel(&compressedBuf, gzipLevel)
		if err != nil {
			audit.GetLogger().LogBackupFailed(ctx, req.BackupType, req.BackupID, err, map[string]interface{}{
				"phase": "compression_init",
			})
			return createBackupResponse{
				BackupID: req.BackupID,
				Status:   "failed",
				Error:    fmt.Sprintf("failed to create compressor: %v", err),
			}, nil
		}
		if _, err := gzWriter.Write(backupData); err != nil {
			gzWriter.Close()
			audit.GetLogger().LogBackupFailed(ctx, req.BackupType, req.BackupID, err, map[string]interface{}{
				"phase": "compression",
			})
			return createBackupResponse{
				BackupID: req.BackupID,
				Status:   "failed",
				Error:    fmt.Sprintf("compression failed: %v", err),
			}, nil
		}
		gzWriter.Close()
		compressedData = compressedBuf.Bytes()
		compressedSize = int64(len(compressedData))
	}

	// Compute hashes on compressed data
	sha256Hash := sha256.Sum256(compressedData)
	sha512Hash := sha512.Sum512(compressedData)
	sha256Hex := hex.EncodeToString(sha256Hash[:])
	sha512Hex := hex.EncodeToString(sha512Hash[:])

	var finalData []byte
	var encryptionIV string

	// Optionally encrypt
	if req.Encrypt && req.EncryptKey != "" {
		encryptedData, iv, err := h.encryptData(compressedData, req.EncryptKey)
		if err != nil {
			audit.GetLogger().LogBackupFailed(ctx, req.BackupType, req.BackupID, err, map[string]interface{}{
				"phase": "encryption",
			})
			return createBackupResponse{
				BackupID: req.BackupID,
				Status:   "failed",
				Error:    fmt.Sprintf("encryption failed: %v", err),
			}, nil
		}
		finalData = encryptedData
		encryptionIV = iv
	} else {
		finalData = compressedData
	}

	// Upload to pre-signed URL
	if err := h.uploadBackupData(ctx, req.UploadURL, finalData); err != nil {
		audit.GetLogger().LogBackupFailed(ctx, req.BackupType, req.BackupID, err, map[string]interface{}{
			"phase": "upload",
		})
		return createBackupResponse{
			BackupID: req.BackupID,
			Status:   "failed",
			Error:    fmt.Sprintf("upload failed: %v", err),
		}, nil
	}

	// Audit log backup completion
	audit.GetLogger().LogBackupComplete(ctx, req.BackupType, req.BackupID, time.Since(startTime), map[string]interface{}{
		"original_size":   originalSize,
		"compressed_size": compressedSize,
		"encrypted":       req.Encrypt,
	})

	h.logger.Info("agent backup created successfully",
		"backup_id", req.BackupID,
		"original_size", originalSize,
		"compressed_size", compressedSize,
		"encrypted", req.Encrypt,
	)

	return createBackupResponse{
		BackupID:          req.BackupID,
		Status:            "completed",
		SizeBytes:         originalSize,
		CompressedBytes:   compressedSize,
		ContentHashSHA256: sha256Hex,
		ContentHashSHA512: sha512Hex,
		Encrypted:         req.Encrypt && req.EncryptKey != "",
		EncryptionIV:      encryptionIV,
	}, nil
}

// collectBackupData gathers data based on backup type.
func (h *Handler) collectBackupData(ctx context.Context, backupType string) ([]byte, error) {
	switch backupType {
	case "agent_config":
		return h.collectConfigData()
	case "agent_logs":
		return h.collectLogsData()
	case "system_state":
		return h.collectSystemStateData(ctx)
	case "software_inventory":
		return h.collectSoftwareInventoryData(ctx)
	case "compliance_results":
		return h.collectComplianceResultsData()
	case "full":
		return h.collectFullBackupData(ctx)
	default:
		return nil, fmt.Errorf(i18n.MsgUnknownBackupType, backupType)
	}
}

// collectBackupDataWithRequest gathers data based on backup type with full request context.
func (h *Handler) collectBackupDataWithRequest(ctx context.Context, req createBackupRequest) ([]byte, error) {
	switch req.BackupType {
	// Agent backups
	case "agent_config":
		return h.collectConfigData()
	case "agent_logs":
		return h.collectLogsData()
	case "system_state":
		return h.collectSystemStateData(ctx)
	case "software_inventory":
		return h.collectSoftwareInventoryData(ctx)
	case "compliance_results":
		return h.collectComplianceResultsData()
	case "full":
		return h.collectFullBackupData(ctx)
	case "files_and_folders":
		return h.collectFilesAndFoldersBackup(ctx, req)

	// Docker backups
	case "docker_container":
		return h.collectDockerContainerBackup(ctx, req)
	case "docker_volume":
		return h.collectDockerVolumeBackup(ctx, req)
	case "docker_image":
		return h.collectDockerImageBackup(ctx, req)
	case "docker_compose":
		return h.collectDockerComposeBackup(ctx, req)

	// Proxmox backups
	case "proxmox_vm":
		return h.collectProxmoxVMBackup(ctx, req)
	case "proxmox_lxc":
		return h.collectProxmoxLXCBackup(ctx, req)
	case "proxmox_config":
		return h.collectProxmoxConfigBackup(ctx, req)

	// Hyper-V backups (Windows only)
	case "hyperv_vm":
		return h.collectHyperVVMBackup(ctx, req)
	case "hyperv_checkpoint":
		return h.collectHyperVCheckpointBackup(ctx, req)
	case "hyperv_config":
		return h.collectHyperVConfigBackup(ctx, req)

	// Database backups
	case "postgresql":
		return h.collectPostgreSQLBackup(ctx, req)
	case "mysql":
		return h.collectMySQLBackup(ctx, req)

	default:
		return nil, fmt.Errorf(i18n.MsgUnknownBackupType, req.BackupType)
	}
}

// collectConfigData collects agent configuration files.
func (h *Handler) collectConfigData() ([]byte, error) {
	backupData := make(map[string]interface{})

	// Read config file
	configPath := h.paths.ConfigFile
	if configData, err := os.ReadFile(configPath); err == nil {
		backupData["config.json"] = base64.StdEncoding.EncodeToString(configData)
	}

	// Include mTLS certificates (public parts only)
	if h.cfg.IsMTLSEnabled() {
		if caCert, err := os.ReadFile(h.paths.CACert); err == nil {
			backupData["ca.crt"] = base64.StdEncoding.EncodeToString(caCert)
		}
		if clientCert, err := os.ReadFile(h.paths.ClientCert); err == nil {
			backupData["client.crt"] = base64.StdEncoding.EncodeToString(clientCert)
		}
		// Note: Client key is intentionally NOT included for security
	}

	backupData["backup_type"] = "agent_config"
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = h.cfg.GetUUID()

	return json.Marshal(backupData)
}

// collectLogsData collects agent log files.
func (h *Handler) collectLogsData() ([]byte, error) {
	backupData := make(map[string]interface{})

	// Get log directory
	logDir := h.paths.LogDir

	// Collect all log files
	logFiles := make(map[string]string)
	err := filepath.Walk(logDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".log") {
			// Limit log file size to 10MB each
			if info.Size() > 10*1024*1024 {
				return nil
			}
			if data, err := os.ReadFile(path); err == nil {
				relPath, _ := filepath.Rel(logDir, path)
				logFiles[relPath] = base64.StdEncoding.EncodeToString(data)
			}
		}
		return nil
	})
	if err != nil {
		h.logger.Warn("error walking log directory", "error", err)
	}

	backupData["logs"] = logFiles
	backupData["backup_type"] = "agent_logs"
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = h.cfg.GetUUID()

	return json.Marshal(backupData)
}

// collectSystemStateData collects system state using osquery.
func (h *Handler) collectSystemStateData(ctx context.Context) ([]byte, error) {
	backupData := make(map[string]interface{})

	client := osquery.New()
	if client.IsAvailable() {
		// System info
		if result, err := client.GetSystemInfo(ctx); err == nil {
			backupData["system_info"] = result.Rows
		}

		// OS version
		if result, err := client.Query(ctx, "SELECT * FROM os_version"); err == nil {
			backupData["os_version"] = result.Rows
		}

		// Hardware info
		if result, err := client.Query(ctx, "SELECT * FROM system_info"); err == nil {
			backupData["hardware_info"] = result.Rows
		}

		// Network interfaces
		if result, err := client.Query(ctx, "SELECT * FROM interface_addresses"); err == nil {
			backupData["network_interfaces"] = result.Rows
		}

		// Users
		if result, err := client.Query(ctx, "SELECT * FROM users"); err == nil {
			backupData["users"] = result.Rows
		}

		// Disk info
		if result, err := client.Query(ctx, "SELECT * FROM disk_info"); err == nil {
			backupData["disk_info"] = result.Rows
		}
	} else {
		h.logger.Warn("osquery not available for system state backup")
	}

	backupData["backup_type"] = "system_state"
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = h.cfg.GetUUID()
	backupData["os"] = runtime.GOOS
	backupData["arch"] = runtime.GOARCH

	return json.Marshal(backupData)
}

// collectSoftwareInventoryData collects installed software list.
func (h *Handler) collectSoftwareInventoryData(ctx context.Context) ([]byte, error) {
	backupData := make(map[string]interface{})

	client := osquery.New()
	if client.IsAvailable() {
		// Get installed programs
		var query string
		switch runtime.GOOS {
		case "windows":
			query = "SELECT name, version, publisher, install_location, install_date FROM programs"
		case "darwin":
			query = "SELECT name, bundle_short_version as version, path FROM apps"
		default:
			query = "SELECT name, version, source FROM deb_packages UNION SELECT name, version, 'rpm' as source FROM rpm_packages"
		}

		if result, err := client.Query(ctx, query); err == nil {
			backupData["installed_software"] = result.Rows
		}
	} else {
		h.logger.Warn("osquery not available for software inventory backup")
	}

	backupData["backup_type"] = "software_inventory"
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = h.cfg.GetUUID()
	backupData["os"] = runtime.GOOS

	return json.Marshal(backupData)
}

// collectComplianceResultsData collects cached compliance check results.
func (h *Handler) collectComplianceResultsData() ([]byte, error) {
	backupData := make(map[string]interface{})

	// Try to read cached compliance results from data directory
	dataDir := filepath.Dir(h.paths.ConfigFile)
	complianceFile := filepath.Join(dataDir, "compliance_cache.json")

	if data, err := os.ReadFile(complianceFile); err == nil {
		var cachedResults interface{}
		if json.Unmarshal(data, &cachedResults) == nil {
			backupData["compliance_results"] = cachedResults
		}
	}

	backupData["backup_type"] = "compliance_results"
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = h.cfg.GetUUID()

	return json.Marshal(backupData)
}

// collectFullBackupData collects all backup types.
func (h *Handler) collectFullBackupData(ctx context.Context) ([]byte, error) {
	fullBackup := make(map[string]interface{})

	// Collect all types
	if configData, err := h.collectConfigData(); err == nil {
		var config interface{}
		json.Unmarshal(configData, &config)
		fullBackup["config"] = config
	}

	if logsData, err := h.collectLogsData(); err == nil {
		var logs interface{}
		json.Unmarshal(logsData, &logs)
		fullBackup["logs"] = logs
	}

	if systemData, err := h.collectSystemStateData(ctx); err == nil {
		var system interface{}
		json.Unmarshal(systemData, &system)
		fullBackup["system_state"] = system
	}

	if softwareData, err := h.collectSoftwareInventoryData(ctx); err == nil {
		var software interface{}
		json.Unmarshal(softwareData, &software)
		fullBackup["software_inventory"] = software
	}

	if complianceData, err := h.collectComplianceResultsData(); err == nil {
		var compliance interface{}
		json.Unmarshal(complianceData, &compliance)
		fullBackup["compliance_results"] = compliance
	}

	fullBackup["backup_type"] = "full"
	fullBackup["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	fullBackup["agent_uuid"] = h.cfg.GetUUID()
	fullBackup["os"] = runtime.GOOS
	fullBackup["arch"] = runtime.GOARCH

	return json.Marshal(fullBackup)
}

// encryptData encrypts data using AES-256-GCM.
func (h *Handler) encryptData(data []byte, keyBase64 string) ([]byte, string, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, "", fmt.Errorf("invalid encryption key: %w", err)
	}

	if len(key) != 32 {
		return nil, "", fmt.Errorf("encryption key must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, "", fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, "", fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	ivBase64 := base64.StdEncoding.EncodeToString(nonce)

	return ciphertext, ivBase64, nil
}

// decryptData decrypts data using AES-256-GCM.
func (h *Handler) decryptData(ciphertext []byte, keyBase64 string, ivBase64 string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid encryption key: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// uploadBackupData uploads backup data to a pre-signed URL.
func (h *Handler) uploadBackupData(ctx context.Context, uploadURL string, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, "PUT", uploadURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(data))

	client := &http.Client{
		Timeout: 5 * time.Minute,
	}

	resp, err := client.Do(req)
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

// handleRestoreAgentBackup handles backup restoration requests.
func (h *Handler) handleRestoreAgentBackup(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req restoreBackupRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.MsgInvalidRequest, err)
	}

	h.logger.Info("restoring agent backup",
		"backup_id", req.BackupID,
		"restore_job_id", req.RestoreJobID,
		"backup_type", req.BackupType,
		"encrypted", req.Encrypted,
	)

	// Create a restore context to track progress
	restoreCtx := &restoreContext{
		req:           req,
		handler:       h,
		totalFiles:    0,
		restoredFiles: 0,
		skippedFiles:  0,
		failedFiles:   0,
		totalSize:     0,
		restoredSize:  0,
	}

	// Report downloading phase
	restoreCtx.reportProgress("downloading", 5, "Downloading backup data", "info")

	// Download backup data
	backupData, err := h.downloadBackupData(ctx, req.DownloadURL)
	if err != nil {
		restoreCtx.reportProgress("failed", 0, fmt.Sprintf("Download failed: %v", err), "error")
		return restoreBackupResponse{
			BackupID:     req.BackupID,
			RestoreJobID: req.RestoreJobID,
			Status:       "failed",
			Error:        fmt.Sprintf("download failed: %v", err),
		}, nil
	}

	// Report decrypting phase
	restoreCtx.reportProgress("decrypting", 20, "Download complete, decrypting...", "info")

	// Decrypt if needed
	if req.Encrypted && req.EncryptKey != "" {
		backupData, err = h.decryptData(backupData, req.EncryptKey, req.EncryptIV)
		if err != nil {
			restoreCtx.reportProgress("failed", 0, fmt.Sprintf("Decryption failed: %v", err), "error")
			return restoreBackupResponse{
				BackupID:     req.BackupID,
				RestoreJobID: req.RestoreJobID,
				Status:       "failed",
				Error:        fmt.Sprintf("decryption failed: %v", err),
			}, nil
		}
	}

	// Report extracting phase
	restoreCtx.reportProgress("extracting", 40, "Decryption complete, extracting...", "info")

	// Decompress
	gzReader, err := gzip.NewReader(bytes.NewReader(backupData))
	if err != nil {
		restoreCtx.reportProgress("failed", 0, fmt.Sprintf("Decompression failed: %v", err), "error")
		return restoreBackupResponse{
			BackupID:     req.BackupID,
			RestoreJobID: req.RestoreJobID,
			Status:       "failed",
			Error:        fmt.Sprintf("decompression failed: %v", err),
		}, nil
	}
	defer gzReader.Close()

	decompressedData, err := io.ReadAll(gzReader)
	if err != nil {
		restoreCtx.reportProgress("failed", 0, fmt.Sprintf("Reading decompressed data failed: %v", err), "error")
		return restoreBackupResponse{
			BackupID:     req.BackupID,
			RestoreJobID: req.RestoreJobID,
			Status:       "failed",
			Error:        fmt.Sprintf("reading decompressed data: %v", err),
		}, nil
	}

	// Report restoring phase
	restoreCtx.reportProgress("restoring", 50, "Extraction complete, restoring files...", "info")

	// Restore based on backup type - all types now support progress tracking
	restoreErr := h.restoreBackupDataWithRequestProgress(ctx, req, decompressedData, restoreCtx)
	if restoreErr != nil {
		restoreCtx.reportProgress("failed", 0, fmt.Sprintf("Restore failed: %v", restoreErr), "error")
		return restoreBackupResponse{
			BackupID:      req.BackupID,
			RestoreJobID:  req.RestoreJobID,
			Status:        "failed",
			TotalFiles:    restoreCtx.totalFiles,
			RestoredFiles: restoreCtx.restoredFiles,
			SkippedFiles:  restoreCtx.skippedFiles,
			FailedFiles:   restoreCtx.failedFiles,
			TotalSize:     restoreCtx.totalSize,
			RestoredSize:  restoreCtx.restoredSize,
			Error:         fmt.Sprintf("restore failed: %v", restoreErr),
		}, nil
	}

	// Report completion
	restoreCtx.reportProgress("completed", 100, "Restore completed successfully", "info")

	h.logger.Info("agent backup restored successfully",
		"backup_id", req.BackupID,
		"restore_job_id", req.RestoreJobID,
		"backup_type", req.BackupType,
		"restored_files", restoreCtx.restoredFiles,
		"skipped_files", restoreCtx.skippedFiles,
		"failed_files", restoreCtx.failedFiles,
	)

	return restoreBackupResponse{
		BackupID:      req.BackupID,
		RestoreJobID:  req.RestoreJobID,
		Status:        "completed",
		Success:       true,
		TotalFiles:    restoreCtx.totalFiles,
		RestoredFiles: restoreCtx.restoredFiles,
		SkippedFiles:  restoreCtx.skippedFiles,
		FailedFiles:   restoreCtx.failedFiles,
		TotalSize:     restoreCtx.totalSize,
		RestoredSize:  restoreCtx.restoredSize,
	}, nil
}

// restoreContext tracks progress during restore operations.
type restoreContext struct {
	req           restoreBackupRequest
	handler       *Handler
	totalFiles    int
	restoredFiles int
	skippedFiles  int
	failedFiles   int
	totalSize     int64
	restoredSize  int64
}

// reportProgress sends a progress update via WebSocket.
func (rc *restoreContext) reportProgress(status string, progress int, message string, level string) {
	if rc.req.RestoreJobID == "" {
		return // No job ID, skip progress reporting
	}

	progressUpdate := restoreProgress{
		RestoreJobID:  rc.req.RestoreJobID,
		Status:        status,
		Progress:      progress,
		CurrentPhase:  message,
		LogMessage:    message,
		LogLevel:      level,
		TotalFiles:    rc.totalFiles,
		RestoredFiles: rc.restoredFiles,
		TotalSize:     rc.totalSize,
		RestoredSize:  rc.restoredSize,
		SkippedFiles:  rc.skippedFiles,
		FailedFiles:   rc.failedFiles,
	}

	// Log progress update
	rc.handler.logger.Debug("restore progress update",
		"job_id", rc.req.RestoreJobID,
		"status", status,
		"progress", progress,
		"message", message,
	)

	// Send progress update via WebSocket
	rc.handler.Send(Response{
		Action:  "restore_progress",
		Success: true,
		Data:    progressUpdate,
	})
}

// restoreBackupDataWithRequestProgress wraps restoreBackupDataWithRequest with progress reporting.
func (h *Handler) restoreBackupDataWithRequestProgress(ctx context.Context, req restoreBackupRequest, data []byte, restoreCtx *restoreContext) error {
	switch req.BackupType {
	// Agent backups with progress
	case "agent_config":
		restoreCtx.reportProgress("restoring", 60, "Restoring agent configuration...", "info")
		restoreCtx.totalFiles = 1
		if err := h.restoreConfigData(data); err != nil {
			restoreCtx.failedFiles = 1
			return err
		}
		restoreCtx.restoredFiles = 1
		restoreCtx.reportProgress("restoring", 90, "Agent configuration restored", "info")
		return nil

	case "agent_logs":
		restoreCtx.reportProgress("restoring", 60, "Log restoration not supported (logs are immutable)", "warning")
		return nil

	case "system_state", "software_inventory":
		restoreCtx.reportProgress("restoring", 60, fmt.Sprintf("%s restoration not applicable (informational data)", req.BackupType), "info")
		return nil

	case "compliance_results":
		restoreCtx.reportProgress("restoring", 60, "Restoring compliance results...", "info")
		restoreCtx.totalFiles = 1
		if err := h.restoreComplianceData(data); err != nil {
			restoreCtx.failedFiles = 1
			return err
		}
		restoreCtx.restoredFiles = 1
		restoreCtx.reportProgress("restoring", 90, "Compliance results restored", "info")
		return nil

	case "full":
		restoreCtx.reportProgress("restoring", 55, "Restoring full backup (config + compliance)...", "info")
		var fullBackup map[string]json.RawMessage
		if err := json.Unmarshal(data, &fullBackup); err != nil {
			return err
		}
		restoreCtx.totalFiles = 2
		if configData, ok := fullBackup["config"]; ok {
			restoreCtx.reportProgress("restoring", 65, "Restoring configuration...", "info")
			if err := h.restoreConfigData(configData); err != nil {
				h.logger.Warn("failed to restore config from full backup", "error", err)
				restoreCtx.failedFiles++
			} else {
				restoreCtx.restoredFiles++
			}
		}
		if complianceData, ok := fullBackup["compliance_results"]; ok {
			restoreCtx.reportProgress("restoring", 80, "Restoring compliance results...", "info")
			if err := h.restoreComplianceData(complianceData); err != nil {
				h.logger.Warn("failed to restore compliance from full backup", "error", err)
				restoreCtx.failedFiles++
			} else {
				restoreCtx.restoredFiles++
			}
		}
		restoreCtx.reportProgress("restoring", 90, "Full backup restored", "info")
		return nil

	// Files and Folders with detailed progress
	case "files_and_folders":
		return h.restoreFilesAndFoldersWithProgress(ctx, req, data, restoreCtx)

	// Docker restores with progress
	case "docker_container":
		restoreCtx.reportProgress("restoring", 60, "Restoring Docker container...", "info")
		restoreCtx.totalFiles = 1
		if err := h.restoreDockerContainer(ctx, req, data); err != nil {
			restoreCtx.failedFiles = 1
			return err
		}
		restoreCtx.restoredFiles = 1
		restoreCtx.reportProgress("restoring", 90, "Docker container restored", "info")
		return nil

	case "docker_volume":
		restoreCtx.reportProgress("restoring", 60, "Restoring Docker volume...", "info")
		restoreCtx.totalFiles = 1
		if err := h.restoreDockerVolume(ctx, req, data); err != nil {
			restoreCtx.failedFiles = 1
			return err
		}
		restoreCtx.restoredFiles = 1
		restoreCtx.reportProgress("restoring", 90, "Docker volume restored", "info")
		return nil

	case "docker_image":
		restoreCtx.reportProgress("restoring", 60, "Restoring Docker image...", "info")
		restoreCtx.totalFiles = 1
		if err := h.restoreDockerImage(ctx, req, data); err != nil {
			restoreCtx.failedFiles = 1
			return err
		}
		restoreCtx.restoredFiles = 1
		restoreCtx.reportProgress("restoring", 90, "Docker image restored", "info")
		return nil

	case "docker_compose":
		restoreCtx.reportProgress("restoring", 60, "Restoring Docker Compose project...", "info")
		restoreCtx.totalFiles = 1
		if err := h.restoreDockerCompose(ctx, req, data); err != nil {
			restoreCtx.failedFiles = 1
			return err
		}
		restoreCtx.restoredFiles = 1
		restoreCtx.reportProgress("restoring", 90, "Docker Compose project restored", "info")
		return nil

	// Proxmox restores with progress
	case "proxmox_vm", "proxmox_lxc":
		restoreCtx.reportProgress("restoring", 60, "Proxmox VM/LXC restoration should be performed via Proxmox restore tools", "warning")
		h.logger.Info("Proxmox VM/LXC restoration should be performed via Proxmox restore tools",
			"backup_type", req.BackupType)
		return nil

	case "proxmox_config":
		restoreCtx.reportProgress("restoring", 60, "Restoring Proxmox configuration...", "info")
		restoreCtx.totalFiles = 1
		if err := h.restoreProxmoxConfig(ctx, req, data); err != nil {
			restoreCtx.failedFiles = 1
			return err
		}
		restoreCtx.restoredFiles = 1
		restoreCtx.reportProgress("restoring", 90, "Proxmox configuration restored", "info")
		return nil

	// Hyper-V restores with progress
	case "hyperv_vm":
		restoreCtx.reportProgress("restoring", 60, "Restoring Hyper-V VM...", "info")
		restoreCtx.totalFiles = 1
		if err := h.restoreHyperVVM(ctx, req, data); err != nil {
			restoreCtx.failedFiles = 1
			return err
		}
		restoreCtx.restoredFiles = 1
		restoreCtx.reportProgress("restoring", 90, "Hyper-V VM restored", "info")
		return nil

	case "hyperv_checkpoint":
		restoreCtx.reportProgress("restoring", 60, "Hyper-V checkpoint restoration is informational only", "info")
		h.logger.Info("Hyper-V checkpoint restoration is informational only")
		return nil

	case "hyperv_config":
		restoreCtx.reportProgress("restoring", 60, "Hyper-V config restoration is informational only", "info")
		h.logger.Info("Hyper-V config restoration is informational only")
		return nil

	default:
		return fmt.Errorf(i18n.MsgUnknownBackupType, req.BackupType)
	}
}

// downloadBackupData downloads backup data from a pre-signed URL.
func (h *Handler) downloadBackupData(ctx context.Context, downloadURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	client := &http.Client{
		Timeout: 5 * time.Minute,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("download failed with status %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// restoreBackupData restores data based on backup type.
func (h *Handler) restoreBackupData(backupType string, data []byte) error {
	switch backupType {
	case "agent_config":
		return h.restoreConfigData(data)
	case "agent_logs":
		// Logs are typically not restored
		h.logger.Info("log restoration not supported (logs are immutable)")
		return nil
	case "system_state":
		// System state is informational, cannot be "restored"
		h.logger.Info("system state restoration not applicable")
		return nil
	case "software_inventory":
		// Software inventory is informational, cannot be "restored"
		h.logger.Info("software inventory restoration not applicable")
		return nil
	case "compliance_results":
		return h.restoreComplianceData(data)
	case "full":
		// For full backups, only restore config and compliance
		var fullBackup map[string]json.RawMessage
		if err := json.Unmarshal(data, &fullBackup); err != nil {
			return err
		}
		if configData, ok := fullBackup["config"]; ok {
			if err := h.restoreConfigData(configData); err != nil {
				h.logger.Warn("failed to restore config from full backup", "error", err)
			}
		}
		if complianceData, ok := fullBackup["compliance_results"]; ok {
			if err := h.restoreComplianceData(complianceData); err != nil {
				h.logger.Warn("failed to restore compliance from full backup", "error", err)
			}
		}
		return nil
	default:
		return fmt.Errorf(i18n.MsgUnknownBackupType, backupType)
	}
}

// restoreBackupDataWithRequest restores data with full request context for virtualization types.
func (h *Handler) restoreBackupDataWithRequest(ctx context.Context, req restoreBackupRequest, data []byte) error {
	switch req.BackupType {
	// Agent backups - use standard restore
	case "agent_config", "agent_logs", "system_state", "software_inventory", "compliance_results", "full":
		return h.restoreBackupData(req.BackupType, data)

	// Files and Folders restore with selective path support
	case "files_and_folders":
		return h.restoreFilesAndFolders(ctx, req, data)

	// Docker restores
	case "docker_container":
		return h.restoreDockerContainer(ctx, req, data)
	case "docker_volume":
		return h.restoreDockerVolume(ctx, req, data)
	case "docker_image":
		return h.restoreDockerImage(ctx, req, data)
	case "docker_compose":
		return h.restoreDockerCompose(ctx, req, data)

	// Proxmox restores - typically handled by Proxmox itself
	case "proxmox_vm", "proxmox_lxc":
		h.logger.Info("Proxmox VM/LXC restoration should be performed via Proxmox restore tools",
			"backup_type", req.BackupType)
		return nil
	case "proxmox_config":
		return h.restoreProxmoxConfig(ctx, req, data)

	// Hyper-V restores
	case "hyperv_vm":
		return h.restoreHyperVVM(ctx, req, data)
	case "hyperv_checkpoint":
		h.logger.Info("Hyper-V checkpoint restoration is informational only")
		return nil
	case "hyperv_config":
		h.logger.Info("Hyper-V config restoration is informational only")
		return nil

	default:
		return fmt.Errorf(i18n.MsgUnknownBackupType, req.BackupType)
	}
}

// restoreConfigData restores agent configuration.
func (h *Handler) restoreConfigData(data []byte) error {
	var backupData map[string]interface{}
	if err := json.Unmarshal(data, &backupData); err != nil {
		return err
	}

	// Restore config file
	if configBase64, ok := backupData["config.json"].(string); ok {
		configData, err := base64.StdEncoding.DecodeString(configBase64)
		if err != nil {
			return fmt.Errorf("decoding config: %w", err)
		}

		// Backup current config
		backupPath := h.paths.ConfigFile + ".backup"
		if currentData, err := os.ReadFile(h.paths.ConfigFile); err == nil {
			if err := os.WriteFile(backupPath, currentData, 0600); err != nil {
				h.logger.Warn("failed to backup current config", "path", backupPath, "error", err)
			}
		}

		// Write restored config
		if err := os.WriteFile(h.paths.ConfigFile, configData, 0600); err != nil {
			return fmt.Errorf("writing config: %w", err)
		}

		h.logger.Info("agent config restored from backup")
	}

	return nil
}

// restoreComplianceData restores cached compliance results.
func (h *Handler) restoreComplianceData(data []byte) error {
	var backupData map[string]interface{}
	if err := json.Unmarshal(data, &backupData); err != nil {
		return err
	}

	if results, ok := backupData["compliance_results"]; ok {
		dataDir := filepath.Dir(h.paths.ConfigFile)
		complianceFile := filepath.Join(dataDir, "compliance_cache.json")

		resultsData, err := json.Marshal(results)
		if err != nil {
			return fmt.Errorf("marshaling compliance results: %w", err)
		}

		if err := os.WriteFile(complianceFile, resultsData, 0600); err != nil {
			return fmt.Errorf("writing compliance cache: %w", err)
		}

		h.logger.Info("compliance results restored from backup")
	}

	return nil
}

// handleGetBackupStatus returns the status of a backup operation.
func (h *Handler) handleGetBackupStatus(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req getBackupStatusRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.MsgInvalidRequest, err)
	}

	// For now, we don't track in-progress backups
	// This could be extended to track async backup operations
	return map[string]interface{}{
		"backup_id": req.BackupID,
		"status":    "unknown",
		"message":   "Backup status tracking not implemented for synchronous operations",
	}, nil
}

// handleVerifyAgentBackup verifies backup integrity.
func (h *Handler) handleVerifyAgentBackup(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req verifyBackupRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.MsgInvalidRequest, err)
	}

	h.logger.Info("verifying agent backup",
		"backup_id", req.BackupID,
	)

	// Download backup data
	backupData, err := h.downloadBackupData(ctx, req.DownloadURL)
	if err != nil {
		return verifyBackupResponse{
			BackupID: req.BackupID,
			Valid:    false,
			Error:    fmt.Sprintf("download failed: %v", err),
		}, nil
	}

	// Compute hashes
	sha256Hash := sha256.Sum256(backupData)
	sha512Hash := sha512.Sum512(backupData)
	actualSHA256 := hex.EncodeToString(sha256Hash[:])
	actualSHA512 := hex.EncodeToString(sha512Hash[:])

	sha256Match := actualSHA256 == req.ExpectedSHA256
	sha512Match := actualSHA512 == req.ExpectedSHA512
	valid := sha256Match && sha512Match

	h.logger.Info("backup verification result",
		"backup_id", req.BackupID,
		"valid", valid,
		"sha256_match", sha256Match,
		"sha512_match", sha512Match,
	)

	return verifyBackupResponse{
		BackupID:     req.BackupID,
		Valid:        valid,
		SHA256Match:  sha256Match,
		SHA512Match:  sha512Match,
		ActualSHA256: actualSHA256,
		ActualSHA512: actualSHA512,
	}, nil
}

// =============================================================================
// Virtualization Backup Functions
// =============================================================================

// isVirtualizationBackup checks if the backup type is a virtualization backup.
func isVirtualizationBackup(backupType string) bool {
	virtTypes := []string{
		"docker_container", "docker_volume", "docker_image", "docker_compose",
		"proxmox_vm", "proxmox_lxc", "proxmox_config",
		"hyperv_vm", "hyperv_checkpoint", "hyperv_config",
		"files_and_folders",
		"postgresql", "mysql",
	}
	for _, vt := range virtTypes {
		if backupType == vt {
			return true
		}
	}
	return false
}

// =============================================================================
// Docker Backup Functions
// =============================================================================

// collectDockerContainerBackup creates a backup of a Docker container.
func (h *Handler) collectDockerContainerBackup(ctx context.Context, req createBackupRequest) ([]byte, error) {
	if !actions.IsDockerAvailable() {
		return nil, fmt.Errorf(i18n.MsgDockerNotAvailable)
	}

	if req.ContainerID == "" {
		return nil, fmt.Errorf("container_id is required for docker_container backup")
	}

	backupData := make(map[string]interface{})
	backupData["backup_type"] = "docker_container"
	backupData["container_id"] = req.ContainerID
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = h.cfg.GetUUID()

	// Get container inspection data
	inspectData, err := actions.InspectDockerContainer(ctx, req.ContainerID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}
	backupData["inspect"] = inspectData

	// Get container stats
	stats, err := actions.GetDockerContainerStats(ctx, req.ContainerID)
	if err == nil {
		backupData["stats"] = stats
	}

	// Include logs if requested
	if req.IncludeLogs {
		logs, err := actions.GetDockerContainerLogs(ctx, req.ContainerID, 10000, true)
		if err == nil {
			backupData["logs"] = logs
		}
	}

	// Stop container for consistent backup if requested
	wasRunning := false
	if req.StopContainer {
		// Check if container is running
		containers, err := actions.ListDockerContainers(ctx, false)
		if err == nil {
			for _, c := range containers {
				if c.ID == req.ContainerID || c.Name == req.ContainerID {
					wasRunning = c.State == "running"
					break
				}
			}
		}

		if wasRunning {
			h.logger.Info("stopping container for backup", "container_id", req.ContainerID)
			if err := actions.DockerContainerAction(ctx, req.ContainerID, "stop"); err != nil {
				h.logger.Warn("failed to stop container", "error", err)
			}
		}
	}

	// Export container filesystem
	exportCmd := exec.CommandContext(ctx, "docker", "export", req.ContainerID)
	exportData, err := exportCmd.Output()
	if err != nil {
		if req.StopContainer && wasRunning {
			actions.DockerContainerAction(ctx, req.ContainerID, "start")
		}
		return nil, fmt.Errorf("failed to export container: %w", err)
	}
	backupData["export_data"] = base64.StdEncoding.EncodeToString(exportData)
	backupData["export_size"] = len(exportData)

	// Restart container if it was stopped
	if req.StopContainer && wasRunning {
		h.logger.Info("restarting container after backup", "container_id", req.ContainerID)
		if err := actions.DockerContainerAction(ctx, req.ContainerID, "start"); err != nil {
			h.logger.Warn("failed to restart container", "error", err)
		}
	}

	return json.Marshal(backupData)
}

// collectDockerVolumeBackup creates a backup of a Docker volume.
func (h *Handler) collectDockerVolumeBackup(ctx context.Context, req createBackupRequest) ([]byte, error) {
	if !actions.IsDockerAvailable() {
		return nil, fmt.Errorf(i18n.MsgDockerNotAvailable)
	}

	if req.VolumeName == "" {
		return nil, fmt.Errorf("volume_name is required for docker_volume backup")
	}

	backupData := make(map[string]interface{})
	backupData["backup_type"] = "docker_volume"
	backupData["volume_name"] = req.VolumeName
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = h.cfg.GetUUID()

	// Get volume info
	inspectCmd := exec.CommandContext(ctx, "docker", "volume", "inspect", req.VolumeName)
	inspectOutput, err := inspectCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to inspect volume: %w", err)
	}

	var volumeInfo []map[string]interface{}
	if err := json.Unmarshal(inspectOutput, &volumeInfo); err == nil && len(volumeInfo) > 0 {
		backupData["volume_info"] = volumeInfo[0]
	}

	// Create tar archive of volume using a temporary container
	// docker run --rm -v VOLUME:/data -v /tmp:/backup alpine tar czf /backup/volume.tar.gz -C /data .
	tarCmd := exec.CommandContext(ctx, "docker", "run", "--rm",
		"-v", req.VolumeName+":/data:ro",
		"alpine", "tar", "-czf", "-", "-C", "/data", ".")
	volumeData, err := tarCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to archive volume: %w", err)
	}

	backupData["volume_data"] = base64.StdEncoding.EncodeToString(volumeData)
	backupData["volume_size"] = len(volumeData)

	return json.Marshal(backupData)
}

// collectDockerImageBackup creates a backup of a Docker image.
func (h *Handler) collectDockerImageBackup(ctx context.Context, req createBackupRequest) ([]byte, error) {
	if !actions.IsDockerAvailable() {
		return nil, fmt.Errorf(i18n.MsgDockerNotAvailable)
	}

	if req.ImageName == "" {
		return nil, fmt.Errorf("image_name is required for docker_image backup")
	}

	backupData := make(map[string]interface{})
	backupData["backup_type"] = "docker_image"
	backupData["image_name"] = req.ImageName
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = h.cfg.GetUUID()

	// Get image info
	inspectCmd := exec.CommandContext(ctx, "docker", "image", "inspect", req.ImageName)
	inspectOutput, err := inspectCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to inspect image: %w", err)
	}

	var imageInfo []map[string]interface{}
	if err := json.Unmarshal(inspectOutput, &imageInfo); err == nil && len(imageInfo) > 0 {
		backupData["image_info"] = imageInfo[0]
	}

	// Save image to tar
	saveCmd := exec.CommandContext(ctx, "docker", "save", req.ImageName)
	imageData, err := saveCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to save image: %w", err)
	}

	backupData["image_data"] = base64.StdEncoding.EncodeToString(imageData)
	backupData["image_size"] = len(imageData)

	return json.Marshal(backupData)
}

// collectDockerComposeBackup creates a backup of a Docker Compose project.
func (h *Handler) collectDockerComposeBackup(ctx context.Context, req createBackupRequest) ([]byte, error) {
	if !actions.IsDockerAvailable() {
		return nil, fmt.Errorf(i18n.MsgDockerNotAvailable)
	}

	if req.ComposePath == "" {
		return nil, fmt.Errorf("compose_path is required for docker_compose backup")
	}

	backupData := make(map[string]interface{})
	backupData["backup_type"] = "docker_compose"
	backupData["compose_path"] = req.ComposePath
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = h.cfg.GetUUID()

	// Read compose file
	composeData, err := os.ReadFile(req.ComposePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read compose file: %w", err)
	}
	backupData["compose_file"] = base64.StdEncoding.EncodeToString(composeData)

	// Read .env file if exists
	envPath := filepath.Join(filepath.Dir(req.ComposePath), ".env")
	if envData, err := os.ReadFile(envPath); err == nil {
		backupData["env_file"] = base64.StdEncoding.EncodeToString(envData)
	}

	// Get compose project info
	composeDir := filepath.Dir(req.ComposePath)
	psCmd := exec.CommandContext(ctx, "docker", "compose", "-f", req.ComposePath, "ps", "--format", "json")
	psCmd.Dir = composeDir
	if psOutput, err := psCmd.Output(); err == nil {
		var services []interface{}
		if json.Unmarshal(psOutput, &services) == nil {
			backupData["services"] = services
		}
	}

	// Collect volumes used by the compose project
	configCmd := exec.CommandContext(ctx, "docker", "compose", "-f", req.ComposePath, "config", "--format", "json")
	configCmd.Dir = composeDir
	if configOutput, err := configCmd.Output(); err == nil {
		var config map[string]interface{}
		if json.Unmarshal(configOutput, &config) == nil {
			backupData["compose_config"] = config

			// Backup named volumes
			if volumes, ok := config["volumes"].(map[string]interface{}); ok {
				volumeBackups := make(map[string]string)
				for volumeName := range volumes {
					// Create tar archive of volume
					tarCmd := exec.CommandContext(ctx, "docker", "run", "--rm",
						"-v", volumeName+":/data:ro",
						"alpine", "tar", "-czf", "-", "-C", "/data", ".")
					if volumeData, err := tarCmd.Output(); err == nil {
						volumeBackups[volumeName] = base64.StdEncoding.EncodeToString(volumeData)
					}
				}
				if len(volumeBackups) > 0 {
					backupData["volume_backups"] = volumeBackups
				}
			}
		}
	}

	return json.Marshal(backupData)
}

// =============================================================================
// Proxmox Backup Functions
// =============================================================================

// collectProxmoxVMBackup creates a backup of a Proxmox VM using the existing Proxmox integration.
func (h *Handler) collectProxmoxVMBackup(ctx context.Context, req createBackupRequest) ([]byte, error) {
	if !proxmox.IsProxmoxHost() {
		return nil, fmt.Errorf("this system is not a Proxmox host")
	}

	if req.VMID == 0 {
		return nil, fmt.Errorf("vmid is required for proxmox_vm backup")
	}

	backupData := make(map[string]interface{})
	backupData["backup_type"] = "proxmox_vm"
	backupData["vmid"] = req.VMID
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = h.cfg.GetUUID()

	// Create Proxmox client with config directory
	configDir := filepath.Dir(h.paths.ConfigFile)
	client, err := proxmox.NewClient(ctx, configDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create Proxmox client: %w", err)
	}
	defer client.Close()

	// Determine backup mode
	mode := proxmox.BackupModeSnapshot
	if req.BackupMode != "" {
		switch req.BackupMode {
		case "stop":
			mode = proxmox.BackupModeStop
		case "suspend":
			mode = proxmox.BackupModeSuspend
		}
	}

	// Determine compression
	compress := proxmox.CompressionZSTD

	// Create backup using the existing Proxmox integration
	backupReq := proxmox.BackupRequest{
		VMIDs:    []uint64{req.VMID},
		Storage:  req.ProxmoxStorage,
		Mode:     mode,
		Compress: compress,
		Notes:    fmt.Sprintf("SlimRMM backup %s", req.BackupID),
	}

	results := client.CreateBackup(ctx, backupReq)
	if len(results) == 0 {
		return nil, fmt.Errorf("no backup result returned")
	}

	result := results[0]
	if !result.Success {
		return nil, fmt.Errorf("backup failed: %s", result.Error)
	}

	backupData["backup_result"] = result
	backupData["task_id"] = result.TaskID
	backupData["storage"] = result.Storage
	backupData["backup_file"] = result.BackupFile

	return json.Marshal(backupData)
}

// collectProxmoxLXCBackup creates a backup of a Proxmox LXC container.
func (h *Handler) collectProxmoxLXCBackup(ctx context.Context, req createBackupRequest) ([]byte, error) {
	if !proxmox.IsProxmoxHost() {
		return nil, fmt.Errorf("this system is not a Proxmox host")
	}

	if req.VMID == 0 {
		return nil, fmt.Errorf("vmid is required for proxmox_lxc backup")
	}

	backupData := make(map[string]interface{})
	backupData["backup_type"] = "proxmox_lxc"
	backupData["vmid"] = req.VMID
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = h.cfg.GetUUID()

	configDir := filepath.Dir(h.paths.ConfigFile)
	client, err := proxmox.NewClient(ctx, configDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create Proxmox client: %w", err)
	}
	defer client.Close()

	// Determine backup mode
	mode := proxmox.BackupModeSnapshot
	if req.BackupMode != "" {
		switch req.BackupMode {
		case "stop":
			mode = proxmox.BackupModeStop
		case "suspend":
			mode = proxmox.BackupModeSuspend
		}
	}

	// Create backup
	backupReq := proxmox.BackupRequest{
		VMIDs:    []uint64{req.VMID},
		Storage:  req.ProxmoxStorage,
		Mode:     mode,
		Compress: proxmox.CompressionZSTD,
		Notes:    fmt.Sprintf("SlimRMM LXC backup %s", req.BackupID),
	}

	results := client.CreateBackup(ctx, backupReq)
	if len(results) == 0 {
		return nil, fmt.Errorf("no backup result returned")
	}

	result := results[0]
	if !result.Success {
		return nil, fmt.Errorf("backup failed: %s", result.Error)
	}

	backupData["backup_result"] = result
	backupData["task_id"] = result.TaskID
	backupData["storage"] = result.Storage
	backupData["backup_file"] = result.BackupFile

	return json.Marshal(backupData)
}

// collectProxmoxConfigBackup creates a backup of Proxmox configuration files.
func (h *Handler) collectProxmoxConfigBackup(ctx context.Context, req createBackupRequest) ([]byte, error) {
	if !proxmox.IsProxmoxHost() {
		return nil, fmt.Errorf("this system is not a Proxmox host")
	}

	backupData := make(map[string]interface{})
	backupData["backup_type"] = "proxmox_config"
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = h.cfg.GetUUID()

	configFiles := make(map[string]string)

	// Key Proxmox configuration directories and files
	configPaths := []string{
		"/etc/pve/storage.cfg",
		"/etc/pve/datacenter.cfg",
		"/etc/pve/user.cfg",
		"/etc/pve/corosync.conf",
		"/etc/pve/ha/groups.cfg",
		"/etc/pve/ha/resources.cfg",
		"/etc/pve/firewall/cluster.fw",
	}

	// Read config files
	for _, path := range configPaths {
		if data, err := os.ReadFile(path); err == nil {
			configFiles[path] = base64.StdEncoding.EncodeToString(data)
		}
	}

	// Read VM/CT config files from /etc/pve/qemu-server and /etc/pve/lxc
	for _, dir := range []string{"/etc/pve/qemu-server", "/etc/pve/lxc"} {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".conf") {
					path := filepath.Join(dir, entry.Name())
					if data, err := os.ReadFile(path); err == nil {
						configFiles[path] = base64.StdEncoding.EncodeToString(data)
					}
				}
			}
		}
	}

	backupData["config_files"] = configFiles

	// Get cluster info
	configDir := filepath.Dir(h.paths.ConfigFile)
	client, err := proxmox.NewClient(ctx, configDir)
	if err == nil {
		defer client.Close()
		if resources, err := client.GetResources(ctx); err == nil {
			backupData["resources"] = resources
		}
		if haStatus := client.GetHAStatus(ctx); haStatus.Success {
			backupData["ha_status"] = haStatus
		}
	}

	return json.Marshal(backupData)
}

// =============================================================================
// Hyper-V Backup Functions (Windows only)
// =============================================================================

// collectHyperVVMBackup creates a backup of a Hyper-V VM.
func (h *Handler) collectHyperVVMBackup(ctx context.Context, req createBackupRequest) ([]byte, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("hyper-v backups are only supported on Windows")
	}

	if req.VMName == "" {
		return nil, fmt.Errorf("vm_name is required for hyperv_vm backup")
	}

	backupData := make(map[string]interface{})
	backupData["backup_type"] = "hyperv_vm"
	backupData["vm_name"] = req.VMName
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = h.cfg.GetUUID()

	// Validate VM name to prevent command injection
	if !isValidVMName(req.VMName) {
		return nil, fmt.Errorf("invalid VM name: contains disallowed characters")
	}
	escapedVMName := escapePowerShellString(req.VMName)

	// Get VM info via PowerShell
	getVMCmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`Get-VM -Name '%s' | ConvertTo-Json -Depth 5`, escapedVMName))
	if vmInfo, err := getVMCmd.Output(); err == nil {
		var vmData interface{}
		if json.Unmarshal(vmInfo, &vmData) == nil {
			backupData["vm_info"] = vmData
		}
	} else {
		return nil, fmt.Errorf("failed to get VM info: %w", err)
	}

	// Get VM snapshots/checkpoints
	getSnapshotsCmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`Get-VMSnapshot -VMName '%s' | ConvertTo-Json -Depth 3`, escapedVMName))
	if snapshotsInfo, err := getSnapshotsCmd.Output(); err == nil {
		var snapshots interface{}
		if json.Unmarshal(snapshotsInfo, &snapshots) == nil {
			backupData["snapshots"] = snapshots
		}
	}

	// Create export directory
	exportDir := filepath.Join(os.TempDir(), "hyperv_export_"+req.BackupID)
	if err := os.MkdirAll(exportDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create export directory: %w", err)
	}
	defer os.RemoveAll(exportDir)

	// Export VM using PowerShell (escapedVMName already validated above)
	escapedExportDir := escapePowerShellString(exportDir)
	exportScript := fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		$vm = Get-VM -Name '%s'
		if ($vm.State -eq 'Running') {
			if (%t) {
				# Use VSS for consistent backup without stopping VM
				Export-VM -Name '%s' -Path '%s' -CaptureLiveState $true
			} else {
				# Standard export
				Export-VM -Name '%s' -Path '%s'
			}
		} else {
			Export-VM -Name '%s' -Path '%s'
		}
	`, escapedVMName, req.UseVSS, escapedVMName, escapedExportDir, escapedVMName, escapedExportDir, escapedVMName, escapedExportDir)

	exportCmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", exportScript)
	if output, err := exportCmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to export VM: %w - %s", err, string(output))
	}

	// Create tar archive of export
	vmExportPath := filepath.Join(exportDir, req.VMName)
	var exportData bytes.Buffer
	if err := createTarArchive(ctx, vmExportPath, &exportData); err != nil {
		return nil, fmt.Errorf("failed to archive export: %w", err)
	}

	backupData["export_data"] = base64.StdEncoding.EncodeToString(exportData.Bytes())
	backupData["export_size"] = exportData.Len()

	return json.Marshal(backupData)
}

// collectHyperVCheckpointBackup creates a backup of a Hyper-V checkpoint.
func (h *Handler) collectHyperVCheckpointBackup(ctx context.Context, req createBackupRequest) ([]byte, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("hyper-v backups are only supported on Windows")
	}

	if req.VMName == "" {
		return nil, fmt.Errorf("vm_name is required for hyperv_checkpoint backup")
	}

	// Validate VM name to prevent command injection
	if !isValidVMName(req.VMName) {
		return nil, fmt.Errorf("invalid VM name: contains disallowed characters")
	}
	escapedVMName := escapePowerShellString(req.VMName)

	backupData := make(map[string]interface{})
	backupData["backup_type"] = "hyperv_checkpoint"
	backupData["vm_name"] = req.VMName
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = h.cfg.GetUUID()

	checkpointName := req.CheckpointName
	if checkpointName == "" {
		checkpointName = fmt.Sprintf("SlimRMM_Backup_%s", time.Now().Format("20060102_150405"))
	}
	// Validate checkpoint name
	if !isValidVMName(checkpointName) {
		return nil, fmt.Errorf("invalid checkpoint name: contains disallowed characters")
	}
	escapedCheckpointName := escapePowerShellString(checkpointName)
	backupData["checkpoint_name"] = checkpointName

	// Create checkpoint via PowerShell
	createCheckpointScript := fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		Checkpoint-VM -Name '%s' -SnapshotName '%s'
		Get-VMSnapshot -VMName '%s' -Name '%s' | ConvertTo-Json -Depth 3
	`, escapedVMName, escapedCheckpointName, escapedVMName, escapedCheckpointName)

	checkpointCmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", createCheckpointScript)
	if output, err := checkpointCmd.Output(); err == nil {
		var checkpointInfo interface{}
		if json.Unmarshal(output, &checkpointInfo) == nil {
			backupData["checkpoint_info"] = checkpointInfo
		}
	} else {
		return nil, fmt.Errorf("failed to create checkpoint: %w", err)
	}

	return json.Marshal(backupData)
}

// collectHyperVConfigBackup creates a backup of Hyper-V configuration.
func (h *Handler) collectHyperVConfigBackup(ctx context.Context, req createBackupRequest) ([]byte, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("hyper-v backups are only supported on Windows")
	}

	backupData := make(map[string]interface{})
	backupData["backup_type"] = "hyperv_config"
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = h.cfg.GetUUID()

	// Get all VMs configuration
	getVMsCmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		`Get-VM | Select-Object Name, State, Generation, ProcessorCount, MemoryStartup, MemoryMinimum, MemoryMaximum, Path | ConvertTo-Json -Depth 3`)
	if vmsInfo, err := getVMsCmd.Output(); err == nil {
		var vms interface{}
		if json.Unmarshal(vmsInfo, &vms) == nil {
			backupData["virtual_machines"] = vms
		}
	}

	// Get virtual switches
	getSwitchesCmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		`Get-VMSwitch | ConvertTo-Json -Depth 3`)
	if switchesInfo, err := getSwitchesCmd.Output(); err == nil {
		var switches interface{}
		if json.Unmarshal(switchesInfo, &switches) == nil {
			backupData["virtual_switches"] = switches
		}
	}

	// Get Hyper-V host settings
	getHostCmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
		`Get-VMHost | ConvertTo-Json -Depth 3`)
	if hostInfo, err := getHostCmd.Output(); err == nil {
		var host interface{}
		if json.Unmarshal(hostInfo, &host) == nil {
			backupData["host_settings"] = host
		}
	}

	// Get storage paths for each VM
	if req.VMName != "" {
		// Validate VM name to prevent command injection
		if !isValidVMName(req.VMName) {
			return nil, fmt.Errorf("invalid VM name: contains disallowed characters")
		}
		escapedVMName := escapePowerShellString(req.VMName)
		getStorageCmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
			fmt.Sprintf(`Get-VMHardDiskDrive -VMName '%s' | ConvertTo-Json -Depth 3`, escapedVMName))
		if storageInfo, err := getStorageCmd.Output(); err == nil {
			var storage interface{}
			if json.Unmarshal(storageInfo, &storage) == nil {
				backupData["vm_storage"] = storage
			}
		}
	}

	return json.Marshal(backupData)
}

// createTarArchive creates a tar archive of a directory.
// Note: srcDir and tempZip are internally generated paths, not user input,
// but we still escape them for defense in depth.
func createTarArchive(ctx context.Context, srcDir string, buf *bytes.Buffer) error {
	// On Windows, use PowerShell Compress-Archive
	if runtime.GOOS == "windows" {
		tempZip := filepath.Join(os.TempDir(), "backup_"+time.Now().Format("20060102150405")+".zip")
		defer os.Remove(tempZip)

		// Escape paths for PowerShell (defense in depth)
		escapedSrcDir := escapePowerShellString(srcDir)
		escapedTempZip := escapePowerShellString(tempZip)
		compressCmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command",
			fmt.Sprintf(`Compress-Archive -Path '%s\*' -DestinationPath '%s' -Force`, escapedSrcDir, escapedTempZip))
		if err := compressCmd.Run(); err != nil {
			return err
		}

		zipData, err := os.ReadFile(tempZip)
		if err != nil {
			return err
		}
		buf.Write(zipData)
		return nil
	}

	// On Unix, use tar with context for timeout support
	tarCmd := exec.CommandContext(ctx, "tar", "-czf", "-", "-C", srcDir, ".")
	tarCmd.Stdout = buf
	return tarCmd.Run()
}

// =============================================================================
// Docker Restore Functions
// =============================================================================

// restoreDockerContainer restores a Docker container from backup.
func (h *Handler) restoreDockerContainer(ctx context.Context, req restoreBackupRequest, data []byte) error {
	if !actions.IsDockerAvailable() {
		return fmt.Errorf(i18n.MsgDockerNotAvailable)
	}

	var backupData map[string]interface{}
	if err := json.Unmarshal(data, &backupData); err != nil {
		return fmt.Errorf("failed to parse backup data: %w", err)
	}

	// Get exported container data
	exportDataB64, ok := backupData["export_data"].(string)
	if !ok {
		return fmt.Errorf("no export_data found in backup")
	}

	exportData, err := base64.StdEncoding.DecodeString(exportDataB64)
	if err != nil {
		return fmt.Errorf("failed to decode export data: %w", err)
	}

	// Create temporary tar file
	tmpFile, err := os.CreateTemp("", "container_restore_*.tar")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(exportData); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write export data: %w", err)
	}
	tmpFile.Close()

	// Import as new image
	imageName := fmt.Sprintf("restored_%s:%s", req.ContainerName, time.Now().Format("20060102150405"))
	if req.ContainerName == "" {
		imageName = fmt.Sprintf("restored_container:%s", time.Now().Format("20060102150405"))
	}

	importCmd := exec.CommandContext(ctx, "docker", "import", tmpFile.Name(), imageName)
	if output, err := importCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to import container: %w - %s", err, string(output))
	}

	h.logger.Info("container restored as image", "image", imageName)

	// If container name specified, create container from image
	if req.ContainerName != "" {
		createCmd := exec.CommandContext(ctx, "docker", "create", "--name", req.ContainerName, imageName)
		if output, err := createCmd.CombinedOutput(); err != nil {
			h.logger.Warn("failed to create container from restored image", "error", err, "output", string(output))
		} else {
			h.logger.Info("container created from restored image", "name", req.ContainerName)
		}
	}

	return nil
}

// restoreDockerVolume restores a Docker volume from backup.
func (h *Handler) restoreDockerVolume(ctx context.Context, req restoreBackupRequest, data []byte) error {
	if !actions.IsDockerAvailable() {
		return fmt.Errorf(i18n.MsgDockerNotAvailable)
	}

	var backupData map[string]interface{}
	if err := json.Unmarshal(data, &backupData); err != nil {
		return fmt.Errorf("failed to parse backup data: %w", err)
	}

	// Get volume data
	volumeDataB64, ok := backupData["volume_data"].(string)
	if !ok {
		return fmt.Errorf("no volume_data found in backup")
	}

	volumeData, err := base64.StdEncoding.DecodeString(volumeDataB64)
	if err != nil {
		return fmt.Errorf("failed to decode volume data: %w", err)
	}

	// Determine volume name
	volumeName := req.VolumeName
	if volumeName == "" {
		if name, ok := backupData["volume_name"].(string); ok {
			volumeName = name + "_restored"
		} else {
			volumeName = fmt.Sprintf("restored_volume_%s", time.Now().Format("20060102150405"))
		}
	}

	// Create volume if it doesn't exist
	createCmd := exec.CommandContext(ctx, "docker", "volume", "create", volumeName)
	if output, err := createCmd.CombinedOutput(); err != nil {
		h.logger.Warn("volume may already exist", "error", err, "output", string(output))
	}

	// Restore volume data using temporary container
	restoreCmd := exec.CommandContext(ctx, "docker", "run", "--rm",
		"-v", volumeName+":/data",
		"-i", "alpine", "tar", "-xzf", "-", "-C", "/data")
	restoreCmd.Stdin = bytes.NewReader(volumeData)

	if output, err := restoreCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to restore volume data: %w - %s", err, string(output))
	}

	h.logger.Info("volume restored", "volume", volumeName)
	return nil
}

// restoreDockerImage restores a Docker image from backup.
func (h *Handler) restoreDockerImage(ctx context.Context, req restoreBackupRequest, data []byte) error {
	if !actions.IsDockerAvailable() {
		return fmt.Errorf(i18n.MsgDockerNotAvailable)
	}

	var backupData map[string]interface{}
	if err := json.Unmarshal(data, &backupData); err != nil {
		return fmt.Errorf("failed to parse backup data: %w", err)
	}

	// Get image data
	imageDataB64, ok := backupData["image_data"].(string)
	if !ok {
		return fmt.Errorf("no image_data found in backup")
	}

	imageData, err := base64.StdEncoding.DecodeString(imageDataB64)
	if err != nil {
		return fmt.Errorf("failed to decode image data: %w", err)
	}

	// Load image using docker load
	loadCmd := exec.CommandContext(ctx, "docker", "load")
	loadCmd.Stdin = bytes.NewReader(imageData)

	if output, err := loadCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to load image: %w - %s", err, string(output))
	}

	// Optionally retag
	if req.ImageName != "" {
		if origName, ok := backupData["image_name"].(string); ok && origName != "" {
			tagCmd := exec.CommandContext(ctx, "docker", "tag", origName, req.ImageName)
			if output, err := tagCmd.CombinedOutput(); err != nil {
				h.logger.Warn("failed to retag image", "error", err, "output", string(output))
			} else {
				h.logger.Info("image retagged", "from", origName, "to", req.ImageName)
			}
		}
	}

	h.logger.Info("image restored")
	return nil
}

// restoreDockerCompose restores a Docker Compose project from backup.
func (h *Handler) restoreDockerCompose(ctx context.Context, req restoreBackupRequest, data []byte) error {
	if !actions.IsDockerAvailable() {
		return fmt.Errorf(i18n.MsgDockerNotAvailable)
	}

	var backupData map[string]interface{}
	if err := json.Unmarshal(data, &backupData); err != nil {
		return fmt.Errorf("failed to parse backup data: %w", err)
	}

	// Determine compose path
	composePath := req.ComposePath
	if composePath == "" {
		if path, ok := backupData["compose_path"].(string); ok {
			composePath = path
		} else {
			return fmt.Errorf("compose_path is required for docker_compose restore")
		}
	}

	// Ensure directory exists
	composeDir := filepath.Dir(composePath)
	if err := os.MkdirAll(composeDir, 0755); err != nil {
		return fmt.Errorf("failed to create compose directory: %w", err)
	}

	// Restore compose file
	if composeFileB64, ok := backupData["compose_file"].(string); ok {
		composeFile, err := base64.StdEncoding.DecodeString(composeFileB64)
		if err != nil {
			return fmt.Errorf("failed to decode compose file: %w", err)
		}
		if err := os.WriteFile(composePath, composeFile, 0600); err != nil {
			return fmt.Errorf("failed to write compose file: %w", err)
		}
		h.logger.Info("compose file restored", "path", composePath)
	}

	// Restore .env file if present
	if envFileB64, ok := backupData["env_file"].(string); ok {
		envFile, err := base64.StdEncoding.DecodeString(envFileB64)
		if err == nil {
			envPath := filepath.Join(composeDir, ".env")
			if err := os.WriteFile(envPath, envFile, 0600); err != nil {
				h.logger.Warn("failed to write env file", "error", err)
			}
		}
	}

	// Restore volumes if requested
	if req.RestoreVolumes {
		if volumeBackups, ok := backupData["volume_backups"].(map[string]interface{}); ok {
			for volumeName, volumeDataB64 := range volumeBackups {
				if dataStr, ok := volumeDataB64.(string); ok {
					volumeData, err := base64.StdEncoding.DecodeString(dataStr)
					if err != nil {
						h.logger.Warn("failed to decode volume data", "volume", volumeName, "error", err)
						continue
					}

					// Create volume
					createCmd := exec.CommandContext(ctx, "docker", "volume", "create", volumeName)
					createCmd.Run()

					// Restore volume data
					restoreCmd := exec.CommandContext(ctx, "docker", "run", "--rm",
						"-v", volumeName+":/data",
						"-i", "alpine", "tar", "-xzf", "-", "-C", "/data")
					restoreCmd.Stdin = bytes.NewReader(volumeData)
					if output, err := restoreCmd.CombinedOutput(); err != nil {
						h.logger.Warn("failed to restore volume", "volume", volumeName, "error", err, "output", string(output))
					} else {
						h.logger.Info("volume restored", "volume", volumeName)
					}
				}
			}
		}
	}

	return nil
}

// =============================================================================
// Proxmox Restore Functions
// =============================================================================

// restoreProxmoxConfig restores Proxmox configuration files.
func (h *Handler) restoreProxmoxConfig(ctx context.Context, req restoreBackupRequest, data []byte) error {
	if !proxmox.IsProxmoxHost() {
		return fmt.Errorf("this system is not a Proxmox host")
	}

	var backupData map[string]interface{}
	if err := json.Unmarshal(data, &backupData); err != nil {
		return fmt.Errorf("failed to parse backup data: %w", err)
	}

	configFiles, ok := backupData["config_files"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("no config_files found in backup")
	}

	for path, contentB64 := range configFiles {
		contentStr, ok := contentB64.(string)
		if !ok {
			continue
		}

		content, err := base64.StdEncoding.DecodeString(contentStr)
		if err != nil {
			h.logger.Warn("failed to decode config file", "path", path, "error", err)
			continue
		}

		// Create backup of existing file
		if _, err := os.Stat(path); err == nil {
			backupPath := path + ".backup." + time.Now().Format("20060102150405")
			if existingData, err := os.ReadFile(path); err == nil {
				if err := os.WriteFile(backupPath, existingData, 0600); err != nil {
					h.logger.Warn("failed to backup existing file", "path", backupPath, "error", err)
				} else {
					h.logger.Info("existing config backed up", "path", backupPath)
				}
			}
		}

		// Ensure directory exists
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			h.logger.Warn("failed to create directory", "path", dir, "error", err)
			continue
		}

		// Write restored config
		if err := os.WriteFile(path, content, 0600); err != nil {
			h.logger.Warn("failed to write config file", "path", path, "error", err)
			continue
		}

		h.logger.Info("config file restored", "path", path)
	}

	return nil
}

// =============================================================================
// Hyper-V Restore Functions
// =============================================================================

// restoreHyperVVM restores a Hyper-V VM from backup.
func (h *Handler) restoreHyperVVM(ctx context.Context, req restoreBackupRequest, data []byte) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("hyper-v restores are only supported on Windows")
	}

	var backupData map[string]interface{}
	if err := json.Unmarshal(data, &backupData); err != nil {
		return fmt.Errorf("failed to parse backup data: %w", err)
	}

	// Get export data
	exportDataB64, ok := backupData["export_data"].(string)
	if !ok {
		return fmt.Errorf("no export_data found in backup")
	}

	exportData, err := base64.StdEncoding.DecodeString(exportDataB64)
	if err != nil {
		return fmt.Errorf("failed to decode export data: %w", err)
	}

	// Determine target path
	targetPath := req.TargetPath
	if targetPath == "" {
		targetPath = filepath.Join(os.TempDir(), "hyperv_restore_"+time.Now().Format("20060102150405"))
	}

	// Create target directory
	if err := os.MkdirAll(targetPath, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	// Extract the zip/tar archive
	archivePath := filepath.Join(os.TempDir(), "vm_restore_"+time.Now().Format("20060102150405")+".zip")
	if err := os.WriteFile(archivePath, exportData, 0600); err != nil {
		return fmt.Errorf("failed to write archive: %w", err)
	}
	defer os.Remove(archivePath)

	// Extract using PowerShell (paths are internally generated, escape for defense in depth)
	escapedArchivePath := escapePowerShellString(archivePath)
	escapedTargetPath := escapePowerShellString(targetPath)
	extractScript := fmt.Sprintf(`
		$ErrorActionPreference = 'Stop'
		Expand-Archive -Path '%s' -DestinationPath '%s' -Force
	`, escapedArchivePath, escapedTargetPath)

	extractCmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", extractScript)
	if output, err := extractCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to extract archive: %w - %s", err, string(output))
	}

	h.logger.Info("VM export extracted", "path", targetPath)

	// Import VM if requested
	if req.RegisterVM {
		vmName := req.VMName
		if vmName == "" {
			if name, ok := backupData["vm_name"].(string); ok {
				vmName = name
			}
		}

		// Find the VM configuration file
		vmcxPattern := filepath.Join(targetPath, "**", "*.vmcx")
		matches, err := filepath.Glob(vmcxPattern)
		if err != nil {
			h.logger.Warn("failed to glob for vmcx files", "error", err)
		}

		if len(matches) > 0 {
			// Escape the matched path for PowerShell
			escapedVMCXPath := escapePowerShellString(matches[0])
			importScript := fmt.Sprintf(`
				$ErrorActionPreference = 'Stop'
				$vmPath = '%s'
				if (%t) {
					# Import with new ID
					Import-VM -Path $vmPath -GenerateNewId -Copy
				} else {
					# Import preserving ID
					Import-VM -Path $vmPath
				}
			`, escapedVMCXPath, req.GenerateNewID)

			importCmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", importScript)
			if output, err := importCmd.CombinedOutput(); err != nil {
				return fmt.Errorf("failed to import VM: %w - %s", err, string(output))
			}

			h.logger.Info("VM imported", "name", vmName)
		} else {
			h.logger.Warn("no VMCX file found in export, manual import required")
		}
	}

	return nil
}

// =============================================================================
// Files and Folders Backup Functions
// =============================================================================

// backupPathsRequest is the request for backup_paths action.
type backupPathsRequest struct {
	Paths           []string `json:"paths"`
	ExcludePatterns []string `json:"exclude_patterns,omitempty"`
	RequestID       string   `json:"request_id"`
}

// backupPathsResponse is the response for backup_paths action.
type backupPathsResponse struct {
	RequestID  string `json:"request_id"`
	TotalFiles int    `json:"total_files"`
	TotalSize  int64  `json:"total_size"`
	Data       string `json:"data"` // Base64 encoded tar.gz
	Hash       string `json:"hash"` // SHA256
}

// handleBackupPaths handles the backup_paths action for creating path-based backups.
func (h *Handler) handleBackupPaths(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req backupPathsRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.MsgInvalidRequest, err)
	}

	if len(req.Paths) == 0 {
		return nil, fmt.Errorf("at least one path is required")
	}

	h.logger.Info("creating path-based backup",
		"request_id", req.RequestID,
		"paths", len(req.Paths),
		"exclude_patterns", len(req.ExcludePatterns),
	)

	// Audit log path access for each path being backed up
	for _, path := range req.Paths {
		audit.GetLogger().LogBackupPathAccess(ctx, path, "backup_read", true)
	}

	// Create tar.gz archive
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	tarWriter := newTarWriter(gzWriter)

	var totalFiles int
	var totalSize int64

	for _, path := range req.Paths {
		info, err := os.Stat(path)
		if err != nil {
			h.logger.Warn("skipping inaccessible path", "path", path, "error", err)
			continue
		}

		if info.IsDir() {
			// Walk directory
			err = filepath.Walk(path, func(filePath string, fi os.FileInfo, err error) error {
				if err != nil {
					return nil // Skip errors
				}

				// Check exclude patterns
				if shouldExclude(filePath, fi.Name(), req.ExcludePatterns) {
					if fi.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}

				if fi.IsDir() {
					return nil // Skip directories (they're created implicitly)
				}

				// Add file to archive
				if err := addFileToTar(tarWriter, filePath, path); err != nil {
					h.logger.Warn("failed to add file to archive", "file", filePath, "error", err)
					return nil
				}

				totalFiles++
				totalSize += fi.Size()
				return nil
			})
			if err != nil {
				h.logger.Warn("error walking directory", "path", path, "error", err)
			}
		} else {
			// Single file
			if !shouldExclude(path, info.Name(), req.ExcludePatterns) {
				if err := addFileToTar(tarWriter, path, filepath.Dir(path)); err != nil {
					h.logger.Warn("failed to add file to archive", "file", path, "error", err)
				} else {
					totalFiles++
					totalSize += info.Size()
				}
			}
		}
	}

	// Close writers
	if err := tarWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close tar writer: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	// Calculate hash
	hash := sha256.Sum256(buf.Bytes())
	hashHex := hex.EncodeToString(hash[:])

	// Encode as base64
	dataBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	h.logger.Info("path-based backup created",
		"request_id", req.RequestID,
		"total_files", totalFiles,
		"total_size", totalSize,
		"compressed_size", buf.Len(),
	)

	return backupPathsResponse{
		RequestID:  req.RequestID,
		TotalFiles: totalFiles,
		TotalSize:  totalSize,
		Data:       dataBase64,
		Hash:       hashHex,
	}, nil
}

// collectFilesAndFoldersBackup creates a backup of specified files and folders.
func (h *Handler) collectFilesAndFoldersBackup(ctx context.Context, req createBackupRequest) ([]byte, error) {
	if len(req.IncludePaths) == 0 {
		return nil, fmt.Errorf("include_paths is required for files_and_folders backup")
	}

	backupData := make(map[string]interface{})
	backupData["backup_type"] = "files_and_folders"
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = h.cfg.GetUUID()
	backupData["include_paths"] = req.IncludePaths
	backupData["exclude_patterns"] = req.ExcludePatterns

	// Create tar.gz archive of the paths
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	tarWriter := newTarWriter(gzWriter)

	var totalFiles int
	var totalSize int64
	fileList := make([]map[string]interface{}, 0)

	for _, path := range req.IncludePaths {
		info, err := os.Stat(path)
		if err != nil {
			h.logger.Warn("skipping inaccessible path", "path", path, "error", err)
			continue
		}

		if info.IsDir() {
			err = filepath.Walk(path, func(filePath string, fi os.FileInfo, err error) error {
				if err != nil {
					return nil
				}

				if shouldExclude(filePath, fi.Name(), req.ExcludePatterns) {
					if fi.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}

				if fi.IsDir() {
					return nil
				}

				if err := addFileToTar(tarWriter, filePath, path); err != nil {
					h.logger.Warn("failed to add file to archive", "file", filePath, "error", err)
					return nil
				}

				relPath, _ := filepath.Rel(path, filePath)
				fileList = append(fileList, map[string]interface{}{
					"path":     relPath,
					"size":     fi.Size(),
					"modified": fi.ModTime().Format(time.RFC3339),
				})

				totalFiles++
				totalSize += fi.Size()
				return nil
			})
			if err != nil {
				h.logger.Warn("error walking directory", "path", path, "error", err)
			}
		} else {
			if !shouldExclude(path, info.Name(), req.ExcludePatterns) {
				if err := addFileToTar(tarWriter, path, filepath.Dir(path)); err != nil {
					h.logger.Warn("failed to add file to archive", "file", path, "error", err)
				} else {
					fileList = append(fileList, map[string]interface{}{
						"path":     filepath.Base(path),
						"size":     info.Size(),
						"modified": info.ModTime().Format(time.RFC3339),
					})
					totalFiles++
					totalSize += info.Size()
				}
			}
		}
	}

	// Properly close writers to ensure all data is flushed
	if err := tarWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close tar writer: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	backupData["archive_data"] = base64.StdEncoding.EncodeToString(buf.Bytes())
	backupData["archive_size"] = buf.Len()
	backupData["total_files"] = totalFiles
	backupData["total_size"] = totalSize
	backupData["files"] = fileList

	return json.Marshal(backupData)
}

// shouldExclude checks if a path should be excluded based on patterns.
func shouldExclude(path, name string, patterns []string) bool {
	for _, pattern := range patterns {
		// Check filename match
		if matched, _ := filepath.Match(pattern, name); matched {
			return true
		}
		// Check full path match
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
		// Check if pattern is contained in path (for directory names like node_modules)
		if strings.Contains(path, pattern) {
			return true
		}
	}
	return false
}

// tarWriter wraps archive/tar.Writer
type tarWriterWrapper struct {
	*tar.Writer
}

func newTarWriter(w io.Writer) *tarWriterWrapper {
	return &tarWriterWrapper{tar.NewWriter(w)}
}

// addFileToTar adds a file to the tar archive.
func addFileToTar(tw *tarWriterWrapper, filePath, basePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	// Create header
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}

	// Use relative path in archive
	relPath, err := filepath.Rel(basePath, filePath)
	if err != nil {
		relPath = filepath.Base(filePath)
	}
	header.Name = filepath.ToSlash(relPath)

	// Write header
	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	// Write content
	_, err = io.Copy(tw.Writer, file)
	return err
}

// =============================================================================
// Files and Folders Restore Functions
// =============================================================================

// restoreFilesAndFolders restores files from a files_and_folders backup.
// Supports selective restore of specific paths.
func (h *Handler) restoreFilesAndFolders(ctx context.Context, req restoreBackupRequest, data []byte) error {
	// Parse the backup data
	var backupData map[string]interface{}
	if err := json.Unmarshal(data, &backupData); err != nil {
		return fmt.Errorf("failed to parse backup data: %w", err)
	}

	// Get the archive data
	archiveDataB64, ok := backupData["archive_data"].(string)
	if !ok {
		return fmt.Errorf("no archive_data found in backup")
	}

	archiveData, err := base64.StdEncoding.DecodeString(archiveDataB64)
	if err != nil {
		return fmt.Errorf("failed to decode archive data: %w", err)
	}

	// Determine target directory
	targetDir := req.RestoreTarget
	if targetDir == "" {
		// Default to temp directory with timestamp
		targetDir = filepath.Join(os.TempDir(), "restore_"+time.Now().Format("20060102150405"))
	}

	// Create target directory
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	// Build a set of paths to restore (if selective restore)
	restorePathSet := make(map[string]bool)
	selectiveRestore := len(req.RestorePaths) > 0
	for _, p := range req.RestorePaths {
		// Normalize path separators
		restorePathSet[filepath.ToSlash(p)] = true
	}

	// Open gzip reader
	gzReader, err := gzip.NewReader(bytes.NewReader(archiveData))
	if err != nil {
		return fmt.Errorf("failed to open gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Open tar reader
	tarReader := tar.NewReader(gzReader)

	var restoredFiles int
	var restoredSize int64

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Check if this file should be restored (selective restore)
		if selectiveRestore {
			shouldRestore := false
			normalizedName := filepath.ToSlash(header.Name)

			// Check if file matches any of the restore paths
			for restorePath := range restorePathSet {
				// Exact match
				if normalizedName == restorePath {
					shouldRestore = true
					break
				}
				// File is under a directory that should be restored
				if strings.HasPrefix(normalizedName, restorePath+"/") {
					shouldRestore = true
					break
				}
				// Restore path is a file under this directory
				if strings.HasPrefix(restorePath, normalizedName+"/") {
					shouldRestore = true
					break
				}
			}

			if !shouldRestore {
				continue
			}
		}

		// Determine target path
		var targetPath string
		if req.PreserveStructure {
			targetPath = filepath.Join(targetDir, header.Name)
		} else {
			// Flatten structure - use just the filename
			targetPath = filepath.Join(targetDir, filepath.Base(header.Name))
		}

		// Validate path is within target directory (prevent path traversal attacks)
		if !isPathSafe(targetDir, targetPath) {
			h.logger.Warn("skipping file with unsafe path", "path", header.Name, "target", targetPath)
			continue
		}

		// Create parent directories
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			h.logger.Warn("failed to create directory", "path", filepath.Dir(targetPath), "error", err)
			continue
		}

		// Check if file exists and overwrite setting
		if _, err := os.Stat(targetPath); err == nil {
			if !req.OverwriteFiles {
				h.logger.Info("skipping existing file", "path", targetPath)
				continue
			}
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil {
				h.logger.Warn("failed to create directory", "path", targetPath, "error", err)
			}

		case tar.TypeReg:
			// Create file
			file, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				h.logger.Warn("failed to create file", "path", targetPath, "error", err)
				continue
			}

			// Copy content
			written, err := io.Copy(file, tarReader)
			file.Close()
			if err != nil {
				h.logger.Warn("failed to write file", "path", targetPath, "error", err)
				continue
			}

			restoredFiles++
			restoredSize += written

			// Set modification time
			if err := os.Chtimes(targetPath, header.AccessTime, header.ModTime); err != nil {
				h.logger.Debug("failed to set file times", "path", targetPath, "error", err)
			}

		case tar.TypeSymlink:
			// Validate symlink target doesn't escape the restore directory
			if !isSymlinkSafe(targetDir, targetPath, header.Linkname) {
				h.logger.Warn("skipping symlink with unsafe target", "path", targetPath, "target", header.Linkname)
				continue
			}
			if err := os.Symlink(header.Linkname, targetPath); err != nil {
				h.logger.Warn("failed to create symlink", "path", targetPath, "error", err)
				continue
			}
			// Post-creation verification: read back symlink and verify target
			// This mitigates TOCTOU race conditions by detecting tampering
			actualTarget, err := os.Readlink(targetPath)
			if err != nil || actualTarget != header.Linkname {
				h.logger.Warn("symlink verification failed, removing",
					"path", targetPath,
					"expected", header.Linkname,
					"actual", actualTarget,
				)
				os.Remove(targetPath)
				continue
			}
		}
	}

	h.logger.Info("files and folders restore completed",
		"target_dir", targetDir,
		"restored_files", restoredFiles,
		"restored_size", restoredSize,
		"selective", selectiveRestore,
	)

	return nil
}

// restoreFilesAndFoldersWithProgress restores files with detailed progress reporting.
func (h *Handler) restoreFilesAndFoldersWithProgress(ctx context.Context, req restoreBackupRequest, data []byte, restoreCtx *restoreContext) error {
	// Parse the backup data using helper
	meta, err := parseFilesBackupData(data)
	if err != nil {
		return err
	}

	// Update restore context with metadata
	restoreCtx.totalFiles = meta.TotalFiles
	restoreCtx.totalSize = meta.TotalSize

	// Prepare target directory using helper
	targetDir, err := prepareRestoreTarget(req.RestoreTarget)
	if err != nil {
		return err
	}

	restoreCtx.reportProgress("restoring", 55, fmt.Sprintf("Restoring to %s", targetDir), "info")

	// Configure and run archive restoration
	archiveConfig := tarArchiveRestoreConfig{
		TargetDir:         targetDir,
		PreserveStructure: req.PreserveStructure,
		OverwriteFiles:    req.OverwriteFiles,
		RestorePaths:      req.RestorePaths,
		Logger:            h.logger,
		ProgressInterval:  500 * time.Millisecond,
		ProgressCallback: func(progress restoreArchiveProgress) {
			pct := 50
			if restoreCtx.totalFiles > 0 {
				pct = 50 + (progress.RestoredFiles * 45 / restoreCtx.totalFiles)
			} else if restoreCtx.totalSize > 0 {
				pct = 50 + int(progress.RestoredSize*45/restoreCtx.totalSize)
			}
			restoreCtx.reportProgress("restoring", pct,
				fmt.Sprintf("Restored %d files (%s)",
					progress.RestoredFiles,
					formatBytes(progress.RestoredSize)),
				"info")
		},
	}

	progress, err := restoreTarArchive(meta.ArchiveData, archiveConfig)
	if err != nil {
		return err
	}

	// Update restore context with final results
	restoreCtx.restoredFiles = progress.RestoredFiles
	restoreCtx.skippedFiles = progress.SkippedFiles
	restoreCtx.failedFiles = progress.FailedFiles
	restoreCtx.restoredSize = progress.RestoredSize

	// Final progress update
	restoreCtx.reportProgress("restoring", 95,
		fmt.Sprintf("Restored %d files, %d skipped, %d failed",
			restoreCtx.restoredFiles,
			restoreCtx.skippedFiles,
			restoreCtx.failedFiles),
		"info")

	h.logger.Info("files and folders restore with progress completed",
		"target_dir", targetDir,
		"restored_files", restoreCtx.restoredFiles,
		"skipped_files", restoreCtx.skippedFiles,
		"failed_files", restoreCtx.failedFiles,
		"restored_size", restoreCtx.restoredSize,
	)

	return nil
}

// formatBytes formats bytes to human-readable string.
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// listBackupContents lists the contents of a files_and_folders backup without extracting.
// This is used for the preview/selection UI before restore.
type backupFileEntry struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
	IsDir    bool   `json:"is_dir"`
}

type listBackupContentsRequest struct {
	BackupID    string `json:"backup_id"`
	DownloadURL string `json:"download_url"`
	Encrypted   bool   `json:"encrypted"`
	EncryptKey  string `json:"encrypt_key,omitempty"`
	EncryptIV   string `json:"encryption_iv,omitempty"`
}

type listBackupContentsResponse struct {
	BackupID string            `json:"backup_id"`
	Entries  []backupFileEntry `json:"entries"`
	Count    int               `json:"count"`
	Error    string            `json:"error,omitempty"`
}

// handleListBackupContents handles the list_backup_contents action.
func (h *Handler) handleListBackupContents(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req listBackupContentsRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.MsgInvalidRequest, err)
	}

	h.logger.Info("listing backup contents", "backup_id", req.BackupID)

	// Download backup data
	backupData, err := h.downloadBackupData(ctx, req.DownloadURL)
	if err != nil {
		return listBackupContentsResponse{
			BackupID: req.BackupID,
			Error:    fmt.Sprintf("download failed: %v", err),
		}, nil
	}

	// Decrypt if needed
	if req.Encrypted && req.EncryptKey != "" {
		decryptedData, err := h.decryptData(backupData, req.EncryptKey, req.EncryptIV)
		if err != nil {
			return listBackupContentsResponse{
				BackupID: req.BackupID,
				Error:    fmt.Sprintf("decryption failed: %v", err),
			}, nil
		}
		backupData = decryptedData
	}

	// Decompress
	gzReader, err := gzip.NewReader(bytes.NewReader(backupData))
	if err != nil {
		return listBackupContentsResponse{
			BackupID: req.BackupID,
			Error:    fmt.Sprintf("decompression failed: %v", err),
		}, nil
	}
	defer gzReader.Close()

	decompressedData, err := io.ReadAll(gzReader)
	if err != nil {
		return listBackupContentsResponse{
			BackupID: req.BackupID,
			Error:    fmt.Sprintf("reading decompressed data: %v", err),
		}, nil
	}

	// Parse backup data
	var backupMeta map[string]interface{}
	if err := json.Unmarshal(decompressedData, &backupMeta); err != nil {
		return listBackupContentsResponse{
			BackupID: req.BackupID,
			Error:    fmt.Sprintf("failed to parse backup: %v", err),
		}, nil
	}

	// Get archive data
	archiveDataB64, ok := backupMeta["archive_data"].(string)
	if !ok {
		return listBackupContentsResponse{
			BackupID: req.BackupID,
			Error:    "no archive_data found in backup",
		}, nil
	}

	archiveData, err := base64.StdEncoding.DecodeString(archiveDataB64)
	if err != nil {
		return listBackupContentsResponse{
			BackupID: req.BackupID,
			Error:    fmt.Sprintf("failed to decode archive: %v", err),
		}, nil
	}

	// Read tar contents
	archiveGzReader, err := gzip.NewReader(bytes.NewReader(archiveData))
	if err != nil {
		return listBackupContentsResponse{
			BackupID: req.BackupID,
			Error:    fmt.Sprintf("failed to open archive: %v", err),
		}, nil
	}
	defer archiveGzReader.Close()

	tarReader := tar.NewReader(archiveGzReader)
	var entries []backupFileEntry

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		entries = append(entries, backupFileEntry{
			Path:     header.Name,
			Size:     header.Size,
			Modified: header.ModTime.Format(time.RFC3339),
			IsDir:    header.Typeflag == tar.TypeDir,
		})
	}

	return listBackupContentsResponse{
		BackupID: req.BackupID,
		Entries:  entries,
		Count:    len(entries),
	}, nil
}

// =============================================================================
// Database Backup Functions
// =============================================================================

// collectPostgreSQLBackup creates a backup of a PostgreSQL database using pg_dump.
func (h *Handler) collectPostgreSQLBackup(ctx context.Context, req createBackupRequest) ([]byte, error) {
	if req.PostgreSQL == nil {
		return nil, fmt.Errorf("postgresql parameters are required for postgresql backup")
	}

	params := req.PostgreSQL

	// Validate all input parameters to prevent command injection
	if params.DatabaseName != "" && !isValidDatabaseName(params.DatabaseName) {
		return nil, fmt.Errorf("invalid database name: contains disallowed characters")
	}
	if params.SocketPath != "" && !isValidSocketPath(params.SocketPath) {
		return nil, fmt.Errorf("invalid socket path: contains disallowed characters or path traversal")
	}
	if params.Host != "" && !isValidDBHost(params.Host) {
		return nil, fmt.Errorf("invalid host: contains disallowed characters")
	}
	if params.Username != "" && !isValidDBUsername(params.Username) {
		return nil, fmt.Errorf("invalid username: contains disallowed characters")
	}

	// Build pg_dump command arguments
	args := []string{}

	// Connection parameters
	if params.ConnectionType == "socket" && params.SocketPath != "" {
		args = append(args, "-h", params.SocketPath)
	} else if params.Host != "" {
		args = append(args, "-h", params.Host)
		if params.Port > 0 {
			args = append(args, "-p", fmt.Sprintf("%d", params.Port))
		}
	}

	if params.Username != "" {
		args = append(args, "-U", params.Username)
	}

	// Dump options
	if params.SchemaOnly {
		args = append(args, "--schema-only")
	}
	if params.DataOnly {
		args = append(args, "--data-only")
	}

	// Database name
	if params.DatabaseName != "" {
		args = append(args, params.DatabaseName)
	}

	h.logger.Info("executing pg_dump",
		"host", params.Host,
		"port", params.Port,
		"database", params.DatabaseName,
		"schema_only", params.SchemaOnly,
		"data_only", params.DataOnly,
	)

	// Audit log database backup start
	pgStartTime := time.Now()
	audit.GetLogger().Log(ctx, audit.Event{
		EventType: audit.EventBackupDatabaseStart,
		Severity:  audit.SeverityInfo,
		Source:    "backup",
		Success:   true,
		Details: map[string]interface{}{
			"database_type": "postgresql",
			"database":      params.DatabaseName,
			"host":          params.Host,
		},
	})

	// Create command
	cmd := exec.CommandContext(ctx, "pg_dump", args...)

	// Set minimal environment with password (prevents leaking sensitive env vars)
	if params.Password != "" {
		cmd.Env = getMinimalDBEnv("PGPASSWORD=" + params.Password)
	} else {
		cmd.Env = getMinimalDBEnv()
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		h.logger.Error("pg_dump failed",
			"error", err,
			"stderr", stderr.String(),
		)
		audit.GetLogger().LogDatabaseBackup(ctx, false, "postgresql", params.DatabaseName, time.Since(pgStartTime), err)
		return nil, fmt.Errorf("pg_dump failed: %w - %s", err, stderr.String())
	}

	// Audit log database backup success
	audit.GetLogger().LogDatabaseBackup(ctx, true, "postgresql", params.DatabaseName, time.Since(pgStartTime), nil)

	// Build backup metadata
	backupData := make(map[string]interface{})
	backupData["backup_type"] = "postgresql"
	backupData["database_type"] = "postgresql"
	backupData["database_name"] = params.DatabaseName
	backupData["host"] = params.Host
	backupData["port"] = params.Port
	backupData["schema_only"] = params.SchemaOnly
	backupData["data_only"] = params.DataOnly
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = h.cfg.GetUUID()
	backupData["dump_size"] = stdout.Len()
	backupData["dump_data"] = base64.StdEncoding.EncodeToString(stdout.Bytes())

	return json.Marshal(backupData)
}

// collectMySQLBackup creates a backup of a MySQL/MariaDB database using mysqldump.
func (h *Handler) collectMySQLBackup(ctx context.Context, req createBackupRequest) ([]byte, error) {
	if req.MySQL == nil {
		return nil, fmt.Errorf("mysql parameters are required for mysql backup")
	}

	params := req.MySQL

	// Validate all input parameters to prevent command injection
	if params.DatabaseName != "" && !isValidDatabaseName(params.DatabaseName) {
		return nil, fmt.Errorf("invalid database name: contains disallowed characters")
	}
	if params.SocketPath != "" && !isValidSocketPath(params.SocketPath) {
		return nil, fmt.Errorf("invalid socket path: contains disallowed characters or path traversal")
	}
	if params.Host != "" && !isValidDBHost(params.Host) {
		return nil, fmt.Errorf("invalid host: contains disallowed characters")
	}
	if params.Username != "" && !isValidDBUsername(params.Username) {
		return nil, fmt.Errorf("invalid username: contains disallowed characters")
	}

	// Build mysqldump command arguments
	args := []string{}

	// Connection parameters
	if params.ConnectionType == "socket" && params.SocketPath != "" {
		args = append(args, "--socket="+params.SocketPath)
	} else if params.Host != "" {
		args = append(args, "-h", params.Host)
		if params.Port > 0 {
			args = append(args, "-P", fmt.Sprintf("%d", params.Port))
		}
	}

	if params.Username != "" {
		args = append(args, "-u", params.Username)
	}

	// Dump options
	if params.SingleTransaction {
		args = append(args, "--single-transaction")
	}

	// Database selection
	if params.AllDatabases {
		args = append(args, "--all-databases")
	} else if params.DatabaseName != "" {
		args = append(args, params.DatabaseName)
	}

	h.logger.Info("executing mysqldump",
		"host", params.Host,
		"port", params.Port,
		"database", params.DatabaseName,
		"all_databases", params.AllDatabases,
		"single_transaction", params.SingleTransaction,
	)

	// Audit log database backup start
	mysqlStartTime := time.Now()
	dbName := params.DatabaseName
	if params.AllDatabases {
		dbName = "*"
	}
	audit.GetLogger().Log(ctx, audit.Event{
		EventType: audit.EventBackupDatabaseStart,
		Severity:  audit.SeverityInfo,
		Source:    "backup",
		Success:   true,
		Details: map[string]interface{}{
			"database_type": "mysql",
			"database":      dbName,
			"host":          params.Host,
			"all_databases": params.AllDatabases,
		},
	})

	// Create command
	cmd := exec.CommandContext(ctx, "mysqldump", args...)

	// Set minimal environment with password (prevents leaking sensitive env vars)
	if params.Password != "" {
		cmd.Env = getMinimalDBEnv("MYSQL_PWD=" + params.Password)
	} else {
		cmd.Env = getMinimalDBEnv()
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		h.logger.Error("mysqldump failed",
			"error", err,
			"stderr", stderr.String(),
		)
		audit.GetLogger().LogDatabaseBackup(ctx, false, "mysql", dbName, time.Since(mysqlStartTime), err)
		return nil, fmt.Errorf("mysqldump failed: %w - %s", err, stderr.String())
	}

	// Audit log database backup success
	audit.GetLogger().LogDatabaseBackup(ctx, true, "mysql", dbName, time.Since(mysqlStartTime), nil)

	// Build backup metadata
	backupData := make(map[string]interface{})
	backupData["backup_type"] = "mysql"
	backupData["database_type"] = "mysql"
	backupData["database_name"] = params.DatabaseName
	backupData["all_databases"] = params.AllDatabases
	backupData["host"] = params.Host
	backupData["port"] = params.Port
	backupData["single_transaction"] = params.SingleTransaction
	backupData["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	backupData["agent_uuid"] = h.cfg.GetUUID()
	backupData["dump_size"] = stdout.Len()
	backupData["dump_data"] = base64.StdEncoding.EncodeToString(stdout.Bytes())

	return json.Marshal(backupData)
}

// testDatabaseConnectionRequest holds parameters for testing database connections.
type testDatabaseConnectionRequest struct {
	DatabaseType   string `json:"database_type"`   // postgresql, mysql
	ConnectionType string `json:"connection_type"` // host, socket
	Host           string `json:"host,omitempty"`
	Port           int    `json:"port,omitempty"`
	SocketPath     string `json:"socket_path,omitempty"`
	Username       string `json:"username,omitempty"`
	Password       string `json:"password,omitempty"`
	DatabaseName   string `json:"database_name,omitempty"`
}

// testDatabaseConnectionResponse holds the result of a database connection test.
type testDatabaseConnectionResponse struct {
	Success       bool     `json:"success"`
	Message       string   `json:"message,omitempty"`
	Error         string   `json:"error,omitempty"`
	ServerVersion string   `json:"server_version,omitempty"`
	Databases     []string `json:"databases,omitempty"`
}

// handleTestDatabaseConnection tests a database connection.
func (h *Handler) handleTestDatabaseConnection(ctx context.Context, payload json.RawMessage) (interface{}, error) {
	var req testDatabaseConnectionRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("failed to parse test connection request: %w", err)
	}

	h.logger.Info("testing database connection",
		"database_type", req.DatabaseType,
		"connection_type", req.ConnectionType,
		"host", req.Host,
		"port", req.Port,
	)

	var response testDatabaseConnectionResponse

	switch req.DatabaseType {
	case "postgresql":
		response = h.testPostgreSQLConnection(ctx, req)
	case "mysql":
		response = h.testMySQLConnection(ctx, req)
	default:
		return testDatabaseConnectionResponse{
			Success: false,
			Error:   fmt.Sprintf("unsupported database type: %s", req.DatabaseType),
		}, nil
	}

	return response, nil
}

// testPostgreSQLConnection tests a PostgreSQL database connection.
func (h *Handler) testPostgreSQLConnection(ctx context.Context, req testDatabaseConnectionRequest) testDatabaseConnectionResponse {
	// Build connection string for psql
	args := []string{"-c", "SELECT version();", "-t", "-A"}

	// Connection parameters
	if req.ConnectionType == "socket" && req.SocketPath != "" {
		args = append(args, "-h", req.SocketPath)
	} else if req.Host != "" {
		args = append(args, "-h", req.Host)
		if req.Port > 0 {
			args = append(args, "-p", fmt.Sprintf("%d", req.Port))
		}
	}

	if req.Username != "" {
		args = append(args, "-U", req.Username)
	}

	dbName := req.DatabaseName
	if dbName == "" {
		dbName = "postgres"
	}
	args = append(args, dbName)

	// Create command with minimal environment (prevents leaking sensitive env vars)
	cmd := exec.CommandContext(ctx, "psql", args...)
	if req.Password != "" {
		cmd.Env = getMinimalDBEnv("PGPASSWORD=" + req.Password)
	} else {
		cmd.Env = getMinimalDBEnv()
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		h.logger.Error("postgresql connection test failed",
			"error", err,
			"stderr", stderr.String(),
		)
		return testDatabaseConnectionResponse{
			Success: false,
			Error:   fmt.Sprintf("connection failed: %s", stderr.String()),
		}
	}

	serverVersion := strings.TrimSpace(stdout.String())

	// Get list of databases
	databases := h.getPostgreSQLDatabases(ctx, req)

	return testDatabaseConnectionResponse{
		Success:       true,
		Message:       "Connection successful",
		ServerVersion: serverVersion,
		Databases:     databases,
	}
}

// getPostgreSQLDatabases retrieves the list of databases from PostgreSQL.
func (h *Handler) getPostgreSQLDatabases(ctx context.Context, req testDatabaseConnectionRequest) []string {
	args := []string{"-c", "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname;", "-t", "-A"}

	if req.ConnectionType == "socket" && req.SocketPath != "" {
		args = append(args, "-h", req.SocketPath)
	} else if req.Host != "" {
		args = append(args, "-h", req.Host)
		if req.Port > 0 {
			args = append(args, "-p", fmt.Sprintf("%d", req.Port))
		}
	}

	if req.Username != "" {
		args = append(args, "-U", req.Username)
	}

	args = append(args, "postgres")

	cmd := exec.CommandContext(ctx, "psql", args...)
	if req.Password != "" {
		cmd.Env = getMinimalDBEnv("PGPASSWORD=" + req.Password)
	} else {
		cmd.Env = getMinimalDBEnv()
	}

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil
	}

	var databases []string
	for _, line := range strings.Split(stdout.String(), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			databases = append(databases, line)
		}
	}

	return databases
}

// testMySQLConnection tests a MySQL database connection.
func (h *Handler) testMySQLConnection(ctx context.Context, req testDatabaseConnectionRequest) testDatabaseConnectionResponse {
	// Build arguments for mysql command
	args := []string{"-e", "SELECT VERSION();", "-N", "-B"}

	// Connection parameters
	if req.ConnectionType == "socket" && req.SocketPath != "" {
		args = append(args, "--socket="+req.SocketPath)
	} else if req.Host != "" {
		args = append(args, "-h", req.Host)
		if req.Port > 0 {
			args = append(args, "-P", fmt.Sprintf("%d", req.Port))
		}
	}

	if req.Username != "" {
		args = append(args, "-u", req.Username)
	}

	if req.DatabaseName != "" {
		args = append(args, req.DatabaseName)
	}

	// Create command
	cmd := exec.CommandContext(ctx, "mysql", args...)

	// Set minimal environment with password (prevents leaking sensitive env vars)
	if req.Password != "" {
		cmd.Env = getMinimalDBEnv("MYSQL_PWD=" + req.Password)
	} else {
		cmd.Env = getMinimalDBEnv()
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		h.logger.Error("mysql connection test failed",
			"error", err,
			"stderr", stderr.String(),
		)
		return testDatabaseConnectionResponse{
			Success: false,
			Error:   fmt.Sprintf("connection failed: %s", stderr.String()),
		}
	}

	serverVersion := strings.TrimSpace(stdout.String())

	// Get list of databases
	databases := h.getMySQLDatabases(ctx, req)

	return testDatabaseConnectionResponse{
		Success:       true,
		Message:       "Connection successful",
		ServerVersion: serverVersion,
		Databases:     databases,
	}
}

// getMySQLDatabases retrieves the list of databases from MySQL.
func (h *Handler) getMySQLDatabases(ctx context.Context, req testDatabaseConnectionRequest) []string {
	args := []string{"-e", "SHOW DATABASES;", "-N", "-B"}

	if req.ConnectionType == "socket" && req.SocketPath != "" {
		args = append(args, "--socket="+req.SocketPath)
	} else if req.Host != "" {
		args = append(args, "-h", req.Host)
		if req.Port > 0 {
			args = append(args, "-P", fmt.Sprintf("%d", req.Port))
		}
	}

	if req.Username != "" {
		args = append(args, "-u", req.Username)
	}

	cmd := exec.CommandContext(ctx, "mysql", args...)

	// Set minimal environment with password (prevents leaking sensitive env vars)
	if req.Password != "" {
		cmd.Env = getMinimalDBEnv("MYSQL_PWD=" + req.Password)
	} else {
		cmd.Env = getMinimalDBEnv()
	}

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil
	}

	var databases []string
	for _, line := range strings.Split(stdout.String(), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && line != "information_schema" && line != "performance_schema" && line != "sys" {
			databases = append(databases, line)
		}
	}

	return databases
}
