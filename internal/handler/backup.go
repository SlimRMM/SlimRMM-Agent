// Package handler provides backup handling for the agent.
package handler

import (
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
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/osquery"
)

// Backup request types

type createBackupRequest struct {
	BackupID   string `json:"backup_id"`
	BackupType string `json:"backup_type"` // config, logs, system_state, software_inventory, compliance_results
	UploadURL  string `json:"upload_url"`  // Pre-signed URL for upload
	Encrypt    bool   `json:"encrypt"`
	EncryptKey string `json:"encrypt_key,omitempty"` // DEK for client-side encryption (base64)
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
}

type restoreBackupRequest struct {
	BackupID    string `json:"backup_id"`
	BackupType  string `json:"backup_type"`
	DownloadURL string `json:"download_url"` // Pre-signed URL for download
	Encrypted   bool   `json:"encrypted"`
	EncryptKey  string `json:"encrypt_key,omitempty"` // DEK for decryption (base64)
	EncryptIV   string `json:"encryption_iv,omitempty"`
}

type restoreBackupResponse struct {
	BackupID string `json:"backup_id"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
}

type getBackupStatusRequest struct {
	BackupID string `json:"backup_id"`
}

type verifyBackupRequest struct {
	BackupID          string `json:"backup_id"`
	DownloadURL       string `json:"download_url"`
	ExpectedSHA256    string `json:"expected_sha256"`
	ExpectedSHA512    string `json:"expected_sha512"`
}

type verifyBackupResponse struct {
	BackupID      string `json:"backup_id"`
	Valid         bool   `json:"valid"`
	SHA256Match   bool   `json:"sha256_match"`
	SHA512Match   bool   `json:"sha512_match"`
	ActualSHA256  string `json:"actual_sha256"`
	ActualSHA512  string `json:"actual_sha512"`
	Error         string `json:"error,omitempty"`
}

// registerBackupHandlers registers backup-related action handlers.
func (h *Handler) registerBackupHandlers() {
	h.handlers["create_agent_backup"] = h.handleCreateAgentBackup
	h.handlers["restore_agent_backup"] = h.handleRestoreAgentBackup
	h.handlers["get_backup_status"] = h.handleGetBackupStatus
	h.handlers["verify_agent_backup"] = h.handleVerifyAgentBackup
}

// handleCreateAgentBackup handles backup creation requests.
func (h *Handler) handleCreateAgentBackup(ctx context.Context, data json.RawMessage) (interface{}, error) {
	var req createBackupRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("creating agent backup",
		"backup_id", req.BackupID,
		"backup_type", req.BackupType,
		"encrypt", req.Encrypt,
	)

	// Collect data based on backup type
	backupData, err := h.collectBackupData(ctx, req.BackupType)
	if err != nil {
		return createBackupResponse{
			BackupID: req.BackupID,
			Status:   "failed",
			Error:    err.Error(),
		}, nil
	}

	originalSize := int64(len(backupData))

	// Compress with gzip
	var compressedBuf bytes.Buffer
	gzWriter := gzip.NewWriter(&compressedBuf)
	if _, err := gzWriter.Write(backupData); err != nil {
		gzWriter.Close()
		return createBackupResponse{
			BackupID: req.BackupID,
			Status:   "failed",
			Error:    fmt.Sprintf("compression failed: %v", err),
		}, nil
	}
	gzWriter.Close()
	compressedData := compressedBuf.Bytes()
	compressedSize := int64(len(compressedData))

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
		return createBackupResponse{
			BackupID: req.BackupID,
			Status:   "failed",
			Error:    fmt.Sprintf("upload failed: %v", err),
		}, nil
	}

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
		return nil, fmt.Errorf("unknown backup type: %s", backupType)
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
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	h.logger.Info("restoring agent backup",
		"backup_id", req.BackupID,
		"backup_type", req.BackupType,
		"encrypted", req.Encrypted,
	)

	// Download backup data
	backupData, err := h.downloadBackupData(ctx, req.DownloadURL)
	if err != nil {
		return restoreBackupResponse{
			BackupID: req.BackupID,
			Status:   "failed",
			Error:    fmt.Sprintf("download failed: %v", err),
		}, nil
	}

	// Decrypt if needed
	if req.Encrypted && req.EncryptKey != "" {
		backupData, err = h.decryptData(backupData, req.EncryptKey, req.EncryptIV)
		if err != nil {
			return restoreBackupResponse{
				BackupID: req.BackupID,
				Status:   "failed",
				Error:    fmt.Sprintf("decryption failed: %v", err),
			}, nil
		}
	}

	// Decompress
	gzReader, err := gzip.NewReader(bytes.NewReader(backupData))
	if err != nil {
		return restoreBackupResponse{
			BackupID: req.BackupID,
			Status:   "failed",
			Error:    fmt.Sprintf("decompression failed: %v", err),
		}, nil
	}
	defer gzReader.Close()

	decompressedData, err := io.ReadAll(gzReader)
	if err != nil {
		return restoreBackupResponse{
			BackupID: req.BackupID,
			Status:   "failed",
			Error:    fmt.Sprintf("reading decompressed data: %v", err),
		}, nil
	}

	// Restore based on backup type
	if err := h.restoreBackupData(req.BackupType, decompressedData); err != nil {
		return restoreBackupResponse{
			BackupID: req.BackupID,
			Status:   "failed",
			Error:    fmt.Sprintf("restore failed: %v", err),
		}, nil
	}

	h.logger.Info("agent backup restored successfully",
		"backup_id", req.BackupID,
		"backup_type", req.BackupType,
	)

	return restoreBackupResponse{
		BackupID: req.BackupID,
		Status:   "completed",
	}, nil
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
		return fmt.Errorf("unknown backup type: %s", backupType)
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
			os.WriteFile(backupPath, currentData, 0600)
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
		return nil, fmt.Errorf("invalid request: %w", err)
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
		return nil, fmt.Errorf("invalid request: %w", err)
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
