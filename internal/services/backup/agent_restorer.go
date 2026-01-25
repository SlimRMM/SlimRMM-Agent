// Package backup provides backup collection services for the RMM agent.
package backup

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// AgentConfigRestorer restores agent configuration from backups.
type AgentConfigRestorer struct {
	paths  AgentPaths
	logger Logger
}

// NewAgentConfigRestorer creates a new agent config restorer.
func NewAgentConfigRestorer(paths AgentPaths, logger Logger) *AgentConfigRestorer {
	return &AgentConfigRestorer{paths: paths, logger: logger}
}

// Type returns the backup type.
func (r *AgentConfigRestorer) Type() BackupType {
	return TypeAgentConfig
}

// Restore restores agent configuration from backup data.
func (r *AgentConfigRestorer) Restore(ctx context.Context, data []byte, config RestoreConfig) (*RestoreResult, error) {
	result := &RestoreResult{
		Status: "in_progress",
	}

	// Parse backup data
	var backupData map[string]interface{}
	if err := json.Unmarshal(data, &backupData); err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to parse backup data: %v", err)
		return result, err
	}

	// Determine config path
	configPath := config.ConfigPath
	if configPath == "" {
		configPath = r.paths.ConfigFile
	}

	// Restore config.json
	if configData, ok := backupData["config.json"].(string); ok {
		decoded, err := base64.StdEncoding.DecodeString(configData)
		if err != nil {
			result.FailedFiles++
			if r.logger != nil {
				r.logger.Warn("Failed to decode config.json", "error", err)
			}
		} else {
			// Create parent directory if needed
			if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
				result.FailedFiles++
				if r.logger != nil {
					r.logger.Warn("Failed to create config directory", "error", err)
				}
			} else if err := os.WriteFile(configPath, decoded, 0600); err != nil {
				result.FailedFiles++
				if r.logger != nil {
					r.logger.Warn("Failed to write config.json", "error", err)
				}
			} else {
				result.RestoredFiles++
				result.TotalFiles++
			}
		}
	}

	// Restore CA certificate
	if caCertData, ok := backupData["ca.crt"].(string); ok {
		decoded, err := base64.StdEncoding.DecodeString(caCertData)
		if err == nil {
			if err := os.MkdirAll(filepath.Dir(r.paths.CACert), 0755); err == nil {
				if err := os.WriteFile(r.paths.CACert, decoded, 0644); err == nil {
					result.RestoredFiles++
				}
			}
		}
		result.TotalFiles++
	}

	// Restore client certificate
	if clientCertData, ok := backupData["client.crt"].(string); ok {
		decoded, err := base64.StdEncoding.DecodeString(clientCertData)
		if err == nil {
			if err := os.MkdirAll(filepath.Dir(r.paths.ClientCert), 0755); err == nil {
				if err := os.WriteFile(r.paths.ClientCert, decoded, 0644); err == nil {
					result.RestoredFiles++
				}
			}
		}
		result.TotalFiles++
	}

	result.Status = "completed"
	if result.FailedFiles > 0 {
		result.Status = "completed_with_errors"
	}

	if r.logger != nil {
		r.logger.Info("Agent config restore completed",
			"restored", result.RestoredFiles,
			"failed", result.FailedFiles,
		)
	}

	return result, nil
}

// AgentLogsRestorer restores agent logs from backups.
type AgentLogsRestorer struct {
	paths  AgentPaths
	logger Logger
}

// NewAgentLogsRestorer creates a new agent logs restorer.
func NewAgentLogsRestorer(paths AgentPaths, logger Logger) *AgentLogsRestorer {
	return &AgentLogsRestorer{paths: paths, logger: logger}
}

// Type returns the backup type.
func (r *AgentLogsRestorer) Type() BackupType {
	return TypeAgentLogs
}

// Restore restores agent logs from backup data.
func (r *AgentLogsRestorer) Restore(ctx context.Context, data []byte, config RestoreConfig) (*RestoreResult, error) {
	result := &RestoreResult{
		Status: "in_progress",
	}

	// Parse backup data
	var backupData struct {
		Logs map[string]string `json:"logs"`
	}
	if err := json.Unmarshal(data, &backupData); err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to parse backup data: %v", err)
		return result, err
	}

	// Restore log files
	logDir := r.paths.LogDir
	if err := os.MkdirAll(logDir, 0755); err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to create log directory: %v", err)
		return result, err
	}

	for relPath, encodedData := range backupData.Logs {
		result.TotalFiles++

		decoded, err := base64.StdEncoding.DecodeString(encodedData)
		if err != nil {
			result.FailedFiles++
			continue
		}

		destPath := filepath.Join(logDir, relPath)

		// Create parent directory if needed
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			result.FailedFiles++
			continue
		}

		if err := os.WriteFile(destPath, decoded, 0644); err != nil {
			result.FailedFiles++
			continue
		}

		result.RestoredFiles++
		result.RestoredSize += int64(len(decoded))
	}

	result.Status = "completed"
	if result.FailedFiles > 0 {
		result.Status = "completed_with_errors"
	}

	if r.logger != nil {
		r.logger.Info("Agent logs restore completed",
			"restored", result.RestoredFiles,
			"failed", result.FailedFiles,
		)
	}

	return result, nil
}
