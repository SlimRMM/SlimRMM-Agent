// Package backup provides streaming database backup collectors.
// These collectors stream database dumps directly to the upload destination
// without loading entire dumps into memory.
package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// StreamingMySQLCollector collects MySQL database backups using streaming.
// Memory usage is O(buffer_size) regardless of database size.
type StreamingMySQLCollector struct {
	logger *slog.Logger
}

// NewStreamingMySQLCollector creates a new streaming MySQL collector.
func NewStreamingMySQLCollector(logger *slog.Logger) *StreamingMySQLCollector {
	if logger == nil {
		logger = slog.Default()
	}
	return &StreamingMySQLCollector{logger: logger}
}

// Type returns the backup type.
func (c *StreamingMySQLCollector) Type() BackupType {
	return TypeMySQL
}

// SupportsStreaming returns true as this collector supports streaming.
func (c *StreamingMySQLCollector) SupportsStreaming() bool {
	return true
}

// CollectStream writes MySQL dump directly to the writer.
// Uses mysqldump with output piped directly to writer.
func (c *StreamingMySQLCollector) CollectStream(ctx context.Context, config CollectorConfig, w io.Writer) (int64, error) {
	if !c.isMySQLDumpAvailable() {
		return 0, &ErrFeatureUnavailable{Feature: "MySQL (mysqldump not found)"}
	}

	// Validate parameters
	if config.Host == "" && config.SocketPath == "" {
		return 0, &ErrMissingParameter{
			Parameter: "host or socket_path",
			Context:   "mysql backup",
		}
	}

	if config.DatabaseName == "" && !config.AllDatabases {
		return 0, &ErrMissingParameter{
			Parameter: "database_name or all_databases",
			Context:   "mysql backup",
		}
	}

	c.logger.Info("starting streaming MySQL backup",
		"database", config.DatabaseName,
		"all_databases", config.AllDatabases,
		"host", config.Host,
	)

	// Create metadata
	metadata := map[string]interface{}{
		"backup_type":   "mysql",
		"database_name": config.DatabaseName,
		"all_databases": config.AllDatabases,
		"host":          config.Host,
		"port":          config.Port,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
		"agent_uuid":    config.AgentUUID,
		"version":       2, // Version 2 = streaming format
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

	// Build mysqldump command
	args := c.buildMySQLDumpArgs(config)

	// Stream mysqldump output directly to writer
	dumpBytes, err := c.streamMySQLDump(ctx, args, config.Password, w)
	if err != nil {
		return totalWritten, fmt.Errorf("streaming mysqldump: %w", err)
	}

	totalWritten += dumpBytes

	c.logger.Info("MySQL backup streaming complete",
		"database", config.DatabaseName,
		"total_bytes", totalWritten,
	)

	return totalWritten, nil
}

// buildMySQLDumpArgs builds command line arguments for mysqldump.
func (c *StreamingMySQLCollector) buildMySQLDumpArgs(config CollectorConfig) []string {
	var args []string

	// Connection type
	if config.ConnectionType == "socket" && config.SocketPath != "" {
		args = append(args, "--socket="+config.SocketPath)
	} else if config.Host != "" {
		args = append(args, "-h", config.Host)
		if config.Port > 0 {
			args = append(args, "-P", fmt.Sprintf("%d", config.Port))
		}
	}

	// Authentication
	if config.Username != "" {
		args = append(args, "-u", config.Username)
	}

	// Dump options for consistency
	args = append(args, "--single-transaction")

	// Database selection
	if config.AllDatabases {
		args = append(args, "--all-databases")
	} else if config.DatabaseName != "" {
		args = append(args, config.DatabaseName)
	}

	return args
}

// streamMySQLDump streams mysqldump output directly to writer.
func (c *StreamingMySQLCollector) streamMySQLDump(ctx context.Context, args []string, password string, w io.Writer) (int64, error) {
	cmd := exec.CommandContext(ctx, "mysqldump", args...)

	// Set password via environment variable (secure way)
	if password != "" {
		cmd.Env = append(os.Environ(), "MYSQL_PWD="+password)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("creating stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return 0, fmt.Errorf("creating stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("starting mysqldump: %w", err)
	}

	// Stream with fixed-size buffer (8 MB)
	buf := make([]byte, 8*1024*1024)
	n, copyErr := io.CopyBuffer(w, stdout, buf)

	stderrBytes, _ := io.ReadAll(io.LimitReader(stderr, MaxResponseBodySize))

	if err := cmd.Wait(); err != nil {
		if len(stderrBytes) > 0 {
			return n, fmt.Errorf("mysqldump failed: %w - %s", err, string(stderrBytes))
		}
		return n, fmt.Errorf("mysqldump failed: %w", err)
	}

	if copyErr != nil {
		return n, fmt.Errorf("streaming dump data: %w", copyErr)
	}

	return n, nil
}

// isMySQLDumpAvailable checks if mysqldump is available.
func (c *StreamingMySQLCollector) isMySQLDumpAvailable() bool {
	_, err := exec.LookPath("mysqldump")
	return err == nil
}

// StreamingPostgreSQLCollector collects PostgreSQL database backups using streaming.
type StreamingPostgreSQLCollector struct {
	logger *slog.Logger
}

// NewStreamingPostgreSQLCollector creates a new streaming PostgreSQL collector.
func NewStreamingPostgreSQLCollector(logger *slog.Logger) *StreamingPostgreSQLCollector {
	if logger == nil {
		logger = slog.Default()
	}
	return &StreamingPostgreSQLCollector{logger: logger}
}

// Type returns the backup type.
func (c *StreamingPostgreSQLCollector) Type() BackupType {
	return TypePostgreSQL
}

// SupportsStreaming returns true as this collector supports streaming.
func (c *StreamingPostgreSQLCollector) SupportsStreaming() bool {
	return true
}

// CollectStream writes PostgreSQL dump directly to the writer.
func (c *StreamingPostgreSQLCollector) CollectStream(ctx context.Context, config CollectorConfig, w io.Writer) (int64, error) {
	if !c.isPgDumpAvailable() {
		return 0, &ErrFeatureUnavailable{Feature: "PostgreSQL (pg_dump not found)"}
	}

	// Validate parameters
	if config.Host == "" && config.SocketPath == "" {
		return 0, &ErrMissingParameter{
			Parameter: "host or socket_path",
			Context:   "postgresql backup",
		}
	}

	c.logger.Info("starting streaming PostgreSQL backup",
		"database", config.DatabaseName,
		"host", config.Host,
	)

	// Create metadata
	metadata := map[string]interface{}{
		"backup_type":   "postgresql",
		"database_name": config.DatabaseName,
		"host":          config.Host,
		"port":          config.Port,
		"schema_only":   config.SchemaOnly,
		"data_only":     config.DataOnly,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
		"agent_uuid":    config.AgentUUID,
		"version":       2, // Version 2 = streaming format
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

	// Build pg_dump command
	args := c.buildPgDumpArgs(config)

	// Stream pg_dump output directly to writer
	dumpBytes, err := c.streamPgDump(ctx, args, config.Password, w)
	if err != nil {
		return totalWritten, fmt.Errorf("streaming pg_dump: %w", err)
	}

	totalWritten += dumpBytes

	c.logger.Info("PostgreSQL backup streaming complete",
		"database", config.DatabaseName,
		"total_bytes", totalWritten,
	)

	return totalWritten, nil
}

// buildPgDumpArgs builds command line arguments for pg_dump.
func (c *StreamingPostgreSQLCollector) buildPgDumpArgs(config CollectorConfig) []string {
	var args []string

	// Connection type
	if config.ConnectionType == "socket" && config.SocketPath != "" {
		args = append(args, "-h", config.SocketPath)
	} else if config.Host != "" {
		args = append(args, "-h", config.Host)
		if config.Port > 0 {
			args = append(args, "-p", fmt.Sprintf("%d", config.Port))
		}
	}

	// Authentication
	if config.Username != "" {
		args = append(args, "-U", config.Username)
	}

	// Dump options
	if config.SchemaOnly {
		args = append(args, "--schema-only")
	}
	if config.DataOnly {
		args = append(args, "--data-only")
	}

	// Database name
	if config.DatabaseName != "" {
		args = append(args, config.DatabaseName)
	}

	return args
}

// streamPgDump streams pg_dump output directly to writer.
func (c *StreamingPostgreSQLCollector) streamPgDump(ctx context.Context, args []string, password string, w io.Writer) (int64, error) {
	cmd := exec.CommandContext(ctx, "pg_dump", args...)

	// Set password via environment variable (secure way)
	if password != "" {
		cmd.Env = append(os.Environ(), "PGPASSWORD="+password)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("creating stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return 0, fmt.Errorf("creating stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("starting pg_dump: %w", err)
	}

	// Stream with fixed-size buffer (8 MB)
	buf := make([]byte, 8*1024*1024)
	n, copyErr := io.CopyBuffer(w, stdout, buf)

	stderrBytes, _ := io.ReadAll(io.LimitReader(stderr, MaxResponseBodySize))

	if err := cmd.Wait(); err != nil {
		if len(stderrBytes) > 0 {
			return n, fmt.Errorf("pg_dump failed: %w - %s", err, string(stderrBytes))
		}
		return n, fmt.Errorf("pg_dump failed: %w", err)
	}

	if copyErr != nil {
		return n, fmt.Errorf("streaming dump data: %w", copyErr)
	}

	return n, nil
}

// isPgDumpAvailable checks if pg_dump is available.
func (c *StreamingPostgreSQLCollector) isPgDumpAvailable() bool {
	_, err := exec.LookPath("pg_dump")
	return err == nil
}

// ValidatePlatform checks platform support for MySQL collector.
func (c *StreamingMySQLCollector) ValidatePlatform() error {
	if !c.isMySQLDumpAvailable() {
		return &ErrFeatureUnavailable{
			Feature: "MySQL backup",
			Reason:  "mysqldump not found in PATH",
		}
	}
	return nil
}

// SupportedPlatforms returns the platforms that support MySQL backup.
func (c *StreamingMySQLCollector) SupportedPlatforms() []string {
	return []string{"linux", "darwin", "windows"}
}

// CurrentPlatformSupported checks if the current platform is supported.
func (c *StreamingMySQLCollector) CurrentPlatformSupported() bool {
	for _, p := range c.SupportedPlatforms() {
		if runtime.GOOS == p {
			return true
		}
	}
	return false
}

// ValidatePlatform checks platform support for PostgreSQL collector.
func (c *StreamingPostgreSQLCollector) ValidatePlatform() error {
	if !c.isPgDumpAvailable() {
		return &ErrFeatureUnavailable{
			Feature: "PostgreSQL backup",
			Reason:  "pg_dump not found in PATH",
		}
	}
	return nil
}

// SupportedPlatforms returns the platforms that support PostgreSQL backup.
func (c *StreamingPostgreSQLCollector) SupportedPlatforms() []string {
	return []string{"linux", "darwin", "windows"}
}

// CurrentPlatformSupported checks if the current platform is supported.
func (c *StreamingPostgreSQLCollector) CurrentPlatformSupported() bool {
	for _, p := range c.SupportedPlatforms() {
		if runtime.GOOS == p {
			return true
		}
	}
	return false
}

// TestMySQLConnection tests MySQL connection for the collector.
func (c *StreamingMySQLCollector) TestConnection(ctx context.Context, config CollectorConfig) error {
	args := []string{"-e", "SELECT 1"}

	if config.ConnectionType == "socket" && config.SocketPath != "" {
		args = append(args, "--socket="+config.SocketPath)
	} else if config.Host != "" {
		args = append(args, "-h", config.Host)
		if config.Port > 0 {
			args = append(args, "-P", fmt.Sprintf("%d", config.Port))
		}
	}

	if config.Username != "" {
		args = append(args, "-u", config.Username)
	}

	if config.DatabaseName != "" {
		args = append(args, config.DatabaseName)
	}

	cmd := exec.CommandContext(ctx, "mysql", args...)

	if config.Password != "" {
		cmd.Env = append(os.Environ(), "MYSQL_PWD="+config.Password)
	}

	if err := cmd.Run(); err != nil {
		return &ErrCollectionFailed{
			Type:   TypeMySQL,
			Reason: "connection test failed",
			Err:    err,
		}
	}

	return nil
}

// TestPostgreSQLConnection tests PostgreSQL connection for the collector.
func (c *StreamingPostgreSQLCollector) TestConnection(ctx context.Context, config CollectorConfig) error {
	args := []string{"-c", "SELECT 1"}

	if config.ConnectionType == "socket" && config.SocketPath != "" {
		args = append(args, "-h", config.SocketPath)
	} else if config.Host != "" {
		args = append(args, "-h", config.Host)
		if config.Port > 0 {
			args = append(args, "-p", fmt.Sprintf("%d", config.Port))
		}
	}

	if config.Username != "" {
		args = append(args, "-U", config.Username)
	}

	if config.DatabaseName != "" {
		args = append(args, "-d", config.DatabaseName)
	}

	cmd := exec.CommandContext(ctx, "psql", args...)

	if config.Password != "" {
		cmd.Env = append(os.Environ(), "PGPASSWORD="+config.Password)
	}

	if err := cmd.Run(); err != nil {
		return &ErrCollectionFailed{
			Type:   TypePostgreSQL,
			Reason: "connection test failed",
			Err:    err,
		}
	}

	return nil
}
