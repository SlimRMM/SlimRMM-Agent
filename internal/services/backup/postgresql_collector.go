package backup

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// PostgreSQLCollector collects PostgreSQL database backups.
type PostgreSQLCollector struct{}

// NewPostgreSQLCollector creates a new PostgreSQL collector.
func NewPostgreSQLCollector() *PostgreSQLCollector {
	return &PostgreSQLCollector{}
}

// Type returns the backup type.
func (c *PostgreSQLCollector) Type() BackupType {
	return TypePostgreSQL
}

// Collect collects a PostgreSQL database backup using pg_dump.
func (c *PostgreSQLCollector) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	// Validate required parameters
	if config.Host == "" && config.SocketPath == "" {
		return nil, &ErrMissingParameter{
			Parameter: "host or socket_path",
			Context:   "postgresql backup",
		}
	}

	// Build pg_dump arguments
	args := c.buildPgDumpArgs(config)

	// Execute pg_dump
	cmd := exec.CommandContext(ctx, "pg_dump", args...)

	// Set password via environment variable (secure way)
	if config.Password != "" {
		cmd.Env = append(os.Environ(), "PGPASSWORD="+config.Password)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, &ErrCollectionFailed{
			Type:   TypePostgreSQL,
			Reason: fmt.Sprintf("pg_dump failed: %s", stderr.String()),
			Err:    err,
		}
	}

	// Build response
	result := map[string]interface{}{
		"backup_type":   "postgresql",
		"database_name": config.DatabaseName,
		"host":          config.Host,
		"port":          config.Port,
		"schema_only":   config.SchemaOnly,
		"data_only":     config.DataOnly,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
		"dump_data":     base64.StdEncoding.EncodeToString(stdout.Bytes()),
		"dump_size":     stdout.Len(),
	}

	return json.Marshal(result)
}

// buildPgDumpArgs builds the command line arguments for pg_dump.
func (c *PostgreSQLCollector) buildPgDumpArgs(config CollectorConfig) []string {
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

// TestConnection tests the PostgreSQL connection.
func (c *PostgreSQLCollector) TestConnection(ctx context.Context, config CollectorConfig) error {
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

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return &ErrCollectionFailed{
			Type:   TypePostgreSQL,
			Reason: fmt.Sprintf("connection test failed: %s", stderr.String()),
			Err:    err,
		}
	}

	return nil
}

// IsAvailable checks if pg_dump is available on the system.
func (c *PostgreSQLCollector) IsAvailable() bool {
	_, err := exec.LookPath("pg_dump")
	return err == nil
}

// GetVersion returns the pg_dump version.
func (c *PostgreSQLCollector) GetVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "pg_dump", "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// ValidatePlatform checks if PostgreSQL backup is supported on this platform.
func (c *PostgreSQLCollector) ValidatePlatform() error {
	// PostgreSQL backup is supported on all platforms where pg_dump is available
	if !c.IsAvailable() {
		return &ErrFeatureUnavailable{
			Feature: "PostgreSQL backup",
			Reason:  "pg_dump not found in PATH",
		}
	}
	return nil
}

// SupportedPlatforms returns the platforms that support PostgreSQL backup.
func (c *PostgreSQLCollector) SupportedPlatforms() []string {
	return []string{"linux", "darwin", "windows"}
}

// CurrentPlatformSupported checks if the current platform is supported.
func (c *PostgreSQLCollector) CurrentPlatformSupported() bool {
	for _, p := range c.SupportedPlatforms() {
		if runtime.GOOS == p {
			return true
		}
	}
	return false
}
