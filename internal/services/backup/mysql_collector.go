package backup

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"time"
)

// MySQLCollector collects MySQL/MariaDB database backups.
type MySQLCollector struct{}

// NewMySQLCollector creates a new MySQL collector.
func NewMySQLCollector() *MySQLCollector {
	return &MySQLCollector{}
}

// Type returns the backup type.
func (c *MySQLCollector) Type() BackupType {
	return TypeMySQL
}

// Collect collects a MySQL database backup using mysqldump.
func (c *MySQLCollector) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	// Validate required parameters
	if config.Host == "" && config.SocketPath == "" {
		return nil, &ErrMissingParameter{
			Parameter: "host or socket_path",
			Context:   "mysql backup",
		}
	}

	if config.DatabaseName == "" && !config.AllDatabases {
		return nil, &ErrMissingParameter{
			Parameter: "database_name or all_databases",
			Context:   "mysql backup",
		}
	}

	// Build mysqldump arguments
	args := c.buildMysqldumpArgs(config)

	// Execute mysqldump
	cmd := exec.CommandContext(ctx, "mysqldump", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, &ErrCollectionFailed{
			Type:   TypeMySQL,
			Reason: fmt.Sprintf("mysqldump failed: %s", stderr.String()),
			Err:    err,
		}
	}

	// Build response
	result := map[string]interface{}{
		"backup_type":   "mysql",
		"database_name": config.DatabaseName,
		"all_databases": config.AllDatabases,
		"host":          config.Host,
		"port":          config.Port,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
		"dump_data":     base64.StdEncoding.EncodeToString(stdout.Bytes()),
		"dump_size":     stdout.Len(),
	}

	return json.Marshal(result)
}

// buildMysqldumpArgs builds the command line arguments for mysqldump.
func (c *MySQLCollector) buildMysqldumpArgs(config CollectorConfig) []string {
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
	if config.Password != "" {
		// Note: Passing password via command line is not ideal but matches
		// the original implementation. Consider using --defaults-extra-file
		// for production use.
		args = append(args, "-p"+config.Password)
	}

	// Dump options
	// Always use single-transaction for InnoDB tables to ensure consistency
	args = append(args, "--single-transaction")

	// Database selection
	if config.AllDatabases {
		args = append(args, "--all-databases")
	} else if config.DatabaseName != "" {
		args = append(args, config.DatabaseName)
	}

	return args
}

// TestConnection tests the MySQL connection.
func (c *MySQLCollector) TestConnection(ctx context.Context, config CollectorConfig) error {
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
	if config.Password != "" {
		args = append(args, "-p"+config.Password)
	}

	if config.DatabaseName != "" {
		args = append(args, config.DatabaseName)
	}

	cmd := exec.CommandContext(ctx, "mysql", args...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return &ErrCollectionFailed{
			Type:   TypeMySQL,
			Reason: fmt.Sprintf("connection test failed: %s", stderr.String()),
			Err:    err,
		}
	}

	return nil
}

// IsAvailable checks if mysqldump is available on the system.
func (c *MySQLCollector) IsAvailable() bool {
	_, err := exec.LookPath("mysqldump")
	return err == nil
}

// GetVersion returns the mysqldump version.
func (c *MySQLCollector) GetVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "mysqldump", "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// ValidatePlatform checks if MySQL backup is supported on this platform.
func (c *MySQLCollector) ValidatePlatform() error {
	if !c.IsAvailable() {
		return &ErrFeatureUnavailable{
			Feature: "MySQL backup",
			Reason:  "mysqldump not found in PATH",
		}
	}
	return nil
}

// SupportedPlatforms returns the platforms that support MySQL backup.
func (c *MySQLCollector) SupportedPlatforms() []string {
	return []string{"linux", "darwin", "windows"}
}

// CurrentPlatformSupported checks if the current platform is supported.
func (c *MySQLCollector) CurrentPlatformSupported() bool {
	for _, p := range c.SupportedPlatforms() {
		if runtime.GOOS == p {
			return true
		}
	}
	return false
}
