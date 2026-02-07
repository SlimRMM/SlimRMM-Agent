// Package backup provides database restore functionality for PostgreSQL and MySQL.
package backup

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// PostgreSQLRestorer restores PostgreSQL databases from backups.
type PostgreSQLRestorer struct {
	logger Logger
}

// NewPostgreSQLRestorer creates a new PostgreSQL restorer.
func NewPostgreSQLRestorer(logger Logger) *PostgreSQLRestorer {
	return &PostgreSQLRestorer{logger: logger}
}

// Type returns the backup type.
func (r *PostgreSQLRestorer) Type() BackupType {
	return TypePostgreSQL
}

// Restore restores a PostgreSQL database from backup data.
func (r *PostgreSQLRestorer) Restore(ctx context.Context, data []byte, config RestoreConfig) (*RestoreResult, error) {
	result := &RestoreResult{
		Status: "in_progress",
	}

	// Check if psql is available
	if _, err := exec.LookPath("psql"); err != nil {
		result.Status = "failed"
		result.Error = "psql is not available"
		return result, fmt.Errorf("psql not available: %w", err)
	}

	// Parse backup data
	var backupData struct {
		BackupType   string `json:"backup_type"`
		DatabaseName string `json:"database_name"`
		Host         string `json:"host"`
		Port         int    `json:"port"`
		SchemaOnly   bool   `json:"schema_only"`
		DataOnly     bool   `json:"data_only"`
		DumpData     string `json:"dump_data"`
		DumpSize     int64  `json:"dump_size"`
	}

	if err := json.Unmarshal(data, &backupData); err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to parse backup data: %v", err)
		return result, err
	}

	// Decode the dump data
	dumpData, err := base64.StdEncoding.DecodeString(backupData.DumpData)
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to decode dump data: %v", err)
		return result, err
	}

	// Use config or fallback to backup metadata
	host := config.Host
	if host == "" {
		host = backupData.Host
	}
	port := config.Port
	if port == 0 {
		port = backupData.Port
	}
	if port == 0 {
		port = 5432
	}
	dbName := config.DatabaseName
	if dbName == "" {
		dbName = backupData.DatabaseName
	}

	// Validate required fields
	if dbName == "" {
		result.Status = "failed"
		result.Error = "database name is required for restore"
		return result, fmt.Errorf("database name is required")
	}

	// Build connection arguments
	args := r.buildPsqlArgs(config, host, port, dbName)

	if r.logger != nil {
		r.logger.Info("starting PostgreSQL restore",
			"database", dbName,
			"host", host,
			"port", port,
			"data_size", len(dumpData),
		)
	}

	// Create database if requested
	if config.CreateDatabase {
		if err := r.createDatabase(ctx, config, host, port, dbName); err != nil {
			if r.logger != nil {
				r.logger.Warn("failed to create database, may already exist", "error", err)
			}
		}
	}

	// Execute psql to restore
	cmd := exec.CommandContext(ctx, "psql", args...)
	cmd.Stdin = bytes.NewReader(dumpData)

	// Set minimal environment with password
	if config.Password != "" {
		cmd.Env = minimalEnvForDatabase("PGPASSWORD=" + config.Password)
	} else {
		cmd.Env = minimalEnvForDatabase()
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to restore database: %v - %s", err, string(output))
		return result, err
	}

	result.Status = "completed"
	result.RestoredFiles = 1
	result.TotalFiles = 1
	result.TotalSize = int64(len(dumpData))
	result.RestoredSize = int64(len(dumpData))

	if r.logger != nil {
		r.logger.Info("PostgreSQL database restored successfully",
			"database", dbName,
			"size", len(dumpData),
		)
	}

	return result, nil
}

// buildPsqlArgs builds psql command arguments.
func (r *PostgreSQLRestorer) buildPsqlArgs(config RestoreConfig, host string, port int, dbName string) []string {
	var args []string

	// Connection type
	if config.ConnectionType == "socket" && config.SocketPath != "" {
		args = append(args, "-h", config.SocketPath)
	} else if host != "" {
		args = append(args, "-h", host)
		args = append(args, "-p", fmt.Sprintf("%d", port))
	}

	// Authentication
	if config.Username != "" {
		args = append(args, "-U", config.Username)
	}

	// Database name
	args = append(args, "-d", dbName)

	// Quiet mode, stop on error
	args = append(args, "-q", "-v", "ON_ERROR_STOP=1")

	return args
}

// createDatabase creates the target database if it doesn't exist.
func (r *PostgreSQLRestorer) createDatabase(ctx context.Context, config RestoreConfig, host string, port int, dbName string) error {
	var args []string

	if config.ConnectionType == "socket" && config.SocketPath != "" {
		args = append(args, "-h", config.SocketPath)
	} else if host != "" {
		args = append(args, "-h", host)
		args = append(args, "-p", fmt.Sprintf("%d", port))
	}

	if config.Username != "" {
		args = append(args, "-U", config.Username)
	}

	// Connect to postgres database to create the target database
	args = append(args, "-d", "postgres", "-c", fmt.Sprintf("CREATE DATABASE %s", dbName))

	cmd := exec.CommandContext(ctx, "psql", args...)
	if config.Password != "" {
		cmd.Env = minimalEnvForDatabase("PGPASSWORD=" + config.Password)
	} else {
		cmd.Env = minimalEnvForDatabase()
	}

	return cmd.Run()
}

// MySQLRestorer restores MySQL databases from backups.
type MySQLRestorer struct {
	logger Logger
}

// NewMySQLRestorer creates a new MySQL restorer.
func NewMySQLRestorer(logger Logger) *MySQLRestorer {
	return &MySQLRestorer{logger: logger}
}

// Type returns the backup type.
func (r *MySQLRestorer) Type() BackupType {
	return TypeMySQL
}

// Restore restores a MySQL database from backup data.
func (r *MySQLRestorer) Restore(ctx context.Context, data []byte, config RestoreConfig) (*RestoreResult, error) {
	result := &RestoreResult{
		Status: "in_progress",
	}

	// Check if mysql is available
	if _, err := exec.LookPath("mysql"); err != nil {
		result.Status = "failed"
		result.Error = "mysql is not available"
		return result, fmt.Errorf("mysql not available: %w", err)
	}

	// Parse backup data
	var backupData struct {
		BackupType   string `json:"backup_type"`
		DatabaseName string `json:"database_name"`
		AllDatabases bool   `json:"all_databases"`
		Host         string `json:"host"`
		Port         int    `json:"port"`
		DumpData     string `json:"dump_data"`
		DumpSize     int64  `json:"dump_size"`
	}

	if err := json.Unmarshal(data, &backupData); err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to parse backup data: %v", err)
		return result, err
	}

	// Decode the dump data
	dumpData, err := base64.StdEncoding.DecodeString(backupData.DumpData)
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to decode dump data: %v", err)
		return result, err
	}

	// Use config or fallback to backup metadata
	host := config.Host
	if host == "" {
		host = backupData.Host
	}
	port := config.Port
	if port == 0 {
		port = backupData.Port
	}
	if port == 0 {
		port = 3306
	}
	dbName := config.DatabaseName
	if dbName == "" {
		dbName = backupData.DatabaseName
	}

	// For all_databases backups, database name is not required
	isAllDatabases := backupData.AllDatabases || strings.Contains(string(dumpData), "CREATE DATABASE")

	if dbName == "" && !isAllDatabases {
		result.Status = "failed"
		result.Error = "database name is required for restore"
		return result, fmt.Errorf("database name is required")
	}

	// Build connection arguments
	args := r.buildMysqlArgs(config, host, port, dbName, isAllDatabases)

	if r.logger != nil {
		r.logger.Info("starting MySQL restore",
			"database", dbName,
			"all_databases", isAllDatabases,
			"host", host,
			"port", port,
			"data_size", len(dumpData),
		)
	}

	// Create database if requested and not all_databases
	if config.CreateDatabase && !isAllDatabases && dbName != "" {
		if err := r.createDatabase(ctx, config, host, port, dbName); err != nil {
			if r.logger != nil {
				r.logger.Warn("failed to create database, may already exist", "error", err)
			}
		}
	}

	// Execute mysql to restore
	cmd := exec.CommandContext(ctx, "mysql", args...)
	cmd.Stdin = bytes.NewReader(dumpData)

	// Set minimal environment with password
	if config.Password != "" {
		cmd.Env = minimalEnvForDatabase("MYSQL_PWD=" + config.Password)
	} else {
		cmd.Env = minimalEnvForDatabase()
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to restore database: %v - %s", err, string(output))
		return result, err
	}

	result.Status = "completed"
	result.RestoredFiles = 1
	result.TotalFiles = 1
	result.TotalSize = int64(len(dumpData))
	result.RestoredSize = int64(len(dumpData))

	if r.logger != nil {
		r.logger.Info("MySQL database restored successfully",
			"database", dbName,
			"all_databases", isAllDatabases,
			"size", len(dumpData),
		)
	}

	return result, nil
}

// buildMysqlArgs builds mysql command arguments.
func (r *MySQLRestorer) buildMysqlArgs(config RestoreConfig, host string, port int, dbName string, isAllDatabases bool) []string {
	var args []string

	// Connection type
	if config.ConnectionType == "socket" && config.SocketPath != "" {
		args = append(args, "--socket="+config.SocketPath)
	} else if host != "" {
		args = append(args, "-h", host)
		args = append(args, "-P", fmt.Sprintf("%d", port))
	}

	// Authentication
	if config.Username != "" {
		args = append(args, "-u", config.Username)
	}

	// Database name (only for single database restores)
	if dbName != "" && !isAllDatabases {
		args = append(args, dbName)
	}

	return args
}

// createDatabase creates the target database if it doesn't exist.
func (r *MySQLRestorer) createDatabase(ctx context.Context, config RestoreConfig, host string, port int, dbName string) error {
	var args []string

	if config.ConnectionType == "socket" && config.SocketPath != "" {
		args = append(args, "--socket="+config.SocketPath)
	} else if host != "" {
		args = append(args, "-h", host)
		args = append(args, "-P", fmt.Sprintf("%d", port))
	}

	if config.Username != "" {
		args = append(args, "-u", config.Username)
	}

	args = append(args, "-e", fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s`", dbName))

	cmd := exec.CommandContext(ctx, "mysql", args...)
	if config.Password != "" {
		cmd.Env = minimalEnvForDatabase("MYSQL_PWD=" + config.Password)
	} else {
		cmd.Env = minimalEnvForDatabase()
	}

	return cmd.Run()
}
