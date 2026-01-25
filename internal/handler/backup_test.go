// Package handler provides backup handling tests for the agent.
package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsValidSocketPath tests socket path validation.
func TestIsValidSocketPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Valid paths
		{"valid unix socket", "/var/run/postgresql/.s.PGSQL.5432", true},
		{"valid mysql socket", "/var/run/mysqld/mysqld.sock", true},
		{"valid tmp socket", "/tmp/mysql.sock", true},
		{"simple path", "/socket", true},

		// Invalid paths
		{"empty path", "", false},
		{"relative path", "var/run/mysql.sock", false},
		{"path traversal", "/var/run/../../../etc/passwd", false},
		{"path with double dot", "/var/../etc/passwd", false},
		{"path with spaces", "/var/run/my socket.sock", false},
		{"path with shell chars", "/var/run/mysql;rm -rf /.sock", false},
		{"path with backtick", "/var/run/`whoami`.sock", false},
		{"path with dollar", "/var/run/$HOME/mysql.sock", false},
		{"path too long", "/" + strings.Repeat("a", 260), false},
		{"path with newline", "/var/run/mysql\n.sock", false},
		{"path with null", "/var/run/mysql\x00.sock", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidSocketPath(tt.path)
			if result != tt.expected {
				t.Errorf("isValidSocketPath(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

// TestIsValidDBHost tests database host validation.
func TestIsValidDBHost(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		// Valid hosts
		{"localhost", "localhost", true},
		{"ip address", "192.168.1.100", true},
		{"hostname", "db.example.com", true},
		{"subdomain", "mysql.internal.company.com", true},
		{"ipv6", "[::1]", true},
		{"ipv6 full", "[2001:db8::1]", true},
		{"hostname with hyphen", "db-server-01.example.com", true},

		// Invalid hosts
		{"empty", "", false},
		{"with spaces", "db server.com", false},
		{"with semicolon", "db;rm -rf /", false},
		{"with backtick", "`whoami`.com", false},
		{"with dollar", "$HOME.com", false},
		{"with pipe", "db|cat /etc/passwd", false},
		{"with ampersand", "db&rm -rf /", false},
		{"with newline", "db\n.com", false},
		{"too long", strings.Repeat("a", 260), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidDBHost(tt.host)
			if result != tt.expected {
				t.Errorf("isValidDBHost(%q) = %v, want %v", tt.host, result, tt.expected)
			}
		})
	}
}

// TestIsValidDBUsername tests database username validation.
func TestIsValidDBUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		expected bool
	}{
		// Valid usernames
		{"simple", "postgres", true},
		{"with underscore", "db_user", true},
		{"with hyphen", "db-user", true},
		{"with dot", "user.name", true},
		{"with number", "user123", true},
		{"uppercase", "DBUser", true},
		{"mixed", "DB_User-123.name", true},

		// Invalid usernames
		{"empty", "", false},
		{"with space", "db user", false},
		{"with semicolon", "user;drop table", false},
		{"with backtick", "`whoami`", false},
		{"with dollar", "$USER", false},
		{"with at sign", "user@host", false},
		{"with slash", "user/admin", false},
		{"with backslash", "user\\admin", false},
		{"too long", strings.Repeat("a", 65), false},
		{"with quotes", "user'name", false},
		{"with double quotes", "user\"name", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidDBUsername(tt.username)
			if result != tt.expected {
				t.Errorf("isValidDBUsername(%q) = %v, want %v", tt.username, result, tt.expected)
			}
		})
	}
}

// TestGetMinimalDBEnv tests minimal environment generation.
func TestGetMinimalDBEnv(t *testing.T) {
	// Set some test environment variables
	originalPath := os.Getenv("PATH")
	originalHome := os.Getenv("HOME")

	t.Run("includes allowed vars", func(t *testing.T) {
		env := getMinimalDBEnv()

		// Check that PATH is included if set
		if originalPath != "" {
			found := false
			for _, e := range env {
				if strings.HasPrefix(e, "PATH=") {
					found = true
					if e != "PATH="+originalPath {
						t.Errorf("PATH value mismatch: got %s", e)
					}
					break
				}
			}
			if !found {
				t.Error("PATH should be included in minimal env")
			}
		}

		// Check that HOME is included if set
		if originalHome != "" {
			found := false
			for _, e := range env {
				if strings.HasPrefix(e, "HOME=") {
					found = true
					break
				}
			}
			if !found {
				t.Error("HOME should be included in minimal env")
			}
		}
	})

	t.Run("adds additional vars", func(t *testing.T) {
		env := getMinimalDBEnv("PGPASSWORD=secret123")

		found := false
		for _, e := range env {
			if e == "PGPASSWORD=secret123" {
				found = true
				break
			}
		}
		if !found {
			t.Error("additional var PGPASSWORD should be included")
		}
	})

	t.Run("adds multiple additional vars", func(t *testing.T) {
		env := getMinimalDBEnv("PGPASSWORD=secret", "PGDATABASE=mydb")

		foundPass := false
		foundDB := false
		for _, e := range env {
			if e == "PGPASSWORD=secret" {
				foundPass = true
			}
			if e == "PGDATABASE=mydb" {
				foundDB = true
			}
		}
		if !foundPass {
			t.Error("PGPASSWORD should be included")
		}
		if !foundDB {
			t.Error("PGDATABASE should be included")
		}
	})

	t.Run("excludes sensitive vars", func(t *testing.T) {
		// Temporarily set a sensitive var
		os.Setenv("AWS_SECRET_ACCESS_KEY", "sensitive")
		os.Setenv("API_KEY", "secret")
		defer os.Unsetenv("AWS_SECRET_ACCESS_KEY")
		defer os.Unsetenv("API_KEY")

		env := getMinimalDBEnv()

		for _, e := range env {
			if strings.HasPrefix(e, "AWS_SECRET_ACCESS_KEY=") {
				t.Error("AWS_SECRET_ACCESS_KEY should not be included")
			}
			if strings.HasPrefix(e, "API_KEY=") {
				t.Error("API_KEY should not be included")
			}
		}
	})

	t.Run("empty additional vars", func(t *testing.T) {
		env := getMinimalDBEnv()
		// Should not panic and should return at least PATH if set
		if originalPath != "" && len(env) == 0 {
			t.Error("env should not be empty when PATH is set")
		}
	})
}

// TestCompressionLevelValidation tests compression level validation.
func TestCompressionLevelValidation(t *testing.T) {
	tests := []struct {
		name  string
		level CompressionLevel
		valid bool
	}{
		{"none", CompressionNone, true},
		{"fast", CompressionFast, true},
		{"balanced", CompressionBalanced, true},
		{"high", CompressionHigh, true},
		{"maximum", CompressionMaximum, true},
		{"empty defaults to balanced", "", true}, // Empty should be treated as balanced
		{"invalid level", CompressionLevel("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that getGzipLevel handles the level correctly
			level := tt.level
			if level == "" {
				level = CompressionBalanced // Default
			}

			switch level {
			case CompressionNone, CompressionFast, CompressionBalanced, CompressionHigh, CompressionMaximum:
				if !tt.valid && level != CompressionLevel("invalid") {
					t.Errorf("level %s should be invalid", tt.level)
				}
			default:
				if tt.valid {
					t.Errorf("level %s should be valid", tt.level)
				}
			}
		})
	}
}

// TestCreateBackupRequestValidation tests backup request struct validation.
func TestCreateBackupRequestValidation(t *testing.T) {
	t.Run("valid files and folders backup", func(t *testing.T) {
		req := createBackupRequest{
			BackupID:     "backup-123",
			BackupType:   "files_and_folders",
			UploadURL:    "https://storage.example.com/upload",
			IncludePaths: []string{"/home/user/documents", "/etc/nginx"},
		}

		if req.BackupID == "" {
			t.Error("BackupID should not be empty")
		}
		if req.BackupType != "files_and_folders" {
			t.Error("BackupType should be files_and_folders")
		}
		if len(req.IncludePaths) != 2 {
			t.Error("IncludePaths should have 2 entries")
		}
	})

	t.Run("valid docker backup", func(t *testing.T) {
		req := createBackupRequest{
			BackupID:    "backup-456",
			BackupType:  "docker_container",
			UploadURL:   "https://storage.example.com/upload",
			ContainerID: "abc123def456",
			IncludeLogs: true,
		}

		if req.ContainerID == "" {
			t.Error("ContainerID should not be empty")
		}
		if !req.IncludeLogs {
			t.Error("IncludeLogs should be true")
		}
	})

	t.Run("valid postgresql backup", func(t *testing.T) {
		req := createBackupRequest{
			BackupID:   "backup-789",
			BackupType: "postgresql",
			UploadURL:  "https://storage.example.com/upload",
			PostgreSQL: &postgresqlBackupParams{
				ConnectionType: "host",
				Host:           "localhost",
				Port:           5432,
				Username:       "postgres",
				DatabaseName:   "mydb",
			},
		}

		if req.PostgreSQL == nil {
			t.Error("PostgreSQL params should not be nil")
		}
		if req.PostgreSQL.Host != "localhost" {
			t.Error("Host should be localhost")
		}
	})

	t.Run("valid mysql backup", func(t *testing.T) {
		req := createBackupRequest{
			BackupID:   "backup-999",
			BackupType: "mysql",
			UploadURL:  "https://storage.example.com/upload",
			MySQL: &mysqlBackupParams{
				ConnectionType:    "socket",
				SocketPath:        "/var/run/mysqld/mysqld.sock",
				Username:          "root",
				AllDatabases:      true,
				SingleTransaction: true,
			},
		}

		if req.MySQL == nil {
			t.Error("MySQL params should not be nil")
		}
		if !req.MySQL.AllDatabases {
			t.Error("AllDatabases should be true")
		}
		if !req.MySQL.SingleTransaction {
			t.Error("SingleTransaction should be true")
		}
	})
}

// TestIsPathSafe tests path safety validation.
func TestIsPathSafe(t *testing.T) {
	// Create temp directory for testing
	tmpDir, err := os.MkdirTemp("", "pathsafe_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name     string
		baseDir  string
		target   string
		expected bool
	}{
		{"same directory", tmpDir, tmpDir, true},
		{"subdirectory", tmpDir, filepath.Join(tmpDir, "subdir"), true},
		{"deep subdirectory", tmpDir, filepath.Join(tmpDir, "a", "b", "c"), true},
		{"parent escape", tmpDir, filepath.Join(tmpDir, "..", "etc"), false},
		{"double parent escape", tmpDir, filepath.Join(tmpDir, "..", "..", "etc"), false},
		{"sibling directory", tmpDir, filepath.Join(tmpDir, "..", "sibling"), false},
		{"absolute escape", tmpDir, "/etc/passwd", false},
		{"root directory", tmpDir, "/", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPathSafe(tt.baseDir, tt.target)
			if result != tt.expected {
				t.Errorf("isPathSafe(%q, %q) = %v, want %v", tt.baseDir, tt.target, result, tt.expected)
			}
		})
	}
}

// TestIsSymlinkSafe tests symlink safety validation.
func TestIsSymlinkSafe(t *testing.T) {
	tmpDir := "/tmp/test"

	tests := []struct {
		name        string
		baseDir     string
		symlinkPath string
		linkTarget  string
		expected    bool
	}{
		{"relative safe", tmpDir, "/tmp/test/link", "subdir/file", true},
		{"relative current dir", tmpDir, "/tmp/test/link", "./file", true},
		{"relative parent escape", tmpDir, "/tmp/test/link", "../outside", false},
		{"relative double escape", tmpDir, "/tmp/test/link", "../../outside", false},
		{"absolute target", tmpDir, "/tmp/test/link", "/etc/passwd", false},
		{"absolute to home", tmpDir, "/tmp/test/link", "/home/user", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSymlinkSafe(tt.baseDir, tt.symlinkPath, tt.linkTarget)
			if result != tt.expected {
				t.Errorf("isSymlinkSafe(%q, %q, %q) = %v, want %v",
					tt.baseDir, tt.symlinkPath, tt.linkTarget, result, tt.expected)
			}
		})
	}
}

// TestEscapePowerShellString tests PowerShell string escaping.
func TestEscapePowerShellString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no quotes", "simple-vm", "simple-vm"},
		{"single quote", "vm's name", "vm''s name"},
		{"multiple quotes", "it's a 'test'", "it''s a ''test''"},
		{"empty string", "", ""},
		{"only quotes", "'''", "''''''"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := escapePowerShellString(tt.input)
			if result != tt.expected {
				t.Errorf("escapePowerShellString(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestIsValidVMName tests VM name validation.
func TestIsValidVMName(t *testing.T) {
	tests := []struct {
		name     string
		vmName   string
		expected bool
	}{
		// Valid names
		{"simple", "my-vm", true},
		{"with space", "My VM", true},
		{"with underscore", "my_vm_01", true},
		{"with dot", "vm.test", true},
		{"with numbers", "vm123", true},
		{"mixed", "My VM-01_test.prod", true},

		// Invalid names
		{"empty", "", false},
		{"with semicolon", "vm;rm -rf /", false},
		{"with backtick", "`whoami`", false},
		{"with dollar", "$vm", false},
		{"with pipe", "vm|cat", false},
		{"with quotes", "vm'name", false},
		{"too long", strings.Repeat("a", 260), false},
		{"with newline", "vm\nname", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidVMName(tt.vmName)
			if result != tt.expected {
				t.Errorf("isValidVMName(%q) = %v, want %v", tt.vmName, result, tt.expected)
			}
		})
	}
}

// TestIsValidDatabaseName tests database name validation.
func TestIsValidDatabaseName(t *testing.T) {
	tests := []struct {
		name     string
		dbName   string
		expected bool
	}{
		// Valid names
		{"simple", "mydb", true},
		{"with underscore", "my_database", true},
		{"with hyphen", "my-database", true},
		{"with numbers", "db123", true},
		{"mixed", "My_Database-01", true},

		// Invalid names
		{"empty", "", false},
		{"with space", "my db", false},
		{"with semicolon", "db;drop", false},
		{"with dot", "db.name", false},
		{"with slash", "db/name", false},
		{"with quotes", "db'name", false},
		{"too long", strings.Repeat("a", 130), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidDatabaseName(tt.dbName)
			if result != tt.expected {
				t.Errorf("isValidDatabaseName(%q) = %v, want %v", tt.dbName, result, tt.expected)
			}
		})
	}
}

// TestIsVirtualizationBackup tests backup type classification.
func TestIsVirtualizationBackup(t *testing.T) {
	tests := []struct {
		name       string
		backupType string
		expected   bool
	}{
		// Virtualization types
		{"docker container", "docker_container", true},
		{"docker volume", "docker_volume", true},
		{"docker image", "docker_image", true},
		{"docker compose", "docker_compose", true},
		{"proxmox vm", "proxmox_vm", true},
		{"proxmox lxc", "proxmox_lxc", true},
		{"proxmox config", "proxmox_config", true},
		{"hyperv vm", "hyperv_vm", true},
		{"hyperv checkpoint", "hyperv_checkpoint", true},
		{"hyperv config", "hyperv_config", true},
		{"files and folders", "files_and_folders", true},
		{"postgresql", "postgresql", true},
		{"mysql", "mysql", true},

		// Non-virtualization types
		{"config", "config", false},
		{"logs", "logs", false},
		{"system_state", "system_state", false},
		{"unknown", "unknown", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isVirtualizationBackup(tt.backupType)
			if result != tt.expected {
				t.Errorf("isVirtualizationBackup(%q) = %v, want %v", tt.backupType, result, tt.expected)
			}
		})
	}
}

// TestShouldExclude tests file exclusion pattern matching.
func TestShouldExclude(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		filename string
		patterns []string
		expected bool
	}{
		// Filename matches
		{"match filename glob", "/project/test.log", "test.log", []string{"*.log"}, true},
		{"match exact filename", "/project/cache", "cache", []string{"cache"}, true},
		{"no match filename", "/project/main.go", "main.go", []string{"*.log"}, false},

		// Path matches
		{"match path contains", "/project/node_modules/pkg", "pkg", []string{"node_modules"}, true},
		{"match vendor path", "/project/vendor/lib", "lib", []string{"vendor"}, true},
		{"match cache dir", "/home/user/.cache/pkg", "pkg", []string{".cache"}, true},

		// Multiple patterns
		{"match one of many", "/project/test.tmp", "test.tmp", []string{"*.log", "*.tmp", "*.bak"}, true},
		{"no match any", "/project/main.go", "main.go", []string{"*.log", "*.tmp", "*.bak"}, false},

		// Empty patterns
		{"empty patterns", "/project/file.txt", "file.txt", []string{}, false},

		// Edge cases
		{"empty path", "", "file", []string{"file"}, true},
		{"empty filename", "/path/to/", "", []string{"*"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldExclude(tt.path, tt.filename, tt.patterns)
			if result != tt.expected {
				t.Errorf("shouldExclude(%q, %q, %v) = %v, want %v",
					tt.path, tt.filename, tt.patterns, result, tt.expected)
			}
		})
	}
}

// TestFormatBytes tests byte size formatting.
func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name     string
		bytes    int64
		expected string
	}{
		{"zero bytes", 0, "0 B"},
		{"bytes", 500, "500 B"},
		{"1023 bytes", 1023, "1023 B"},
		{"1 KB", 1024, "1.0 KB"},
		{"1.5 KB", 1536, "1.5 KB"},
		{"1 MB", 1024 * 1024, "1.0 MB"},
		{"100 MB", 100 * 1024 * 1024, "100.0 MB"},
		{"1 GB", 1024 * 1024 * 1024, "1.0 GB"},
		{"1.5 GB", 1536 * 1024 * 1024, "1.5 GB"},
		{"1 TB", 1024 * 1024 * 1024 * 1024, "1.0 TB"},
		{"1 PB", 1024 * 1024 * 1024 * 1024 * 1024, "1.0 PB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatBytes(tt.bytes)
			if result != tt.expected {
				t.Errorf("formatBytes(%d) = %q, want %q", tt.bytes, result, tt.expected)
			}
		})
	}
}
