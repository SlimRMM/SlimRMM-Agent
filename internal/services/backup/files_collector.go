package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FilesAndFoldersCollector collects files and folders backups.
type FilesAndFoldersCollector struct {
	config AgentConfig
	logger Logger
}

// NewFilesAndFoldersCollector creates a new files and folders collector.
func NewFilesAndFoldersCollector(config AgentConfig, logger Logger) *FilesAndFoldersCollector {
	return &FilesAndFoldersCollector{config: config, logger: logger}
}

// Type returns the backup type.
func (c *FilesAndFoldersCollector) Type() BackupType {
	return TypeFilesAndFolders
}

// Collect collects files and folders backup.
func (c *FilesAndFoldersCollector) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	if len(config.Paths) == 0 {
		return nil, &ErrMissingParameter{
			Parameter: "paths",
			Context:   "files_and_folders backup",
		}
	}

	// Create tar.gz archive
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)

	var totalFiles int
	var totalSize int64
	var errors []string

	for _, path := range config.Paths {
		err := c.addToTar(ctx, tarWriter, path, config, &totalFiles, &totalSize)
		if err != nil {
			errors = append(errors, err.Error())
			if c.logger != nil {
				c.logger.Warn("error adding path to backup", "path", path, "error", err)
			}
		}
	}

	if err := tarWriter.Close(); err != nil {
		return nil, &ErrCollectionFailed{
			Type:   TypeFilesAndFolders,
			Reason: "failed to close tar writer",
			Err:    err,
		}
	}

	if err := gzWriter.Close(); err != nil {
		return nil, &ErrCollectionFailed{
			Type:   TypeFilesAndFolders,
			Reason: "failed to close gzip writer",
			Err:    err,
		}
	}

	backupData := map[string]interface{}{
		"backup_type":   "files_and_folders",
		"paths":         config.Paths,
		"total_files":   totalFiles,
		"total_size":    totalSize,
		"archive_size":  buf.Len(),
		"archive_data":  base64.StdEncoding.EncodeToString(buf.Bytes()),
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
		"agent_uuid":    config.AgentUUID,
	}

	if len(errors) > 0 {
		backupData["errors"] = errors
	}

	return json.Marshal(backupData)
}

// addToTar adds a file or directory to the tar archive.
func (c *FilesAndFoldersCollector) addToTar(
	ctx context.Context,
	tw *tar.Writer,
	path string,
	config CollectorConfig,
	totalFiles *int,
	totalSize *int64,
) error {
	return filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err != nil {
			return nil // Skip files we can't access
		}

		// Skip hidden files if not included
		if !config.IncludeHidden && strings.HasPrefix(info.Name(), ".") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Check exclude patterns
		for _, pattern := range config.ExcludePatterns {
			if matched, _ := filepath.Match(pattern, info.Name()); matched {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}

		// Check file size limit
		if !info.IsDir() && config.MaxFileSize > 0 && info.Size() > config.MaxFileSize {
			return nil
		}

		// Create tar header
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return nil // Skip files we can't create headers for
		}

		// Use relative path
		relPath, err := filepath.Rel(filepath.Dir(path), filePath)
		if err != nil {
			relPath = filePath
		}
		header.Name = relPath

		// Handle symlinks
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(filePath)
			if err != nil {
				return nil
			}
			header.Linkname = link
		}

		if err := tw.WriteHeader(header); err != nil {
			return nil
		}

		// Write file content
		if !info.IsDir() && info.Mode().IsRegular() {
			file, err := os.Open(filePath)
			if err != nil {
				return nil
			}
			defer file.Close()

			if _, err := io.Copy(tw, file); err != nil {
				return nil
			}

			*totalFiles++
			*totalSize += info.Size()
		}

		return nil
	})
}

// isPathSafe validates that a file path is safely contained within the target directory.
func isPathSafe(baseDir, targetPath string) bool {
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return false
	}
	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return false
	}

	absBase = filepath.Clean(absBase)
	absTarget = filepath.Clean(absTarget)

	if !strings.HasPrefix(absTarget, absBase+string(filepath.Separator)) && absTarget != absBase {
		return false
	}

	return true
}

// isSymlinkSafe validates that a symlink target doesn't escape the base directory.
func isSymlinkSafe(baseDir, symlinkPath, linkTarget string) bool {
	if filepath.IsAbs(linkTarget) {
		return false
	}

	symlinkDir := filepath.Dir(symlinkPath)
	targetPath := filepath.Join(symlinkDir, linkTarget)

	return isPathSafe(baseDir, targetPath)
}
