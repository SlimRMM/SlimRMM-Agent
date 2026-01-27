// Package handler provides backup helper functions.
package handler

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// maxTarFileCount is the maximum number of files allowed in a tar archive.
// This prevents DoS attacks via tar archives with millions of small files.
const maxTarFileCount = 1_000_000

// filesBackupMetadata contains metadata from a files_and_folders backup.
type filesBackupMetadata struct {
	TotalFiles  int
	TotalSize   int64
	ArchiveData []byte
}

// parseFilesBackupData parses the backup data and extracts metadata and archive data.
// It supports two formats:
// 1. Raw tar archive data (current format from collectFilesAndFoldersBackup)
// 2. JSON-wrapped format with base64-encoded archive (legacy format)
func parseFilesBackupData(data []byte) (*filesBackupMetadata, error) {
	meta := &filesBackupMetadata{}

	// First, try to detect if this is raw tar data by checking for tar header magic
	// Tar archives start with a file entry, and the magic is at offset 257
	if len(data) > 262 && (string(data[257:262]) == "ustar" || data[0] != '{') {
		// This is raw tar data - count files and size by scanning the archive
		totalFiles, totalSize := countTarContents(data)
		meta.TotalFiles = totalFiles
		meta.TotalSize = totalSize
		meta.ArchiveData = data
		return meta, nil
	}

	// Try parsing as JSON (legacy format)
	var backupData map[string]interface{}
	if err := json.Unmarshal(data, &backupData); err != nil {
		// Not JSON either - assume it's raw tar data
		totalFiles, totalSize := countTarContents(data)
		meta.TotalFiles = totalFiles
		meta.TotalSize = totalSize
		meta.ArchiveData = data
		return meta, nil
	}

	// Extract file count for progress calculation
	if totalFiles, ok := backupData["total_files"].(float64); ok {
		meta.TotalFiles = int(totalFiles)
	}
	if totalSize, ok := backupData["total_size"].(float64); ok {
		meta.TotalSize = int64(totalSize)
	}

	// Get the archive data
	archiveDataB64, ok := backupData["archive_data"].(string)
	if !ok {
		return nil, fmt.Errorf("no archive_data found in backup")
	}

	var err error
	meta.ArchiveData, err = base64.StdEncoding.DecodeString(archiveDataB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode archive data: %w", err)
	}

	return meta, nil
}

// countTarContents scans a tar archive and returns file count and total size.
// Stops counting at maxTarFileCount to prevent DoS via malicious archives.
func countTarContents(data []byte) (int, int64) {
	reader := tar.NewReader(bytes.NewReader(data))
	var totalFiles int
	var totalSize int64

	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		if header.Typeflag == tar.TypeReg {
			totalFiles++
			totalSize += header.Size

			// Prevent DoS via archives with excessive file counts
			if totalFiles >= maxTarFileCount {
				break
			}
		}
	}

	return totalFiles, totalSize
}

// prepareRestoreTarget determines and creates the target directory for restore.
func prepareRestoreTarget(targetPath string) (string, error) {
	if targetPath == "" {
		targetPath = filepath.Join(os.TempDir(), "restore_"+time.Now().Format("20060102150405"))
	}

	if err := os.MkdirAll(targetPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create target directory: %w", err)
	}

	return targetPath, nil
}

// buildRestorePathSet builds a set of paths to restore for selective restore operations.
func buildRestorePathSet(paths []string) map[string]bool {
	pathSet := make(map[string]bool)
	for _, p := range paths {
		pathSet[filepath.ToSlash(p)] = true
	}
	return pathSet
}

// shouldRestoreFile checks if a file should be restored based on selective restore paths.
func shouldRestoreFile(fileName string, restorePathSet map[string]bool) bool {
	if len(restorePathSet) == 0 {
		return true // No selective restore, restore everything
	}

	normalizedName := filepath.ToSlash(fileName)
	for restorePath := range restorePathSet {
		if normalizedName == restorePath ||
			strings.HasPrefix(normalizedName, restorePath+"/") ||
			strings.HasPrefix(restorePath, normalizedName+"/") {
			return true
		}
	}
	return false
}

// tarEntryRestoreResult represents the result of restoring a single tar entry.
type tarEntryRestoreResult struct {
	Restored bool
	Skipped  bool
	Failed   bool
	Size     int64
	Error    error
}

// tarEntryRestoreConfig contains configuration for restoring a tar entry.
type tarEntryRestoreConfig struct {
	TargetDir         string
	PreserveStructure bool
	OverwriteFiles    bool
	Logger            *slog.Logger
}

// restoreTarEntry restores a single tar entry to the target directory.
func restoreTarEntry(header *tar.Header, reader io.Reader, config tarEntryRestoreConfig) tarEntryRestoreResult {
	result := tarEntryRestoreResult{}

	// Determine target path
	var targetPath string
	if config.PreserveStructure {
		targetPath = filepath.Join(config.TargetDir, header.Name)
	} else {
		targetPath = filepath.Join(config.TargetDir, filepath.Base(header.Name))
	}

	// Validate path is within target directory (prevent path traversal attacks)
	if !isPathSafe(config.TargetDir, targetPath) {
		if config.Logger != nil {
			config.Logger.Warn("skipping file with unsafe path", "path", header.Name, "target", targetPath)
		}
		result.Skipped = true
		return result
	}

	// Create parent directories
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		if config.Logger != nil {
			config.Logger.Warn("failed to create directory", "path", filepath.Dir(targetPath), "error", err)
		}
		result.Failed = true
		result.Error = err
		return result
	}

	// Check if file exists and overwrite setting
	if _, err := os.Stat(targetPath); err == nil && !config.OverwriteFiles {
		result.Skipped = true
		return result
	}

	switch header.Typeflag {
	case tar.TypeDir:
		if err := os.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil {
			if config.Logger != nil {
				config.Logger.Warn("failed to create directory", "path", targetPath, "error", err)
			}
			result.Failed = true
			result.Error = err
		} else {
			result.Restored = true
		}

	case tar.TypeReg:
		file, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
		if err != nil {
			if config.Logger != nil {
				config.Logger.Warn("failed to create file", "path", targetPath, "error", err)
			}
			result.Failed = true
			result.Error = err
			return result
		}

		written, err := io.Copy(file, reader)
		file.Close()
		if err != nil {
			if config.Logger != nil {
				config.Logger.Warn("failed to write file", "path", targetPath, "error", err)
			}
			result.Failed = true
			result.Error = err
			return result
		}

		result.Restored = true
		result.Size = written

		// Set modification time
		os.Chtimes(targetPath, header.AccessTime, header.ModTime)

	case tar.TypeSymlink:
		// Validate symlink target doesn't escape the restore directory
		if !isSymlinkSafe(config.TargetDir, targetPath, header.Linkname) {
			if config.Logger != nil {
				config.Logger.Warn("skipping symlink with unsafe target", "path", targetPath, "target", header.Linkname)
			}
			result.Skipped = true
			return result
		}

		if err := os.Symlink(header.Linkname, targetPath); err != nil {
			if config.Logger != nil {
				config.Logger.Warn("failed to create symlink", "path", targetPath, "error", err)
			}
			result.Failed = true
			result.Error = err
			return result
		}

		// Post-creation verification: read back symlink and verify target
		// This mitigates TOCTOU race conditions by detecting tampering
		actualTarget, err := os.Readlink(targetPath)
		if err != nil || actualTarget != header.Linkname {
			if config.Logger != nil {
				config.Logger.Warn("symlink verification failed, removing",
					"path", targetPath,
					"expected", header.Linkname,
					"actual", actualTarget,
				)
			}
			os.Remove(targetPath)
			result.Failed = true
			result.Error = fmt.Errorf("symlink verification failed")
			return result
		}

		result.Restored = true
	}

	return result
}

// restoreArchiveProgress tracks progress during archive restoration.
type restoreArchiveProgress struct {
	RestoredFiles int
	SkippedFiles  int
	FailedFiles   int
	RestoredSize  int64
}

// tarArchiveRestoreConfig contains configuration for restoring a tar archive.
type tarArchiveRestoreConfig struct {
	TargetDir         string
	PreserveStructure bool
	OverwriteFiles    bool
	RestorePaths      []string
	Logger            *slog.Logger
	ProgressCallback  func(progress restoreArchiveProgress)
	ProgressInterval  time.Duration
}

// restoreTarArchive extracts a gzipped tar archive to the target directory.
func restoreTarArchive(archiveData []byte, config tarArchiveRestoreConfig) (restoreArchiveProgress, error) {
	progress := restoreArchiveProgress{}

	// Build selective restore path set
	restorePathSet := buildRestorePathSet(config.RestorePaths)
	selectiveRestore := len(config.RestorePaths) > 0

	// Open gzip reader
	gzReader, err := gzip.NewReader(bytes.NewReader(archiveData))
	if err != nil {
		return progress, fmt.Errorf("failed to open gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Open tar reader
	tarReader := tar.NewReader(gzReader)

	// Track progress interval
	lastProgressUpdate := time.Now()
	progressInterval := config.ProgressInterval
	if progressInterval == 0 {
		progressInterval = 500 * time.Millisecond
	}

	entryConfig := tarEntryRestoreConfig{
		TargetDir:         config.TargetDir,
		PreserveStructure: config.PreserveStructure,
		OverwriteFiles:    config.OverwriteFiles,
		Logger:            config.Logger,
	}

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return progress, fmt.Errorf("failed to read tar header: %w", err)
		}

		// Check if this file should be restored (selective restore)
		if selectiveRestore && !shouldRestoreFile(header.Name, restorePathSet) {
			progress.SkippedFiles++
			continue
		}

		// Restore the entry
		result := restoreTarEntry(header, tarReader, entryConfig)
		if result.Restored {
			progress.RestoredFiles++
			progress.RestoredSize += result.Size
		} else if result.Skipped {
			progress.SkippedFiles++
		} else if result.Failed {
			progress.FailedFiles++
		}

		// Report progress periodically
		if config.ProgressCallback != nil && time.Since(lastProgressUpdate) > progressInterval {
			config.ProgressCallback(progress)
			lastProgressUpdate = time.Now()
		}
	}

	return progress, nil
}
