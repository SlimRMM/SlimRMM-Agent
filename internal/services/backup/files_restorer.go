// Package backup provides backup collection services for the RMM agent.
package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// FilesAndFoldersRestorer restores files and folders from backups.
type FilesAndFoldersRestorer struct {
	logger Logger
}

// NewFilesAndFoldersRestorer creates a new files and folders restorer.
func NewFilesAndFoldersRestorer(logger Logger) *FilesAndFoldersRestorer {
	return &FilesAndFoldersRestorer{logger: logger}
}

// Type returns the backup type.
func (r *FilesAndFoldersRestorer) Type() BackupType {
	return TypeFilesAndFolders
}

// Restore restores files and folders from backup data.
func (r *FilesAndFoldersRestorer) Restore(ctx context.Context, data []byte, config RestoreConfig) (*RestoreResult, error) {
	result := &RestoreResult{
		Status: "in_progress",
	}

	// Parse backup data
	var backupData struct {
		ArchiveData string   `json:"archive_data"`
		Files       []string `json:"files"`
		Strategy    string   `json:"strategy,omitempty"`
		DeltaInfo   *struct {
			NewFiles      int   `json:"new_files"`
			ModifiedFiles int   `json:"modified_files"`
			DeletedFiles  int   `json:"deleted_files"`
		} `json:"delta_info,omitempty"`
		DeletedPaths []string `json:"deleted_paths,omitempty"`
	}
	if err := json.Unmarshal(data, &backupData); err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to parse backup data: %v", err)
		return result, err
	}

	// Handle deleted files for incremental restore
	if config.ApplyDeltas && !config.SkipDeletedFiles && len(backupData.DeletedPaths) > 0 {
		targetPath := config.RestoreTarget
		if targetPath == "" {
			targetPath = "."
		}
		for _, deletedPath := range backupData.DeletedPaths {
			fullPath := filepath.Join(targetPath, deletedPath)
			if isRestorePathSafe(targetPath, fullPath) {
				if err := os.Remove(fullPath); err == nil {
					result.DeletedFilesCount++
					if r.logger != nil {
						r.logger.Info("Deleted file from incremental restore", "path", deletedPath)
					}
				}
			}
		}
	}

	// Decode the archive data
	archiveData, err := base64.StdEncoding.DecodeString(backupData.ArchiveData)
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to decode archive data: %v", err)
		return result, err
	}

	// Determine restore target
	targetPath := config.RestoreTarget
	if targetPath == "" {
		targetPath = "."
	}

	// Ensure target directory exists
	if err := os.MkdirAll(targetPath, 0755); err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("failed to create restore target: %v", err)
		return result, err
	}

	// Build set of paths to restore
	restorePathSet := make(map[string]bool)
	for _, p := range config.RestorePaths {
		restorePathSet[p] = true
	}

	// Extract tar archive
	tarReader := tar.NewReader(bytes.NewReader(archiveData))
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			result.FailedFiles++
			continue
		}

		result.TotalFiles++

		// Check if this file should be restored
		if len(restorePathSet) > 0 && !shouldRestoreFileByPath(header.Name, restorePathSet) {
			result.SkippedFiles++
			continue
		}

		// Determine destination path
		destPath := filepath.Join(targetPath, header.Name)
		if config.PreserveStructure {
			destPath = filepath.Join(targetPath, header.Name)
		} else {
			destPath = filepath.Join(targetPath, filepath.Base(header.Name))
		}

		// Check path safety
		if !isRestorePathSafe(targetPath, destPath) {
			result.SkippedFiles++
			if r.logger != nil {
				r.logger.Warn("Skipping unsafe path", "path", header.Name)
			}
			continue
		}

		// Handle directories
		if header.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(destPath, os.FileMode(header.Mode)); err != nil {
				result.FailedFiles++
				continue
			}
			result.RestoredFiles++
			continue
		}

		// Handle regular files
		if header.Typeflag == tar.TypeReg {
			// Check if file exists and overwrite is disabled
			if _, err := os.Stat(destPath); err == nil && !config.OverwriteFiles {
				result.SkippedFiles++
				continue
			}

			// Create parent directories
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				result.FailedFiles++
				continue
			}

			// Create file
			file, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				result.FailedFiles++
				continue
			}

			written, err := io.Copy(file, tarReader)
			file.Close()
			if err != nil {
				result.FailedFiles++
				continue
			}

			result.RestoredFiles++
			result.RestoredSize += written
		}
	}

	result.Status = "completed"
	if result.FailedFiles > 0 {
		result.Status = "completed_with_errors"
	}

	if r.logger != nil {
		r.logger.Info("Files restore completed",
			"restored", result.RestoredFiles,
			"skipped", result.SkippedFiles,
			"failed", result.FailedFiles,
		)
	}

	return result, nil
}

// shouldRestoreFileByPath checks if a file should be restored based on the path set.
func shouldRestoreFileByPath(fileName string, pathSet map[string]bool) bool {
	// Check exact match
	if pathSet[fileName] {
		return true
	}

	// Check if any path is a prefix
	for path := range pathSet {
		if len(fileName) >= len(path) && fileName[:len(path)] == path {
			return true
		}
	}

	return false
}

// isRestorePathSafe validates that the destination path is within the target directory.
func isRestorePathSafe(targetDir, destPath string) bool {
	absTarget, err := filepath.Abs(targetDir)
	if err != nil {
		return false
	}

	absDest, err := filepath.Abs(destPath)
	if err != nil {
		return false
	}

	// Ensure destination is within target
	rel, err := filepath.Rel(absTarget, absDest)
	if err != nil {
		return false
	}

	// Check for path traversal
	if len(rel) > 0 && rel[0] == '.' && rel[1] == '.' {
		return false
	}

	return true
}
