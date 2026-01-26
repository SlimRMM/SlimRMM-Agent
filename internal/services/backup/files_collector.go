package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// SupportsIncremental returns true as files and folders backups support incremental.
func (c *FilesAndFoldersCollector) SupportsIncremental() bool {
	return true
}

// Collect collects files and folders backup.
func (c *FilesAndFoldersCollector) Collect(ctx context.Context, config CollectorConfig) ([]byte, error) {
	result, err := c.CollectIncremental(ctx, config)
	if err != nil {
		return nil, err
	}
	return result.Data, nil
}

// CollectIncremental collects files and folders backup with manifest and delta support.
func (c *FilesAndFoldersCollector) CollectIncremental(ctx context.Context, config CollectorConfig) (*CollectorResult, error) {
	if len(config.Paths) == 0 {
		return nil, &ErrMissingParameter{
			Parameter: "paths",
			Context:   "files_and_folders backup",
		}
	}

	// Log paths being collected
	if c.logger != nil {
		c.logger.Info("files_and_folders collector starting",
			"paths", config.Paths,
			"strategy", config.Strategy,
			"exclude_patterns", config.ExcludePatterns,
		)
	}

	// Build a lookup map from previous manifest for change detection
	previousFiles := make(map[string]FileManifestEntry)
	if config.PreviousManifest != nil {
		for _, entry := range config.PreviousManifest.Files {
			previousFiles[entry.Path] = entry
		}
	}

	// Determine if we're doing incremental/differential backup
	isIncremental := config.Strategy == StrategyIncremental || config.Strategy == StrategyDifferential
	computeHashes := config.ComputeHashes || isIncremental

	// Create tar archive (orchestrator handles compression)
	var buf bytes.Buffer
	tarWriter := tar.NewWriter(&buf)

	// Track files and changes
	var manifestEntries []FileManifestEntry
	var totalFiles int
	var totalSize int64
	var errors []string
	deltaInfo := &DeltaInfo{}
	seenPaths := make(map[string]bool)

	for _, path := range config.Paths {
		err := c.addToTarIncremental(
			ctx, tarWriter, path, config,
			&totalFiles, &totalSize,
			&manifestEntries, previousFiles, seenPaths,
			deltaInfo, isIncremental, computeHashes,
		)
		if err != nil {
			errors = append(errors, err.Error())
			if c.logger != nil {
				c.logger.Warn("error adding path to backup", "path", path, "error", err)
			}
		}
	}

	// Track deleted files (files in previous manifest but not seen in current scan)
	if config.PreviousManifest != nil {
		for path, prevEntry := range previousFiles {
			if !seenPaths[path] {
				deltaInfo.DeletedFiles++
				// Add deleted file entry to manifest
				deletedEntry := prevEntry
				deletedEntry.ChangeType = "deleted"
				manifestEntries = append(manifestEntries, deletedEntry)
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

	// Log collection summary
	if c.logger != nil {
		c.logger.Info("files_and_folders collection complete",
			"total_files", totalFiles,
			"total_size", totalSize,
			"archive_size", buf.Len(),
			"manifest_entries", len(manifestEntries),
		)
	}

	// Log any errors that occurred during collection
	if len(errors) > 0 && c.logger != nil {
		c.logger.Warn("backup completed with errors", "error_count", len(errors), "errors", errors)
	}

	// Build manifest with all metadata (previously stored in JSON wrapper)
	manifest := &FileManifest{
		BackupID:       config.AgentUUID,
		BackupType:     TypeFilesAndFolders,
		Strategy:       config.Strategy,
		BaseBackupID:   config.BaseBackupID,
		ParentBackupID: config.ParentBackupID,
		CreatedAt:      time.Now().UTC(),
		TotalFiles:     totalFiles,
		TotalSize:      totalSize,
		Files:          manifestEntries,
	}

	return &CollectorResult{
		Data:      buf.Bytes(), // Return raw tar data (orchestrator handles compression)
		Manifest:  manifest,
		DeltaInfo: deltaInfo,
	}, nil
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

		// Skip hidden files if not included, but ALWAYS include the root path
		// This allows backing up hidden directories like .ssh when explicitly specified
		isRootPath := filePath == path
		if !config.IncludeHidden && !isRootPath && strings.HasPrefix(info.Name(), ".") {
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

// addToTarIncremental adds files to tar archive with change detection support.
func (c *FilesAndFoldersCollector) addToTarIncremental(
	ctx context.Context,
	tw *tar.Writer,
	path string,
	config CollectorConfig,
	totalFiles *int,
	totalSize *int64,
	manifestEntries *[]FileManifestEntry,
	previousFiles map[string]FileManifestEntry,
	seenPaths map[string]bool,
	deltaInfo *DeltaInfo,
	isIncremental bool,
	computeHashes bool,
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

		// Skip hidden files if not included, but ALWAYS include the root path
		// This allows backing up hidden directories like .ssh when explicitly specified
		isRootPath := filePath == path
		if !config.IncludeHidden && !isRootPath && strings.HasPrefix(info.Name(), ".") {
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

		// Use relative path for manifest and tar
		relPath, err := filepath.Rel(filepath.Dir(path), filePath)
		if err != nil {
			relPath = filePath
		}

		// Mark this path as seen
		seenPaths[relPath] = true

		// Build manifest entry
		entry := FileManifestEntry{
			Path:    relPath,
			Size:    info.Size(),
			ModTime: info.ModTime(),
			Mode:    uint32(info.Mode()),
			IsDir:   info.IsDir(),
		}

		// Handle symlinks
		linkTarget := ""
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(filePath)
			if err == nil {
				entry.IsSymlink = true
				entry.LinkTarget = link
				linkTarget = link
			}
		}

		// Compute hash for regular files if needed
		var fileHash string
		if !info.IsDir() && info.Mode().IsRegular() && computeHashes {
			hash, err := c.computeFileHash(filePath)
			if err == nil {
				fileHash = hash
				entry.SHA256 = hash
			}
		}

		// Determine change type for incremental backups
		shouldInclude := true
		if isIncremental && len(previousFiles) > 0 {
			if prevEntry, exists := previousFiles[relPath]; exists {
				// File existed before - check if changed
				changed := c.hasFileChanged(entry, prevEntry, fileHash)
				if changed {
					entry.ChangeType = "modified"
					deltaInfo.ModifiedFiles++
					deltaInfo.DeltaSize += info.Size()
				} else {
					entry.ChangeType = "unchanged"
					deltaInfo.UnchangedFiles++
					// For incremental, skip unchanged files
					if config.Strategy == StrategyIncremental {
						shouldInclude = false
					}
					// For differential, include all changed since base (handled by parent comparison)
				}
			} else {
				// New file
				entry.ChangeType = "new"
				deltaInfo.NewFiles++
				deltaInfo.DeltaSize += info.Size()
			}
		} else {
			entry.ChangeType = "new"
		}

		// Add entry to manifest (always, even if not included in archive)
		*manifestEntries = append(*manifestEntries, entry)

		// Skip adding to archive if unchanged in incremental mode
		if !shouldInclude {
			return nil
		}

		// Create tar header
		header, err := tar.FileInfoHeader(info, linkTarget)
		if err != nil {
			return nil // Skip files we can't create headers for
		}
		header.Name = relPath

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

// computeFileHash computes the SHA256 hash of a file.
func (c *FilesAndFoldersCollector) computeFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// hasFileChanged determines if a file has changed compared to the previous backup.
func (c *FilesAndFoldersCollector) hasFileChanged(current, previous FileManifestEntry, currentHash string) bool {
	// If we have hashes, use them for reliable comparison
	if currentHash != "" && previous.SHA256 != "" {
		return currentHash != previous.SHA256
	}

	// Fall back to size and modification time comparison
	if current.Size != previous.Size {
		return true
	}

	// Allow some tolerance for mod time (1 second)
	timeDiff := current.ModTime.Sub(previous.ModTime)
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}
	if timeDiff > time.Second {
		return true
	}

	return false
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
