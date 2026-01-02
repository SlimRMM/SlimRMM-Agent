// Package archive provides secure archive handling with ZIP-Slip prevention.
// It validates archive entries to prevent path traversal attacks.
package archive

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	DefaultMaxFileSize    = 100 * 1024 * 1024  // 100 MB per file
	DefaultMaxTotalSize   = 1024 * 1024 * 1024 // 1 GB total
	DefaultMaxFileCount   = 10000
	DefaultMaxPathLength  = 256
)

var (
	ErrZipSlip         = errors.New("zip slip: path traversal detected")
	ErrFileTooLarge    = errors.New("file exceeds maximum size")
	ErrTooManyFiles    = errors.New("archive contains too many files")
	ErrTotalSizeTooLarge = errors.New("archive total size exceeds limit")
	ErrPathTooLong     = errors.New("file path too long")
	ErrInvalidArchive  = errors.New("invalid archive")
)

// Limits defines extraction limits.
type Limits struct {
	MaxFileSize   int64
	MaxTotalSize  int64
	MaxFileCount  int
	MaxPathLength int
}

// DefaultLimits returns the default extraction limits.
func DefaultLimits() Limits {
	return Limits{
		MaxFileSize:   DefaultMaxFileSize,
		MaxTotalSize:  DefaultMaxTotalSize,
		MaxFileCount:  DefaultMaxFileCount,
		MaxPathLength: DefaultMaxPathLength,
	}
}

// ValidateZipEntry checks if a zip entry is safe to extract.
func ValidateZipEntry(destDir string, entry *zip.File, limits Limits) error {
	// Check path length
	if len(entry.Name) > limits.MaxPathLength {
		return fmt.Errorf("%w: %s", ErrPathTooLong, entry.Name)
	}

	// Check for absolute paths
	if filepath.IsAbs(entry.Name) {
		return fmt.Errorf("%w: absolute path in archive", ErrZipSlip)
	}

	// Clean the path and check for traversal
	cleanName := filepath.Clean(entry.Name)
	if strings.HasPrefix(cleanName, "..") || strings.Contains(cleanName, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("%w: %s", ErrZipSlip, entry.Name)
	}

	// Construct the destination path
	destPath := filepath.Join(destDir, cleanName)

	// Ensure the destination is within the target directory
	if !strings.HasPrefix(destPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
		return fmt.Errorf("%w: %s escapes destination", ErrZipSlip, entry.Name)
	}

	// Check file size (for regular files)
	if !entry.FileInfo().IsDir() && int64(entry.UncompressedSize64) > limits.MaxFileSize {
		return fmt.Errorf("%w: %s (%d bytes)", ErrFileTooLarge, entry.Name, entry.UncompressedSize64)
	}

	return nil
}

// ExtractZip safely extracts a zip archive to the destination directory.
func ExtractZip(zipPath, destDir string, limits Limits) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("opening zip: %w", err)
	}
	defer reader.Close()

	// Check file count
	if len(reader.File) > limits.MaxFileCount {
		return fmt.Errorf("%w: %d files", ErrTooManyFiles, len(reader.File))
	}

	// Calculate total uncompressed size
	var totalSize uint64
	for _, f := range reader.File {
		totalSize += f.UncompressedSize64
	}
	if int64(totalSize) > limits.MaxTotalSize {
		return fmt.Errorf("%w: %d bytes", ErrTotalSizeTooLarge, totalSize)
	}

	// Create destination directory
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("creating destination: %w", err)
	}

	// Extract files
	for _, f := range reader.File {
		if err := ValidateZipEntry(destDir, f, limits); err != nil {
			return err
		}

		destPath := filepath.Join(destDir, filepath.Clean(f.Name))

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(destPath, f.Mode()); err != nil {
				return fmt.Errorf("creating directory: %w", err)
			}
			continue
		}

		if err := extractFile(f, destPath); err != nil {
			return err
		}
	}

	return nil
}

// extractFile extracts a single file from the archive.
func extractFile(f *zip.File, destPath string) error {
	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("creating parent directory: %w", err)
	}

	// Open source file
	src, err := f.Open()
	if err != nil {
		return fmt.Errorf("opening archive entry: %w", err)
	}
	defer src.Close()

	// Create destination file
	dst, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer dst.Close()

	// Copy contents
	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("extracting file: %w", err)
	}

	return nil
}

// CreateZip creates a zip archive from the source path.
func CreateZip(srcPath, zipPath string) error {
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return fmt.Errorf("creating zip file: %w", err)
	}
	defer zipFile.Close()

	writer := zip.NewWriter(zipFile)
	defer writer.Close()

	info, err := os.Stat(srcPath)
	if err != nil {
		return fmt.Errorf("stat source: %w", err)
	}

	var baseDir string
	if info.IsDir() {
		baseDir = filepath.Base(srcPath)
	}

	return filepath.Walk(srcPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Create header
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return fmt.Errorf("creating header: %w", err)
		}

		// Set relative path
		if baseDir != "" {
			relPath, err := filepath.Rel(filepath.Dir(srcPath), path)
			if err != nil {
				return err
			}
			header.Name = relPath
		} else {
			header.Name = filepath.Base(path)
		}

		if info.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Deflate
		}

		// Create entry
		w, err := writer.CreateHeader(header)
		if err != nil {
			return fmt.Errorf("creating entry: %w", err)
		}

		if info.IsDir() {
			return nil
		}

		// Copy file contents
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("opening file: %w", err)
		}
		defer f.Close()

		_, err = io.Copy(w, f)
		return err
	})
}
