package archive

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultLimits(t *testing.T) {
	limits := DefaultLimits()

	if limits.MaxFileSize != DefaultMaxFileSize {
		t.Errorf("MaxFileSize = %d, want %d", limits.MaxFileSize, DefaultMaxFileSize)
	}
	if limits.MaxTotalSize != DefaultMaxTotalSize {
		t.Errorf("MaxTotalSize = %d, want %d", limits.MaxTotalSize, DefaultMaxTotalSize)
	}
	if limits.MaxFileCount != DefaultMaxFileCount {
		t.Errorf("MaxFileCount = %d, want %d", limits.MaxFileCount, DefaultMaxFileCount)
	}
	if limits.MaxPathLength != DefaultMaxPathLength {
		t.Errorf("MaxPathLength = %d, want %d", limits.MaxPathLength, DefaultMaxPathLength)
	}
}

func TestValidateZipEntry_Safe(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "archive_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test zip file
	zipPath := filepath.Join(tmpDir, "test.zip")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip file: %v", err)
	}

	w := zip.NewWriter(zipFile)
	f, err := w.Create("safe/path/file.txt")
	if err != nil {
		t.Fatalf("failed to create entry: %v", err)
	}
	f.Write([]byte("content"))
	w.Close()
	zipFile.Close()

	// Read and validate
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open zip: %v", err)
	}
	defer reader.Close()

	limits := DefaultLimits()
	for _, entry := range reader.File {
		if err := ValidateZipEntry(tmpDir, entry, limits); err != nil {
			t.Errorf("ValidateZipEntry failed for safe path: %v", err)
		}
	}
}

func TestValidateZipEntry_PathTraversal(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "archive_traversal_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a zip with path traversal
	zipPath := filepath.Join(tmpDir, "malicious.zip")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip file: %v", err)
	}

	w := zip.NewWriter(zipFile)
	f, err := w.Create("../../../etc/passwd")
	if err != nil {
		t.Fatalf("failed to create entry: %v", err)
	}
	f.Write([]byte("fake"))
	w.Close()
	zipFile.Close()

	// Read and validate
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open zip: %v", err)
	}
	defer reader.Close()

	limits := DefaultLimits()
	for _, entry := range reader.File {
		err := ValidateZipEntry(tmpDir, entry, limits)
		if err == nil {
			t.Error("ValidateZipEntry should reject path traversal")
		}
	}
}

func TestValidateZipEntry_PathTooLong(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "archive_long_path_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a zip with very long path
	zipPath := filepath.Join(tmpDir, "long.zip")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip file: %v", err)
	}

	longName := ""
	for i := 0; i < 300; i++ {
		longName += "a"
	}

	w := zip.NewWriter(zipFile)
	f, err := w.Create(longName + ".txt")
	if err != nil {
		t.Fatalf("failed to create entry: %v", err)
	}
	f.Write([]byte("content"))
	w.Close()
	zipFile.Close()

	// Read and validate
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open zip: %v", err)
	}
	defer reader.Close()

	limits := DefaultLimits()
	for _, entry := range reader.File {
		err := ValidateZipEntry(tmpDir, entry, limits)
		if err == nil {
			t.Error("ValidateZipEntry should reject paths that are too long")
		}
	}
}

func TestExtractZip(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "extract_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test zip
	zipPath := filepath.Join(tmpDir, "test.zip")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip file: %v", err)
	}

	w := zip.NewWriter(zipFile)
	f1, _ := w.Create("file1.txt")
	f1.Write([]byte("content1"))
	f2, _ := w.Create("subdir/file2.txt")
	f2.Write([]byte("content2"))
	w.Close()
	zipFile.Close()

	// Extract
	extractDir := filepath.Join(tmpDir, "extracted")
	limits := DefaultLimits()
	if err := ExtractZip(zipPath, extractDir, limits); err != nil {
		t.Fatalf("ExtractZip failed: %v", err)
	}

	// Verify files exist
	if _, err := os.Stat(filepath.Join(extractDir, "file1.txt")); err != nil {
		t.Error("file1.txt should exist")
	}
	if _, err := os.Stat(filepath.Join(extractDir, "subdir", "file2.txt")); err != nil {
		t.Error("subdir/file2.txt should exist")
	}
}

func TestExtractZip_TooManyFiles(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "too_many_files_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a zip with many files
	zipPath := filepath.Join(tmpDir, "many.zip")
	zipFile, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip file: %v", err)
	}

	w := zip.NewWriter(zipFile)
	for i := 0; i < 15; i++ {
		f, _ := w.Create(filepath.Join("dir", "file"+string(rune('0'+i))+".txt"))
		f.Write([]byte("x"))
	}
	w.Close()
	zipFile.Close()

	// Extract with low limit
	extractDir := filepath.Join(tmpDir, "extracted")
	limits := Limits{
		MaxFileSize:   DefaultMaxFileSize,
		MaxTotalSize:  DefaultMaxTotalSize,
		MaxFileCount:  5, // Low limit
		MaxPathLength: DefaultMaxPathLength,
	}

	err = ExtractZip(zipPath, extractDir, limits)
	if err == nil {
		t.Error("ExtractZip should fail when too many files")
	}
}

func TestCreateZip(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "create_zip_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create source files
	srcDir := filepath.Join(tmpDir, "source")
	if err := os.MkdirAll(filepath.Join(srcDir, "subdir"), 0755); err != nil {
		t.Fatalf("failed to create source dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("content1"), 0644); err != nil {
		t.Fatalf("failed to write file1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "subdir", "file2.txt"), []byte("content2"), 0644); err != nil {
		t.Fatalf("failed to write file2: %v", err)
	}

	// Create zip
	zipPath := filepath.Join(tmpDir, "output.zip")
	if err := CreateZip(srcDir, zipPath); err != nil {
		t.Fatalf("CreateZip failed: %v", err)
	}

	// Verify zip was created
	info, err := os.Stat(zipPath)
	if err != nil {
		t.Fatalf("zip file not created: %v", err)
	}
	if info.Size() == 0 {
		t.Error("zip file should have content")
	}

	// Verify zip contents
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open zip: %v", err)
	}
	defer reader.Close()

	if len(reader.File) < 2 {
		t.Errorf("zip should have at least 2 files, got %d", len(reader.File))
	}
}

func TestCreateZip_SingleFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "create_single_zip_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create single source file
	srcFile := filepath.Join(tmpDir, "single.txt")
	if err := os.WriteFile(srcFile, []byte("single file content"), 0644); err != nil {
		t.Fatalf("failed to write source file: %v", err)
	}

	// Create zip
	zipPath := filepath.Join(tmpDir, "single.zip")
	if err := CreateZip(srcFile, zipPath); err != nil {
		t.Fatalf("CreateZip failed: %v", err)
	}

	// Verify
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open zip: %v", err)
	}
	defer reader.Close()

	if len(reader.File) != 1 {
		t.Errorf("zip should have 1 file, got %d", len(reader.File))
	}
}

func TestErrors(t *testing.T) {
	errors := []error{
		ErrZipSlip,
		ErrFileTooLarge,
		ErrTooManyFiles,
		ErrTotalSizeTooLarge,
		ErrPathTooLong,
		ErrInvalidArchive,
	}

	for _, err := range errors {
		if err == nil {
			t.Error("error should not be nil")
		}
		if err.Error() == "" {
			t.Error("error should have a message")
		}
	}
}

func TestConstants(t *testing.T) {
	if DefaultMaxFileSize != 100*1024*1024 {
		t.Errorf("DefaultMaxFileSize = %d, want 100MB", DefaultMaxFileSize)
	}
	if DefaultMaxTotalSize != 1024*1024*1024 {
		t.Errorf("DefaultMaxTotalSize = %d, want 1GB", DefaultMaxTotalSize)
	}
	if DefaultMaxFileCount != 10000 {
		t.Errorf("DefaultMaxFileCount = %d, want 10000", DefaultMaxFileCount)
	}
	if DefaultMaxPathLength != 256 {
		t.Errorf("DefaultMaxPathLength = %d, want 256", DefaultMaxPathLength)
	}
}

func TestExtractZip_InvalidPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "invalid_path_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	limits := DefaultLimits()
	err = ExtractZip("/nonexistent/path.zip", tmpDir, limits)
	if err == nil {
		t.Error("ExtractZip should fail for nonexistent file")
	}
}

func TestCreateZip_InvalidSource(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "invalid_source_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	zipPath := filepath.Join(tmpDir, "test.zip")
	err = CreateZip("/nonexistent/source", zipPath)
	if err == nil {
		t.Error("CreateZip should fail for nonexistent source")
	}
}
