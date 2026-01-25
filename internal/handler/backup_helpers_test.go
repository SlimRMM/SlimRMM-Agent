package handler

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParseFilesBackupData(t *testing.T) {
	// Create test archive
	var archiveBuf bytes.Buffer
	gzw := gzip.NewWriter(&archiveBuf)
	tw := tar.NewWriter(gzw)

	// Add a test file to the archive
	content := []byte("test content")
	header := &tar.Header{
		Name: "test.txt",
		Mode: 0644,
		Size: int64(len(content)),
	}
	tw.WriteHeader(header)
	tw.Write(content)
	tw.Close()
	gzw.Close()

	// Create backup data JSON
	backupData := map[string]interface{}{
		"total_files":  5.0,
		"total_size":   1024.0,
		"archive_data": base64.StdEncoding.EncodeToString(archiveBuf.Bytes()),
	}
	data, _ := json.Marshal(backupData)

	// Test parsing
	meta, err := parseFilesBackupData(data)
	if err != nil {
		t.Fatalf("parseFilesBackupData failed: %v", err)
	}

	if meta.TotalFiles != 5 {
		t.Errorf("TotalFiles = %d, want 5", meta.TotalFiles)
	}
	if meta.TotalSize != 1024 {
		t.Errorf("TotalSize = %d, want 1024", meta.TotalSize)
	}
	if len(meta.ArchiveData) == 0 {
		t.Error("ArchiveData is empty")
	}
}

func TestParseFilesBackupDataMissingArchive(t *testing.T) {
	backupData := map[string]interface{}{
		"total_files": 5.0,
	}
	data, _ := json.Marshal(backupData)

	_, err := parseFilesBackupData(data)
	if err == nil {
		t.Error("expected error for missing archive_data")
	}
}

func TestPrepareRestoreTarget(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "restore_target")

	result, err := prepareRestoreTarget(targetPath)
	if err != nil {
		t.Fatalf("prepareRestoreTarget failed: %v", err)
	}

	if result != targetPath {
		t.Errorf("result = %s, want %s", result, targetPath)
	}

	// Verify directory was created
	info, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("target is not a directory")
	}
}

func TestPrepareRestoreTargetEmpty(t *testing.T) {
	result, err := prepareRestoreTarget("")
	if err != nil {
		t.Fatalf("prepareRestoreTarget failed: %v", err)
	}

	// Should create a directory in temp
	if result == "" {
		t.Error("result should not be empty")
	}

	info, err := os.Stat(result)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("target is not a directory")
	}

	// Clean up
	os.RemoveAll(result)
}

func TestBuildRestorePathSet(t *testing.T) {
	paths := []string{"/foo/bar", "/baz"}
	result := buildRestorePathSet(paths)

	if len(result) != 2 {
		t.Errorf("len(result) = %d, want 2", len(result))
	}

	if !result["/foo/bar"] {
		t.Error("/foo/bar should be in path set")
	}
	if !result["/baz"] {
		t.Error("/baz should be in path set")
	}
}

func TestShouldRestoreFile(t *testing.T) {
	tests := []struct {
		name           string
		fileName       string
		restorePathSet map[string]bool
		want           bool
	}{
		{
			name:           "empty path set restores all",
			fileName:       "any/file.txt",
			restorePathSet: map[string]bool{},
			want:           true,
		},
		{
			name:           "exact match",
			fileName:       "foo/bar.txt",
			restorePathSet: map[string]bool{"foo/bar.txt": true},
			want:           true,
		},
		{
			name:           "prefix match",
			fileName:       "foo/bar/baz.txt",
			restorePathSet: map[string]bool{"foo/bar": true},
			want:           true,
		},
		{
			name:           "no match",
			fileName:       "other/file.txt",
			restorePathSet: map[string]bool{"foo/bar": true},
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldRestoreFile(tt.fileName, tt.restorePathSet)
			if result != tt.want {
				t.Errorf("shouldRestoreFile(%q) = %v, want %v", tt.fileName, result, tt.want)
			}
		})
	}
}

func TestRestoreTarArchive(t *testing.T) {
	// Create test archive
	var archiveBuf bytes.Buffer
	gzw := gzip.NewWriter(&archiveBuf)
	tw := tar.NewWriter(gzw)

	// Add a test file
	content := []byte("test content")
	header := &tar.Header{
		Name: "test.txt",
		Mode: 0644,
		Size: int64(len(content)),
	}
	tw.WriteHeader(header)
	tw.Write(content)

	// Add another file
	content2 := []byte("another file")
	header2 := &tar.Header{
		Name: "subdir/file2.txt",
		Mode: 0644,
		Size: int64(len(content2)),
	}
	tw.WriteHeader(header2)
	tw.Write(content2)

	tw.Close()
	gzw.Close()

	// Restore to temp directory
	tmpDir := t.TempDir()

	config := tarArchiveRestoreConfig{
		TargetDir:         tmpDir,
		PreserveStructure: true,
		OverwriteFiles:    true,
		RestorePaths:      nil, // Restore all
	}

	progress, err := restoreTarArchive(archiveBuf.Bytes(), config)
	if err != nil {
		t.Fatalf("restoreTarArchive failed: %v", err)
	}

	if progress.RestoredFiles != 2 {
		t.Errorf("RestoredFiles = %d, want 2", progress.RestoredFiles)
	}

	// Verify files exist
	if _, err := os.Stat(filepath.Join(tmpDir, "test.txt")); err != nil {
		t.Error("test.txt was not restored")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "subdir", "file2.txt")); err != nil {
		t.Error("subdir/file2.txt was not restored")
	}
}

func TestRestoreTarArchiveSelective(t *testing.T) {
	// Create test archive with multiple files
	var archiveBuf bytes.Buffer
	gzw := gzip.NewWriter(&archiveBuf)
	tw := tar.NewWriter(gzw)

	files := []struct {
		name    string
		content string
	}{
		{"include/file1.txt", "included"},
		{"exclude/file2.txt", "excluded"},
		{"include/subdir/file3.txt", "also included"},
	}

	for _, f := range files {
		header := &tar.Header{
			Name: f.name,
			Mode: 0644,
			Size: int64(len(f.content)),
		}
		tw.WriteHeader(header)
		tw.Write([]byte(f.content))
	}

	tw.Close()
	gzw.Close()

	// Restore only "include" directory
	tmpDir := t.TempDir()

	config := tarArchiveRestoreConfig{
		TargetDir:         tmpDir,
		PreserveStructure: true,
		OverwriteFiles:    true,
		RestorePaths:      []string{"include"},
	}

	progress, err := restoreTarArchive(archiveBuf.Bytes(), config)
	if err != nil {
		t.Fatalf("restoreTarArchive failed: %v", err)
	}

	if progress.RestoredFiles != 2 {
		t.Errorf("RestoredFiles = %d, want 2", progress.RestoredFiles)
	}
	if progress.SkippedFiles != 1 {
		t.Errorf("SkippedFiles = %d, want 1", progress.SkippedFiles)
	}

	// Verify included files exist
	if _, err := os.Stat(filepath.Join(tmpDir, "include", "file1.txt")); err != nil {
		t.Error("include/file1.txt was not restored")
	}

	// Verify excluded file does not exist
	if _, err := os.Stat(filepath.Join(tmpDir, "exclude", "file2.txt")); !os.IsNotExist(err) {
		t.Error("exclude/file2.txt should not have been restored")
	}
}
