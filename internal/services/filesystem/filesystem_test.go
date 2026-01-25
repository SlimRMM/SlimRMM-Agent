package filesystem

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNew(t *testing.T) {
	svc := New()
	if svc == nil {
		t.Fatal("New returned nil")
	}
}

func TestGetDefault(t *testing.T) {
	svc1 := GetDefault()
	if svc1 == nil {
		t.Fatal("GetDefault returned nil")
	}

	// Should return same instance
	svc2 := GetDefault()
	if svc1 != svc2 {
		t.Error("GetDefault should return same instance")
	}
}

func TestCreateFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "filesystem_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	svc := New()
	path := filepath.Join(tmpDir, "test.txt")

	f, err := svc.CreateFile(path)
	if err != nil {
		t.Fatalf("CreateFile failed: %v", err)
	}
	f.Close()

	if !svc.FileExists(path) {
		t.Error("file should exist after CreateFile")
	}
}

func TestOpenFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "filesystem_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	svc := New()
	path := filepath.Join(tmpDir, "test.txt")

	// Create file
	f, err := svc.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}

	n, err := f.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != 5 {
		t.Errorf("wrote %d bytes, want 5", n)
	}
	f.Close()

	// Verify file exists
	if !svc.FileExists(path) {
		t.Error("file should exist")
	}
}

func TestOpenRead(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "filesystem_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	svc := New()
	path := filepath.Join(tmpDir, "test.txt")
	content := []byte("hello world")

	// Create file first
	if err := svc.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Open for reading
	f, err := svc.OpenRead(path)
	if err != nil {
		t.Fatalf("OpenRead failed: %v", err)
	}
	defer f.Close()

	buf := make([]byte, 11)
	n, err := f.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 11 {
		t.Errorf("read %d bytes, want 11", n)
	}
	if string(buf) != "hello world" {
		t.Errorf("content = %q, want 'hello world'", string(buf))
	}
}

func TestFileExists(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "filesystem_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	svc := New()
	path := filepath.Join(tmpDir, "test.txt")

	// File doesn't exist yet
	if svc.FileExists(path) {
		t.Error("file should not exist yet")
	}

	// Create file
	if err := svc.WriteFile(path, []byte("test"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Now file exists
	if !svc.FileExists(path) {
		t.Error("file should exist now")
	}
}

func TestStat(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "filesystem_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	svc := New()
	path := filepath.Join(tmpDir, "test.txt")
	content := []byte("hello")

	if err := svc.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	info, err := svc.Stat(path)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	if info.Size() != 5 {
		t.Errorf("Size = %d, want 5", info.Size())
	}
	if info.Name() != "test.txt" {
		t.Errorf("Name = %s, want test.txt", info.Name())
	}
	if info.IsDir() {
		t.Error("should not be a directory")
	}
}

func TestStatNotFound(t *testing.T) {
	svc := New()
	_, err := svc.Stat("/nonexistent/path/file.txt")
	if err == nil {
		t.Error("Stat should fail for non-existent file")
	}
}

func TestRemove(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "filesystem_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	svc := New()
	path := filepath.Join(tmpDir, "test.txt")

	if err := svc.WriteFile(path, []byte("test"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if !svc.FileExists(path) {
		t.Fatal("file should exist")
	}

	if err := svc.Remove(path); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	if svc.FileExists(path) {
		t.Error("file should not exist after Remove")
	}
}

func TestRemoveAll(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "filesystem_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	svc := New()
	subDir := filepath.Join(tmpDir, "subdir")

	if err := svc.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Create file in subdir
	if err := svc.WriteFile(filepath.Join(subDir, "test.txt"), []byte("test"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Remove all
	if err := svc.RemoveAll(subDir); err != nil {
		t.Fatalf("RemoveAll failed: %v", err)
	}

	if svc.FileExists(subDir) {
		t.Error("directory should not exist after RemoveAll")
	}
}

func TestMkdirAll(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "filesystem_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	svc := New()
	path := filepath.Join(tmpDir, "a", "b", "c")

	if err := svc.MkdirAll(path, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	if !svc.FileExists(path) {
		t.Error("directory should exist after MkdirAll")
	}

	info, _ := svc.Stat(path)
	if !info.IsDir() {
		t.Error("should be a directory")
	}
}

func TestReadFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "filesystem_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	svc := New()
	path := filepath.Join(tmpDir, "test.txt")
	content := []byte("hello world")

	if err := svc.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	data, err := svc.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if string(data) != "hello world" {
		t.Errorf("content = %q, want 'hello world'", string(data))
	}
}

func TestReadFileNotFound(t *testing.T) {
	svc := New()
	_, err := svc.ReadFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("ReadFile should fail for non-existent file")
	}
}

func TestWriteFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "filesystem_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	svc := New()
	path := filepath.Join(tmpDir, "test.txt")

	if err := svc.WriteFile(path, []byte("test content"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	data, _ := svc.ReadFile(path)
	if string(data) != "test content" {
		t.Errorf("content = %q, want 'test content'", string(data))
	}
}

func TestCommandExists(t *testing.T) {
	svc := New()

	// 'ls' or 'dir' should exist on most systems
	if svc.CommandExists("ls") || svc.CommandExists("dir") || svc.CommandExists("echo") {
		// At least one common command exists
	} else {
		t.Error("at least one common command should exist")
	}

	// Non-existent command
	if svc.CommandExists("nonexistent_command_xyz123") {
		t.Error("non-existent command should not exist")
	}
}

func TestFileInterface(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "filesystem_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	svc := New()
	path := filepath.Join(tmpDir, "test.txt")

	f, err := svc.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	defer f.Close()

	// Test Name
	if f.Name() != path {
		t.Errorf("Name = %s, want %s", f.Name(), path)
	}

	// Test Write
	n, err := f.Write([]byte("hello world"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != 11 {
		t.Errorf("wrote %d bytes, want 11", n)
	}

	// Test Sync
	if err := f.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	// Test Stat
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if info.Size() != 11 {
		t.Errorf("Size = %d, want 11", info.Size())
	}

	// Test Seek
	pos, err := f.Seek(0, 0)
	if err != nil {
		t.Fatalf("Seek failed: %v", err)
	}
	if pos != 0 {
		t.Errorf("position = %d, want 0", pos)
	}

	// Test Read
	buf := make([]byte, 5)
	n, err = f.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("read = %q, want 'hello'", string(buf))
	}

	// Test Truncate
	if err := f.Truncate(5); err != nil {
		t.Fatalf("Truncate failed: %v", err)
	}
	info, _ = f.Stat()
	if info.Size() != 5 {
		t.Errorf("Size after truncate = %d, want 5", info.Size())
	}
}

func TestFileServiceInterface(t *testing.T) {
	svc := New()
	// Verify it implements FileService interface
	var _ FileService = svc
}
