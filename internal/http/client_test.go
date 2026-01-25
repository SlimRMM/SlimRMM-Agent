package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	client := NewClient(nil)
	if client == nil {
		t.Error("NewClient should not return nil")
	}
}

func TestGetDefault(t *testing.T) {
	client := GetDefault()
	if client == nil {
		t.Error("GetDefault should not return nil")
	}
}

func TestSetDefault(t *testing.T) {
	original := GetDefault()
	defer SetDefault(original)

	newClient := NewClient(nil)
	SetDefault(newClient)

	if GetDefault() != newClient {
		t.Error("SetDefault should update the default client")
	}
}

func TestDownloadSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test data"))
	}))
	defer server.Close()

	client := NewClient(nil)
	data, err := client.Download(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}

	if string(data) != "test data" {
		t.Errorf("got %q, want %q", string(data), "test data")
	}
}

func TestDownloadWithToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("got auth %q, want %q", auth, "Bearer test-token")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("authorized"))
	}))
	defer server.Close()

	client := NewClient(nil)
	data, err := client.Download(context.Background(), server.URL, WithAuthToken("test-token"))
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}

	if string(data) != "authorized" {
		t.Errorf("got %q, want %q", string(data), "authorized")
	}
}

func TestDownloadWithTimeout(t *testing.T) {
	// Test that timeout option is applied (we can't easily test the actual timeout)
	cfg := &downloadConfig{timeout: 1 * time.Second}
	opt := WithDownloadTimeout(5 * time.Minute)
	opt(cfg)

	if cfg.timeout != 5*time.Minute {
		t.Errorf("timeout = %v, want 5m", cfg.timeout)
	}
}

func TestDownloadError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer server.Close()

	client := NewClient(nil)
	_, err := client.Download(context.Background(), server.URL)
	if err == nil {
		t.Error("expected error for 500 status")
	}
}

func TestDownloadToFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "9")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("file data"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "test.txt")

	client := NewClient(nil)
	err := client.DownloadToFile(context.Background(), server.URL, destPath)
	if err != nil {
		t.Fatalf("DownloadToFile failed: %v", err)
	}

	data, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	if string(data) != "file data" {
		t.Errorf("got %q, want %q", string(data), "file data")
	}
}

func TestDownloadToFileWithProgress(t *testing.T) {
	largeData := make([]byte, 100*1024) // 100KB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "102400")
		w.WriteHeader(http.StatusOK)
		w.Write(largeData)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "large.bin")

	var progressCalls int
	progressFn := func(progress int, transferred, total int64) {
		progressCalls++
	}

	client := NewClient(nil)
	err := client.DownloadToFile(context.Background(), server.URL, destPath,
		WithDownloadProgress(progressFn, 10))
	if err != nil {
		t.Fatalf("DownloadToFile failed: %v", err)
	}

	if progressCalls == 0 {
		t.Error("progress callback should have been called")
	}
}

func TestUploadSuccess(t *testing.T) {
	var receivedData []byte
	var receivedContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s, want PUT", r.Method)
		}
		receivedContentType = r.Header.Get("Content-Type")
		data := make([]byte, r.ContentLength)
		r.Body.Read(data)
		receivedData = data
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(nil)
	err := client.Upload(context.Background(), server.URL, []byte("upload data"))
	if err != nil {
		t.Fatalf("Upload failed: %v", err)
	}

	if string(receivedData) != "upload data" {
		t.Errorf("received %q, want %q", string(receivedData), "upload data")
	}

	if receivedContentType != "application/octet-stream" {
		t.Errorf("content-type = %s, want application/octet-stream", receivedContentType)
	}
}

func TestUploadWithContentType(t *testing.T) {
	var receivedContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(nil)
	err := client.Upload(context.Background(), server.URL, []byte("data"),
		WithContentType("application/json"))
	if err != nil {
		t.Fatalf("Upload failed: %v", err)
	}

	if receivedContentType != "application/json" {
		t.Errorf("content-type = %s, want application/json", receivedContentType)
	}
}

func TestUploadError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
	}))
	defer server.Close()

	client := NewClient(nil)
	err := client.Upload(context.Background(), server.URL, []byte("data"))
	if err == nil {
		t.Error("expected error for 403 status")
	}
}

func TestUploadWithTimeout(t *testing.T) {
	cfg := &uploadConfig{timeout: 1 * time.Second}
	opt := WithUploadTimeout(10 * time.Minute)
	opt(cfg)

	if cfg.timeout != 10*time.Minute {
		t.Errorf("timeout = %v, want 10m", cfg.timeout)
	}
}

func TestProgressReader(t *testing.T) {
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i)
	}

	var calls int
	progressFn := func(progress int, transferred, total int64) {
		calls++
	}

	reader := newProgressReader(data, progressFn)

	buf := make([]byte, 20)
	totalRead := 0
	for {
		n, err := reader.Read(buf)
		totalRead += n
		if err != nil {
			break
		}
	}

	if totalRead != 100 {
		t.Errorf("total read = %d, want 100", totalRead)
	}
}

func TestProgressReaderNilCallback(t *testing.T) {
	data := []byte("test")
	reader := newProgressReader(data, nil)

	buf := make([]byte, 10)
	n, _ := reader.Read(buf)

	if n != 4 {
		t.Errorf("read = %d, want 4", n)
	}
}

func TestCreateFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "subdir", "test.txt")

	f, err := createFile(path)
	if err != nil {
		t.Fatalf("createFile failed: %v", err)
	}
	defer f.Close()

	_, err = f.WriteString("test")
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
}
