// Package actions provides file transfer functionality.
package actions

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kiefernetworks/slimrmm-agent/internal/security/pathval"
)

const (
	DefaultChunkSize = 64 * 1024 // 64 KB
	MaxFileSize      = 100 * 1024 * 1024 // 100 MB
)

// UploadSession tracks an ongoing file upload.
type UploadSession struct {
	ID          string
	Path        string
	TotalSize   int64
	Received    int64
	ChunkCount  int
	File        *os.File
	Hash        string
	StartTime   time.Time
	mu          sync.Mutex
}

// UploadManager manages file upload sessions.
type UploadManager struct {
	sessions map[string]*UploadSession
	mu       sync.RWMutex
}

// NewUploadManager creates a new upload manager.
func NewUploadManager() *UploadManager {
	return &UploadManager{
		sessions: make(map[string]*UploadSession),
	}
}

// StartUpload starts a new upload session.
func (m *UploadManager) StartUpload(sessionID, path string, totalSize int64) error {
	validator := pathval.New()
	if err := validator.Validate(filepath.Dir(path)); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}

	if totalSize > MaxFileSize {
		return fmt.Errorf("file too large: %d > %d", totalSize, MaxFileSize)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[sessionID]; exists {
		return fmt.Errorf("session %s already exists", sessionID)
	}

	// Create parent directory if needed
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}

	m.sessions[sessionID] = &UploadSession{
		ID:        sessionID,
		Path:      path,
		TotalSize: totalSize,
		File:      file,
		StartTime: time.Now(),
	}

	return nil
}

// UploadChunk receives a chunk of data for an upload.
func (m *UploadManager) UploadChunk(sessionID string, chunkIndex int, data []byte) error {
	m.mu.RLock()
	session, exists := m.sessions[sessionID]
	m.mu.RUnlock()

	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	n, err := session.File.Write(data)
	if err != nil {
		return fmt.Errorf("writing chunk: %w", err)
	}

	session.Received += int64(n)
	session.ChunkCount++

	return nil
}

// FinishUpload completes an upload session.
func (m *UploadManager) FinishUpload(sessionID string) (*UploadResult, error) {
	m.mu.Lock()
	session, exists := m.sessions[sessionID]
	if exists {
		delete(m.sessions, sessionID)
	}
	m.mu.Unlock()

	if !exists {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	session.File.Close()

	// Calculate hash
	file, err := os.Open(session.Path)
	if err != nil {
		return nil, fmt.Errorf("opening file for hash: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return nil, fmt.Errorf("calculating hash: %w", err)
	}

	return &UploadResult{
		Path:     session.Path,
		Size:     session.Received,
		Hash:     hex.EncodeToString(hasher.Sum(nil)),
		Duration: time.Since(session.StartTime).Milliseconds(),
	}, nil
}

// CancelUpload cancels an upload session.
func (m *UploadManager) CancelUpload(sessionID string) error {
	m.mu.Lock()
	session, exists := m.sessions[sessionID]
	if exists {
		delete(m.sessions, sessionID)
	}
	m.mu.Unlock()

	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	session.File.Close()
	os.Remove(session.Path)

	return nil
}

// UploadResult contains the result of a completed upload.
type UploadResult struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Hash     string `json:"hash"`
	Duration int64  `json:"duration_ms"`
}

// DownloadResult contains file download information.
type DownloadResult struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Hash     string `json:"hash"`
	Content  string `json:"content,omitempty"` // Base64 encoded for small files
	ChunkCount int  `json:"chunk_count,omitempty"`
}

// DownloadFile prepares a file for download.
func DownloadFile(path string, offset, limit int64) (*DownloadResult, error) {
	validator := pathval.New()
	if err := validator.ValidateWithSymlinkResolution(path); err != nil {
		return nil, fmt.Errorf("path validation failed: %w", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		return nil, fmt.Errorf("cannot download directory")
	}

	if info.Size() > MaxFileSize {
		return nil, fmt.Errorf("file too large: %d > %d", info.Size(), MaxFileSize)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Calculate hash
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return nil, fmt.Errorf("calculating hash: %w", err)
	}

	result := &DownloadResult{
		Path: path,
		Size: info.Size(),
		Hash: hex.EncodeToString(hasher.Sum(nil)),
	}

	// For small files, include content directly
	if info.Size() <= DefaultChunkSize {
		file.Seek(0, io.SeekStart)
		data, err := io.ReadAll(file)
		if err != nil {
			return nil, err
		}
		result.Content = base64.StdEncoding.EncodeToString(data)
	} else {
		result.ChunkCount = int((info.Size() + DefaultChunkSize - 1) / DefaultChunkSize)
	}

	return result, nil
}

// DownloadChunk returns a specific chunk of a file.
func DownloadChunk(path string, chunkIndex int) ([]byte, error) {
	validator := pathval.New()
	if err := validator.ValidateWithSymlinkResolution(path); err != nil {
		return nil, fmt.Errorf("path validation failed: %w", err)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	offset := int64(chunkIndex) * DefaultChunkSize
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}

	data := make([]byte, DefaultChunkSize)
	n, err := file.Read(data)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return data[:n], nil
}

// DownloadURL downloads a file from a URL.
func DownloadURL(url, destPath string) (*DownloadResult, error) {
	validator := pathval.New()
	if err := validator.Validate(filepath.Dir(destPath)); err != nil {
		return nil, fmt.Errorf("path validation failed: %w", err)
	}

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("downloading: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed: status %d", resp.StatusCode)
	}

	// Create parent directory
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return nil, fmt.Errorf("creating directory: %w", err)
	}

	file, err := os.Create(destPath)
	if err != nil {
		return nil, fmt.Errorf("creating file: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	writer := io.MultiWriter(file, hasher)

	size, err := io.Copy(writer, resp.Body)
	if err != nil {
		os.Remove(destPath)
		return nil, fmt.Errorf("writing file: %w", err)
	}

	return &DownloadResult{
		Path: destPath,
		Size: size,
		Hash: hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}
