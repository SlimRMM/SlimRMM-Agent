// Package http provides HTTP client abstractions for the RMM agent.
package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// ProgressCallback is called during downloads/uploads with progress updates.
// progress is a value between 0 and 100.
type ProgressCallback func(progress int, bytesTransferred, totalBytes int64)

// Client provides HTTP operations for the RMM agent.
type Client interface {
	// Download downloads data from a URL.
	Download(ctx context.Context, url string, opts ...DownloadOption) ([]byte, error)

	// DownloadToFile downloads data from a URL to a file.
	DownloadToFile(ctx context.Context, url, destPath string, opts ...DownloadOption) error

	// Upload uploads data to a URL using PUT.
	Upload(ctx context.Context, url string, data []byte, opts ...UploadOption) error
}

// DownloadOption configures download behavior.
type DownloadOption func(*downloadConfig)

type downloadConfig struct {
	timeout        time.Duration
	token          string
	progressFunc   ProgressCallback
	progressStep   int // Report progress every N percent
}

// WithDownloadTimeout sets the download timeout.
func WithDownloadTimeout(d time.Duration) DownloadOption {
	return func(c *downloadConfig) {
		c.timeout = d
	}
}

// WithAuthToken sets the authorization token.
func WithAuthToken(token string) DownloadOption {
	return func(c *downloadConfig) {
		c.token = token
	}
}

// WithDownloadProgress sets a progress callback.
func WithDownloadProgress(fn ProgressCallback, stepPercent int) DownloadOption {
	return func(c *downloadConfig) {
		c.progressFunc = fn
		c.progressStep = stepPercent
	}
}

// UploadOption configures upload behavior.
type UploadOption func(*uploadConfig)

type uploadConfig struct {
	timeout      time.Duration
	contentType  string
	progressFunc ProgressCallback
}

// WithUploadTimeout sets the upload timeout.
func WithUploadTimeout(d time.Duration) UploadOption {
	return func(c *uploadConfig) {
		c.timeout = d
	}
}

// WithContentType sets the Content-Type header.
func WithContentType(ct string) UploadOption {
	return func(c *uploadConfig) {
		c.contentType = ct
	}
}

// WithUploadProgress sets a progress callback.
func WithUploadProgress(fn ProgressCallback) UploadOption {
	return func(c *uploadConfig) {
		c.progressFunc = fn
	}
}

// DefaultClient is the default HTTP client implementation.
type DefaultClient struct {
	logger *logrus.Logger
}

// NewClient creates a new HTTP client.
func NewClient(logger *logrus.Logger) *DefaultClient {
	return &DefaultClient{logger: logger}
}

// Download downloads data from a URL.
func (c *DefaultClient) Download(ctx context.Context, url string, opts ...DownloadOption) ([]byte, error) {
	cfg := &downloadConfig{
		timeout: 5 * time.Minute,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	if cfg.token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.token)
	}

	client := &http.Client{
		Timeout: cfg.timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("download failed with status %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// DownloadToFile downloads data from a URL to a file.
func (c *DefaultClient) DownloadToFile(ctx context.Context, url, destPath string, opts ...DownloadOption) error {
	cfg := &downloadConfig{
		timeout:      10 * time.Minute,
		progressStep: 10,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	if cfg.token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.token)
	}

	client := &http.Client{
		Timeout: cfg.timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("downloading: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("download failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Import filesystem service for file creation
	// Note: We use a simple file creation here to avoid circular imports
	out, err := createFile(destPath)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer out.Close()

	totalSize := resp.ContentLength
	var downloaded int64
	lastProgress := 0

	buf := make([]byte, 32*1024) // 32KB buffer
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			_, writeErr := out.Write(buf[:n])
			if writeErr != nil {
				return fmt.Errorf("writing file: %w", writeErr)
			}
			downloaded += int64(n)

			// Report progress
			if cfg.progressFunc != nil && totalSize > 0 {
				progress := int(float64(downloaded) / float64(totalSize) * 100)
				if progress >= lastProgress+cfg.progressStep {
					lastProgress = progress
					cfg.progressFunc(progress, downloaded, totalSize)
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("reading response: %w", readErr)
		}
	}

	return nil
}

// Upload uploads data to a URL using PUT.
func (c *DefaultClient) Upload(ctx context.Context, url string, data []byte, opts ...UploadOption) error {
	cfg := &uploadConfig{
		timeout:     5 * time.Minute,
		contentType: "application/octet-stream",
	}
	for _, opt := range opts {
		opt(cfg)
	}

	reader := newProgressReader(data, cfg.progressFunc)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, reader)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", cfg.contentType)
	req.ContentLength = int64(len(data))

	client := &http.Client{
		Timeout: cfg.timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("uploading: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// progressReader wraps a byte slice reader with progress reporting.
type progressReader struct {
	data         []byte
	pos          int
	totalSize    int64
	progressFunc ProgressCallback
	lastProgress int
}

func newProgressReader(data []byte, progressFunc ProgressCallback) *progressReader {
	return &progressReader{
		data:         data,
		totalSize:    int64(len(data)),
		progressFunc: progressFunc,
	}
}

func (r *progressReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}

	n = copy(p, r.data[r.pos:])
	r.pos += n

	if r.progressFunc != nil && r.totalSize > 0 {
		progress := int(float64(r.pos) / float64(r.totalSize) * 100)
		if progress >= r.lastProgress+10 {
			r.lastProgress = progress
			r.progressFunc(progress, int64(r.pos), r.totalSize)
		}
	}

	return n, nil
}

// Default client instance
var defaultClient *DefaultClient

// GetDefault returns the default HTTP client.
func GetDefault() *DefaultClient {
	if defaultClient == nil {
		defaultClient = NewClient(nil)
	}
	return defaultClient
}

// SetDefault sets the default HTTP client.
func SetDefault(c *DefaultClient) {
	defaultClient = c
}
