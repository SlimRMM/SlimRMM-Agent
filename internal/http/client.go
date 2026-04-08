// Package http provides HTTP client abstractions for the RMM agent.
package http

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"log/slog"
)

// MaxErrorBodySize is the maximum size of error response bodies to prevent DoS.
// Error messages shouldn't need more than 64KB.
const MaxErrorBodySize = 64 * 1024

// MaxResponseSize is the maximum in-memory response body size (100 MiB).
// Protects against OOM caused by malicious or misconfigured servers.
// Untyped so callers can compare against int or int64 naturally.
const MaxResponseSize = 100 * 1024 * 1024

// MaxDownloadSize is the maximum download-to-file size (500 MiB).
const MaxDownloadSize = 500 * 1024 * 1024

var (
	sharedTransport     *http.Transport
	sharedTransportOnce sync.Once
)

// SharedTransport returns a process-wide HTTP transport with sane connection
// pooling and a TLS 1.3 minimum floor. It is safe for concurrent use.
func SharedTransport() *http.Transport {
	sharedTransportOnce.Do(func() {
		sharedTransport = &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
			},
		}
	})
	return sharedTransport
}

// newHTTPClient returns an *http.Client that uses the shared transport and
// the given request timeout.
func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: SharedTransport(),
		Timeout:   timeout,
	}
}

// VerifyCertPin returns a VerifyPeerCertificate callback that validates the
// peer's leaf certificate SPKI against a list of hex-encoded SHA-256 pin
// hashes. If pinHashes is empty the callback always fails (defence in depth).
func VerifyCertPin(pinHashes []string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	// Normalise pins once.
	pins := make(map[string]struct{}, len(pinHashes))
	for _, p := range pinHashes {
		pins[p] = struct{}{}
	}
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(pins) == 0 {
			return fmt.Errorf("certificate pinning: no pins configured")
		}
		if len(rawCerts) == 0 {
			return fmt.Errorf("certificate pinning: peer sent no certificates")
		}
		for _, raw := range rawCerts {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				continue
			}
			sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			got := hex.EncodeToString(sum[:])
			if _, ok := pins[got]; ok {
				return nil
			}
		}
		return fmt.Errorf("certificate pinning: no peer cert matched configured pins")
	}
}

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
	timeout      time.Duration
	token        string
	progressFunc ProgressCallback
	progressStep int // Report progress every N percent
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
	logger *slog.Logger
}

// NewClient creates a new HTTP client.
func NewClient(logger *slog.Logger) *DefaultClient {
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

	client := newHTTPClient(cfg.timeout)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Limit error body size to prevent DoS via large error responses
		body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodySize))
		return nil, fmt.Errorf("download failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Cap in-memory response size to guard against OOM from hostile servers.
	return io.ReadAll(io.LimitReader(resp.Body, MaxResponseSize))
}

// DownloadToFile downloads data from a URL to a file.
func (c *DefaultClient) DownloadToFile(ctx context.Context, url, destPath string, opts ...DownloadOption) error {
	// Validate destination path BEFORE hitting the network so a compromised
	// server cannot coerce us into overwriting e.g. /etc/passwd via a crafted
	// destPath. createFile() re-validates as defense-in-depth.
	if err := validateDestPath(destPath); err != nil {
		return fmt.Errorf("destination path validation failed: %w", err)
	}

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

	client := newHTTPClient(cfg.timeout)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("downloading: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Limit error body size to prevent DoS via large error responses
		body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodySize))
		return fmt.Errorf("download failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Reject oversized responses based on the advertised Content-Length,
	// before we create the destination file.
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if n, parseErr := strconv.ParseInt(cl, 10, 64); parseErr == nil && n > MaxDownloadSize {
			return fmt.Errorf("download too large: Content-Length %d exceeds max %d", n, MaxDownloadSize)
		}
	}

	// Limit the body reader so a lying server cannot exceed MaxDownloadSize.
	// We allow +1 byte so we can detect overflow.
	limited := io.LimitReader(resp.Body, MaxDownloadSize+1)

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
		n, readErr := limited.Read(buf)
		if n > 0 {
			if downloaded+int64(n) > MaxDownloadSize {
				return fmt.Errorf("download too large: exceeds max %d bytes", MaxDownloadSize)
			}
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

	client := newHTTPClient(cfg.timeout)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("uploading: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Limit error body size to prevent DoS via large error responses
		body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodySize))
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
