// Package backup provides memory-safe streaming backup infrastructure.
package backup

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/security/urlval"
)

// Memory safety constants for enterprise-grade backup operations.
const (
	// DefaultChunkSize is the default size for streaming chunks (8 MB).
	DefaultChunkSize = 8 * 1024 * 1024

	// MaxChunkSize is the maximum allowed chunk size (64 MB).
	MaxChunkSize = 64 * 1024 * 1024

	// MinChunkSize is the minimum allowed chunk size (1 MB).
	MinChunkSize = 1 * 1024 * 1024

	// DefaultBufferPoolSize is the number of buffers to keep in the pool.
	DefaultBufferPoolSize = 4

	// MaxConcurrentUploads is the maximum number of concurrent chunk uploads.
	MaxConcurrentUploads = 4

	// DefaultUploadTimeout is the timeout for a single chunk upload.
	DefaultUploadTimeout = 5 * time.Minute

	// MaxRetries is the maximum number of retries for failed uploads.
	MaxRetries = 3

	// RetryBackoff is the base duration for exponential backoff.
	RetryBackoff = 1 * time.Second

	// MaxResponseBodySize limits error response body reads to prevent memory exhaustion.
	MaxResponseBodySize = 1 * 1024 * 1024 // 1 MB
)

// ErrMemoryLimitExceeded indicates the operation would exceed memory limits.
var ErrMemoryLimitExceeded = errors.New("memory limit exceeded")

// StreamingCollector defines the interface for memory-safe backup collectors.
// Unlike the legacy Collector interface that returns []byte, StreamingCollector
// writes directly to an io.Writer, enabling unbounded backup sizes.
type StreamingCollector interface {
	// CollectStream writes backup data directly to the provided writer.
	// The writer receives raw, uncompressed data.
	// Returns the number of bytes written and any error.
	CollectStream(ctx context.Context, config CollectorConfig, w io.Writer) (int64, error)

	// Type returns the backup type this collector handles.
	Type() BackupType

	// SupportsStreaming returns true if this collector supports streaming.
	SupportsStreaming() bool
}

// StreamingIncrementalCollector extends StreamingCollector with incremental support.
type StreamingIncrementalCollector interface {
	StreamingCollector

	// CollectIncrementalStream writes incremental backup data to the writer.
	// Returns bytes written, manifest, delta info, and any error.
	CollectIncrementalStream(ctx context.Context, config CollectorConfig, w io.Writer) (int64, *FileManifest, *DeltaInfo, error)

	// SupportsIncrementalStreaming returns true if incremental streaming is supported.
	SupportsIncrementalStreaming() bool
}

// BufferPool manages a pool of reusable byte buffers to reduce GC pressure.
type BufferPool struct {
	pool      sync.Pool
	chunkSize int
	allocated int64
	maxSize   int64
	mu        sync.Mutex
}

// NewBufferPool creates a new buffer pool with the specified chunk size.
func NewBufferPool(chunkSize int, maxPoolSize int64) *BufferPool {
	if chunkSize < MinChunkSize {
		chunkSize = MinChunkSize
	}
	if chunkSize > MaxChunkSize {
		chunkSize = MaxChunkSize
	}

	bp := &BufferPool{
		chunkSize: chunkSize,
		maxSize:   maxPoolSize,
	}

	bp.pool = sync.Pool{
		New: func() interface{} {
			return make([]byte, chunkSize)
		},
	}

	return bp
}

// Get retrieves a buffer from the pool.
func (bp *BufferPool) Get() []byte {
	bp.mu.Lock()
	atomic.AddInt64(&bp.allocated, int64(bp.chunkSize))
	bp.mu.Unlock()

	return bp.pool.Get().([]byte)
}

// Put returns a buffer to the pool.
func (bp *BufferPool) Put(buf []byte) {
	if len(buf) != bp.chunkSize {
		return // Don't pool incorrectly sized buffers
	}

	bp.mu.Lock()
	atomic.AddInt64(&bp.allocated, -int64(bp.chunkSize))
	bp.mu.Unlock()

	bp.pool.Put(buf)
}

// Allocated returns the current allocated memory from this pool.
func (bp *BufferPool) Allocated() int64 {
	return atomic.LoadInt64(&bp.allocated)
}

// ChunkSize returns the configured chunk size.
func (bp *BufferPool) ChunkSize() int {
	return bp.chunkSize
}

// HashingWriter wraps a writer and computes hashes on the fly.
type HashingWriter struct {
	w       io.Writer
	sha256h hash.Hash
	sha512h hash.Hash
	written int64
}

// NewHashingWriter creates a writer that computes SHA256 and SHA512 hashes.
func NewHashingWriter(w io.Writer) *HashingWriter {
	return &HashingWriter{
		w:       w,
		sha256h: sha256.New(),
		sha512h: sha512.New(),
	}
}

// Write implements io.Writer, writing to underlying writer and hash functions.
func (hw *HashingWriter) Write(p []byte) (n int, err error) {
	n, err = hw.w.Write(p)
	if n > 0 {
		hw.sha256h.Write(p[:n])
		hw.sha512h.Write(p[:n])
		hw.written += int64(n)
	}
	return n, err
}

// SHA256Sum returns the hex-encoded SHA256 hash.
func (hw *HashingWriter) SHA256Sum() string {
	return hex.EncodeToString(hw.sha256h.Sum(nil))
}

// SHA512Sum returns the hex-encoded SHA512 hash.
func (hw *HashingWriter) SHA512Sum() string {
	return hex.EncodeToString(hw.sha512h.Sum(nil))
}

// Written returns the total bytes written.
func (hw *HashingWriter) Written() int64 {
	return hw.written
}

// CountingWriter wraps a writer and counts bytes written.
type CountingWriter struct {
	w       io.Writer
	written int64
}

// NewCountingWriter creates a new counting writer.
func NewCountingWriter(w io.Writer) *CountingWriter {
	return &CountingWriter{w: w}
}

// Write implements io.Writer.
func (cw *CountingWriter) Write(p []byte) (n int, err error) {
	n, err = cw.w.Write(p)
	cw.written += int64(n)
	return n, err
}

// Written returns the total bytes written.
func (cw *CountingWriter) Written() int64 {
	return cw.written
}

// StreamingEncryptor wraps a writer with AES-256-CTR encryption.
type StreamingEncryptor struct {
	w      io.Writer
	stream cipher.Stream
	iv     []byte
}

// NewStreamingEncryptor creates a new streaming encryptor.
// The key must be 32 bytes (AES-256).
func NewStreamingEncryptor(w io.Writer, key []byte) (*StreamingEncryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("generating IV: %w", err)
	}

	stream := cipher.NewCTR(block, iv)

	return &StreamingEncryptor{
		w:      w,
		stream: stream,
		iv:     iv,
	}, nil
}

// Write implements io.Writer with encryption.
func (se *StreamingEncryptor) Write(p []byte) (n int, err error) {
	encrypted := make([]byte, len(p))
	se.stream.XORKeyStream(encrypted, p)
	return se.w.Write(encrypted)
}

// IV returns the initialization vector (hex-encoded).
func (se *StreamingEncryptor) IV() string {
	return hex.EncodeToString(se.iv)
}

// StreamingDecryptor wraps a reader with AES-256-CTR decryption.
type StreamingDecryptor struct {
	r      io.Reader
	stream cipher.Stream
}

// NewStreamingDecryptor creates a new streaming decryptor.
func NewStreamingDecryptor(r io.Reader, key []byte, ivHex string) (*StreamingDecryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}

	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return nil, fmt.Errorf("decoding IV: %w", err)
	}

	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV must be %d bytes, got %d", aes.BlockSize, len(iv))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	stream := cipher.NewCTR(block, iv)

	return &StreamingDecryptor{
		r:      r,
		stream: stream,
	}, nil
}

// Read implements io.Reader with decryption.
func (sd *StreamingDecryptor) Read(p []byte) (n int, err error) {
	n, err = sd.r.Read(p)
	if n > 0 {
		sd.stream.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

// ChunkedUploader uploads data in chunks using multipart upload or PUT requests.
type ChunkedUploader struct {
	httpClient *http.Client
	bufferPool *BufferPool
	logger     *slog.Logger

	// Configuration
	chunkSize   int
	maxRetries  int
	timeout     time.Duration
	concurrency int
}

// ChunkedUploaderConfig holds configuration for the chunked uploader.
type ChunkedUploaderConfig struct {
	HTTPClient  *http.Client
	BufferPool  *BufferPool
	Logger      *slog.Logger
	ChunkSize   int
	MaxRetries  int
	Timeout     time.Duration
	Concurrency int
}

// NewChunkedUploader creates a new chunked uploader.
func NewChunkedUploader(cfg ChunkedUploaderConfig) *ChunkedUploader {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{
			Timeout: 30 * time.Minute,
		}
	}

	if cfg.BufferPool == nil {
		cfg.BufferPool = NewBufferPool(DefaultChunkSize, 256*1024*1024) // 256 MB max
	}

	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	if cfg.ChunkSize == 0 {
		cfg.ChunkSize = DefaultChunkSize
	}

	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = MaxRetries
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultUploadTimeout
	}

	if cfg.Concurrency == 0 {
		cfg.Concurrency = 1 // Sequential by default for simple PUT uploads
	}

	return &ChunkedUploader{
		httpClient:  cfg.HTTPClient,
		bufferPool:  cfg.BufferPool,
		logger:      cfg.Logger,
		chunkSize:   cfg.ChunkSize,
		maxRetries:  cfg.MaxRetries,
		timeout:     cfg.Timeout,
		concurrency: cfg.Concurrency,
	}
}

// UploadResult contains the result of an upload operation.
type UploadResult struct {
	BytesUploaded int64
	SHA256        string
	SHA512        string
	EncryptionIV  string
	Encrypted     bool
}

// Upload streams data from a reader to the specified URL.
// This method handles the entire upload in a memory-efficient manner.
func (cu *ChunkedUploader) Upload(ctx context.Context, url string, r io.Reader) (*UploadResult, error) {
	// For simple PUT uploads (like S3 pre-signed URLs), we need to buffer
	// because we need Content-Length header. We use a pipe to stream through.
	pr, pw := io.Pipe()

	result := &UploadResult{}
	var uploadErr error
	var wg sync.WaitGroup

	// Start upload in a goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer pr.Close()

		req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, pr)
		if err != nil {
			uploadErr = fmt.Errorf("creating request: %w", err)
			return
		}

		req.Header.Set("Content-Type", "application/octet-stream")
		// Note: Content-Length will be set by the pipe mechanism or chunked encoding

		resp, err := cu.httpClient.Do(req)
		if err != nil {
			uploadErr = fmt.Errorf("uploading: %w", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body := cu.readLimitedBody(resp.Body)
			uploadErr = fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, body)
		}
	}()

	// Create hashing writer to compute hashes while writing
	hw := NewHashingWriter(pw)

	// Copy data through the pipe with buffering
	buf := cu.bufferPool.Get()
	defer cu.bufferPool.Put(buf)

	_, err := io.CopyBuffer(hw, r, buf)
	pw.Close() // Signal end of data

	// Wait for upload to complete
	wg.Wait()

	if err != nil {
		return nil, fmt.Errorf("copying data: %w", err)
	}

	if uploadErr != nil {
		return nil, uploadErr
	}

	result.BytesUploaded = hw.Written()
	result.SHA256 = hw.SHA256Sum()
	result.SHA512 = hw.SHA512Sum()

	return result, nil
}

// UploadWithRetry uploads with automatic retries on failure.
func (cu *ChunkedUploader) UploadWithRetry(ctx context.Context, url string, r io.ReadSeeker) (*UploadResult, error) {
	var lastErr error

	for attempt := 0; attempt <= cu.maxRetries; attempt++ {
		if attempt > 0 {
			// Reset reader position for retry
			if _, err := r.Seek(0, io.SeekStart); err != nil {
				return nil, fmt.Errorf("seeking for retry: %w", err)
			}

			// Exponential backoff
			backoff := RetryBackoff * time.Duration(1<<uint(attempt-1))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}

			cu.logger.Info("retrying upload",
				"attempt", attempt+1,
				"max_retries", cu.maxRetries,
			)
		}

		result, err := cu.Upload(ctx, url, r)
		if err == nil {
			return result, nil
		}

		lastErr = err
		cu.logger.Warn("upload attempt failed",
			"attempt", attempt+1,
			"error", err,
		)
	}

	return nil, fmt.Errorf("upload failed after %d attempts: %w", cu.maxRetries+1, lastErr)
}

// readLimitedBody reads response body with a size limit to prevent memory exhaustion.
func (cu *ChunkedUploader) readLimitedBody(body io.Reader) string {
	limited := io.LimitReader(body, MaxResponseBodySize)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Sprintf("<error reading body: %v>", err)
	}
	if len(data) == MaxResponseBodySize {
		return string(data) + "... (truncated)"
	}
	return string(data)
}

// StreamingDownloader downloads data in a memory-efficient manner.
type StreamingDownloader struct {
	httpClient *http.Client
	bufferPool *BufferPool
	logger     *slog.Logger
	maxRetries int
}

// StreamingDownloaderConfig holds configuration for the streaming downloader.
type StreamingDownloaderConfig struct {
	HTTPClient *http.Client
	BufferPool *BufferPool
	Logger     *slog.Logger
	MaxRetries int
}

// NewStreamingDownloader creates a new streaming downloader.
func NewStreamingDownloader(cfg StreamingDownloaderConfig) *StreamingDownloader {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{
			Timeout: 30 * time.Minute,
		}
	}

	if cfg.BufferPool == nil {
		cfg.BufferPool = NewBufferPool(DefaultChunkSize, 256*1024*1024)
	}

	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = MaxRetries
	}

	return &StreamingDownloader{
		httpClient: cfg.HTTPClient,
		bufferPool: cfg.BufferPool,
		logger:     cfg.Logger,
		maxRetries: cfg.MaxRetries,
	}
}

// Download streams data from a URL to the provided writer.
// SECURITY: Validates URL to prevent SSRF attacks.
func (sd *StreamingDownloader) Download(ctx context.Context, url string, w io.Writer) (int64, error) {
	// SECURITY: Validate URL to prevent SSRF attacks
	validator := urlval.NewDefault()
	if err := validator.ValidateWithDNS(url); err != nil {
		return 0, fmt.Errorf("url validation failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("creating request: %w", err)
	}

	resp, err := sd.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("downloading: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limited := io.LimitReader(resp.Body, MaxResponseBodySize)
		body, _ := io.ReadAll(limited)
		return 0, fmt.Errorf("download failed with status %d: %s", resp.StatusCode, string(body))
	}

	buf := sd.bufferPool.Get()
	defer sd.bufferPool.Put(buf)

	return io.CopyBuffer(w, resp.Body, buf)
}

// DownloadWithSize downloads and validates the expected size.
func (sd *StreamingDownloader) DownloadWithSize(ctx context.Context, url string, w io.Writer, expectedSize int64) (int64, error) {
	cw := NewCountingWriter(w)
	n, err := sd.Download(ctx, url, cw)
	if err != nil {
		return n, err
	}

	if expectedSize > 0 && n != expectedSize {
		return n, fmt.Errorf("size mismatch: expected %d, got %d", expectedSize, n)
	}

	return n, nil
}

// ProgressTracker tracks progress of streaming operations.
type ProgressTracker struct {
	total      int64
	current    int64
	startTime  time.Time
	reporter   ProgressReporter
	updateFreq time.Duration
	lastUpdate time.Time
	mu         sync.Mutex
}

// NewProgressTracker creates a new progress tracker.
func NewProgressTracker(total int64, reporter ProgressReporter) *ProgressTracker {
	return &ProgressTracker{
		total:      total,
		startTime:  time.Now(),
		reporter:   reporter,
		updateFreq: 500 * time.Millisecond,
	}
}

// Add adds to the current progress.
func (pt *ProgressTracker) Add(n int64) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	pt.current += n

	if pt.reporter != nil && time.Since(pt.lastUpdate) >= pt.updateFreq {
		pt.lastUpdate = time.Now()
		pct := 0
		if pt.total > 0 {
			pct = int(float64(pt.current) / float64(pt.total) * 100)
		}
		pt.reporter.ReportProgress("streaming", pct, fmt.Sprintf("Processed %d bytes", pt.current), "info")
	}
}

// Current returns the current progress.
func (pt *ProgressTracker) Current() int64 {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	return pt.current
}

// Rate returns the current throughput in bytes per second.
func (pt *ProgressTracker) Rate() float64 {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	elapsed := time.Since(pt.startTime).Seconds()
	if elapsed == 0 {
		return 0
	}
	return float64(pt.current) / elapsed
}

// ProgressWriter wraps a writer and tracks progress.
type ProgressWriter struct {
	w       io.Writer
	tracker *ProgressTracker
}

// NewProgressWriter creates a writer that tracks progress.
func NewProgressWriter(w io.Writer, tracker *ProgressTracker) *ProgressWriter {
	return &ProgressWriter{
		w:       w,
		tracker: tracker,
	}
}

// Write implements io.Writer with progress tracking.
func (pw *ProgressWriter) Write(p []byte) (n int, err error) {
	n, err = pw.w.Write(p)
	if n > 0 && pw.tracker != nil {
		pw.tracker.Add(int64(n))
	}
	return n, err
}

// LimitedWriter wraps a writer with a maximum size limit.
type LimitedWriter struct {
	w       io.Writer
	limit   int64
	written int64
}

// NewLimitedWriter creates a writer with a size limit.
func NewLimitedWriter(w io.Writer, limit int64) *LimitedWriter {
	return &LimitedWriter{
		w:     w,
		limit: limit,
	}
}

// Write implements io.Writer with size limiting.
func (lw *LimitedWriter) Write(p []byte) (n int, err error) {
	if lw.written+int64(len(p)) > lw.limit {
		return 0, ErrMemoryLimitExceeded
	}
	n, err = lw.w.Write(p)
	lw.written += int64(n)
	return n, err
}

// Written returns the bytes written so far.
func (lw *LimitedWriter) Written() int64 {
	return lw.written
}
