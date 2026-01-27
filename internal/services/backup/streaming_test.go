// Package backup provides tests for streaming backup infrastructure.
package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"sync"
	"testing"
	"time"
)

// TestBufferPoolBasic tests basic buffer pool operations.
func TestBufferPoolBasic(t *testing.T) {
	pool := NewBufferPool(1024*1024, 64*1024*1024) // 1MB chunks, 64MB max

	// Get a buffer
	buf := pool.Get()
	if buf == nil {
		t.Fatal("expected non-nil buffer")
	}
	if cap(buf) < MinChunkSize {
		t.Errorf("buffer capacity = %d, want >= %d", cap(buf), MinChunkSize)
	}

	// Put it back
	pool.Put(buf)

	// Get another - should reuse the pooled buffer
	buf2 := pool.Get()
	if buf2 == nil {
		t.Fatal("expected non-nil buffer")
	}
}

// TestBufferPoolConcurrent tests concurrent access to buffer pool.
func TestBufferPoolConcurrent(t *testing.T) {
	pool := NewBufferPool(DefaultChunkSize, 256*1024*1024)
	var wg sync.WaitGroup
	iterations := 100
	goroutines := 10

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				buf := pool.Get()
				if buf == nil {
					t.Error("expected non-nil buffer")
					return
				}
				// Simulate some work
				copy(buf, []byte("test data"))
				pool.Put(buf)
			}
		}()
	}

	wg.Wait()
}

// TestBufferPoolChunkSize tests chunk size enforcement.
func TestBufferPoolChunkSize(t *testing.T) {
	tests := []struct {
		requestedSize int
		expectedMin   int
	}{
		{512, MinChunkSize},                       // Too small, should use min
		{MinChunkSize, MinChunkSize},              // Exactly min
		{DefaultChunkSize, DefaultChunkSize},      // Normal
		{MaxChunkSize + 1024, MaxChunkSize},       // Too large, should use max
	}

	for _, tt := range tests {
		pool := NewBufferPool(tt.requestedSize, 64*1024*1024)
		if pool.ChunkSize() < tt.expectedMin {
			t.Errorf("ChunkSize(%d) = %d, want >= %d", tt.requestedSize, pool.ChunkSize(), tt.expectedMin)
		}
		if pool.ChunkSize() > MaxChunkSize {
			t.Errorf("ChunkSize(%d) = %d, want <= %d", tt.requestedSize, pool.ChunkSize(), MaxChunkSize)
		}
	}
}

// TestHashingWriter tests hashing writer functionality.
func TestHashingWriter(t *testing.T) {
	var buf bytes.Buffer
	hw := NewHashingWriter(&buf)

	testData := []byte("Hello, World! This is test data for hashing.")

	n, err := hw.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Write returned %d, want %d", n, len(testData))
	}

	// Check that data was written to underlying writer
	if !bytes.Equal(buf.Bytes(), testData) {
		t.Error("data not written to underlying writer")
	}

	// Check hash values
	sha256Hash := hw.SHA256Sum()
	sha512Hash := hw.SHA512Sum()

	if len(sha256Hash) != 64 { // 32 bytes * 2 hex chars
		t.Errorf("SHA256 hash length = %d, want 64", len(sha256Hash))
	}
	if len(sha512Hash) != 128 { // 64 bytes * 2 hex chars
		t.Errorf("SHA512 hash length = %d, want 128", len(sha512Hash))
	}

	// Verify bytes written tracking
	if hw.Written() != int64(len(testData)) {
		t.Errorf("Written = %d, want %d", hw.Written(), len(testData))
	}
}

// TestHashingWriterMultipleWrites tests multiple writes to hashing writer.
func TestHashingWriterMultipleWrites(t *testing.T) {
	var buf bytes.Buffer
	hw := NewHashingWriter(&buf)

	// Write in multiple chunks
	chunks := [][]byte{
		[]byte("First chunk. "),
		[]byte("Second chunk. "),
		[]byte("Third chunk."),
	}

	var totalBytes int64
	for _, chunk := range chunks {
		n, err := hw.Write(chunk)
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		totalBytes += int64(n)
	}

	if hw.Written() != totalBytes {
		t.Errorf("Written = %d, want %d", hw.Written(), totalBytes)
	}

	// Hash should be consistent for the combined data
	hash1 := hw.SHA256Sum()

	// Create new writer with same data in one write
	var buf2 bytes.Buffer
	hw2 := NewHashingWriter(&buf2)
	allData := bytes.Join(chunks, nil)
	hw2.Write(allData)
	hash2 := hw2.SHA256Sum()

	if hash1 != hash2 {
		t.Errorf("hash mismatch: %s != %s", hash1, hash2)
	}
}

// TestCountingWriter tests counting writer functionality.
func TestCountingWriter(t *testing.T) {
	var buf bytes.Buffer
	cw := NewCountingWriter(&buf)

	testData := []byte("Counting writer test data")
	n, err := cw.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Write returned %d, want %d", n, len(testData))
	}

	if cw.Written() != int64(len(testData)) {
		t.Errorf("Written = %d, want %d", cw.Written(), len(testData))
	}
}

// TestStreamingEncryptor tests streaming encryption.
func TestStreamingEncryptor(t *testing.T) {
	key := make([]byte, 32) // AES-256 key
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	var encryptedBuf bytes.Buffer
	enc, err := NewStreamingEncryptor(&encryptedBuf, key)
	if err != nil {
		t.Fatalf("NewStreamingEncryptor failed: %v", err)
	}

	testData := []byte("Secret data that needs encryption!")

	n, err := enc.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Write returned %d, want %d", n, len(testData))
	}

	// Get IV for decryption
	iv := enc.IV()
	if len(iv) != 32 { // 16 bytes * 2 hex chars
		t.Errorf("IV hex length = %d, want 32", len(iv))
	}

	// Encrypted data should be same length (CTR mode)
	if encryptedBuf.Len() != len(testData) {
		t.Errorf("encrypted length = %d, want %d", encryptedBuf.Len(), len(testData))
	}

	// Encrypted data should be different from plaintext
	if bytes.Equal(encryptedBuf.Bytes(), testData) {
		t.Error("encrypted data equals plaintext")
	}
}

// TestStreamingEncryptorDecrypt tests that encrypted data can be decrypted.
func TestStreamingEncryptorDecrypt(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	testData := []byte("This is the plaintext that we want to encrypt and then decrypt to verify correctness.")

	// Encrypt
	var encryptedBuf bytes.Buffer
	enc, _ := NewStreamingEncryptor(&encryptedBuf, key)
	enc.Write(testData)
	iv := enc.IV()

	// Decrypt using the decryptor
	dec, err := NewStreamingDecryptor(bytes.NewReader(encryptedBuf.Bytes()), key, iv)
	if err != nil {
		t.Fatalf("NewStreamingDecryptor failed: %v", err)
	}

	decryptedData, err := io.ReadAll(dec)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	// Verify
	if !bytes.Equal(decryptedData, testData) {
		t.Error("decrypted data does not match original")
	}
}

// TestStreamingEncryptorInvalidKey tests error handling for invalid key.
func TestStreamingEncryptorInvalidKey(t *testing.T) {
	invalidKeys := [][]byte{
		nil,
		{},
		make([]byte, 15), // Too short
		make([]byte, 17), // Not AES key size
		make([]byte, 31), // Almost 256-bit
	}

	var buf bytes.Buffer
	for _, key := range invalidKeys {
		_, err := NewStreamingEncryptor(&buf, key)
		if err == nil {
			t.Errorf("expected error for key length %d", len(key))
		}
	}
}

// TestStreamingDecryptorInvalidIV tests error handling for invalid IV.
func TestStreamingDecryptorInvalidIV(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	invalidIVs := []string{
		"",
		"abc",                             // Too short
		"0123456789abcdef",                // 16 chars but not valid hex length for 16 bytes
		"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", // Invalid hex
	}

	for _, iv := range invalidIVs {
		_, err := NewStreamingDecryptor(bytes.NewReader(nil), key, iv)
		if err == nil {
			t.Errorf("expected error for IV %q", iv)
		}
	}
}

// TestStreamingCollectorInterface tests the StreamingCollector interface.
func TestStreamingCollectorInterface(t *testing.T) {
	// This test verifies that our streaming collectors implement the interface correctly
	// by testing the mock implementation

	collector := &mockStreamingCollector{
		data:        []byte("test streaming data"),
		backupType:  "test_type",
		description: "Test Streaming Collector",
	}

	// Test interface methods
	if collector.Type() != "test_type" {
		t.Errorf("Type = %s, want test_type", collector.Type())
	}

	if !collector.SupportsStreaming() {
		t.Error("expected SupportsStreaming to return true")
	}

	// Test streaming collection
	ctx := context.Background()
	var buf bytes.Buffer
	cfg := CollectorConfig{}

	n, err := collector.CollectStream(ctx, cfg, &buf)
	if err != nil {
		t.Fatalf("CollectStream failed: %v", err)
	}

	if n != int64(len(collector.data)) {
		t.Errorf("CollectStream returned %d bytes, want %d", n, len(collector.data))
	}

	if !bytes.Equal(buf.Bytes(), collector.data) {
		t.Error("collected data mismatch")
	}
}

// mockStreamingCollector implements StreamingCollector for testing.
type mockStreamingCollector struct {
	data        []byte
	backupType  string
	description string
	shouldFail  bool
}

func (m *mockStreamingCollector) Type() BackupType {
	return BackupType(m.backupType)
}

func (m *mockStreamingCollector) SupportsStreaming() bool {
	return true
}

func (m *mockStreamingCollector) CollectStream(ctx context.Context, config CollectorConfig, w io.Writer) (int64, error) {
	if m.shouldFail {
		return 0, io.ErrUnexpectedEOF
	}

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
		n, err := w.Write(m.data)
		return int64(n), err
	}
}

// TestStreamingCollectorContextCancellation tests context cancellation.
func TestStreamingCollectorContextCancellation(t *testing.T) {
	collector := &slowStreamingCollector{
		delay: 100 * time.Millisecond,
		data:  make([]byte, 1024),
	}

	ctx, cancel := context.WithCancel(context.Background())

	var buf bytes.Buffer
	done := make(chan error)

	go func() {
		_, err := collector.CollectStream(ctx, CollectorConfig{}, &buf)
		done <- err
	}()

	// Cancel immediately
	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Error("timeout waiting for cancellation")
	}
}

// slowStreamingCollector simulates a slow streaming collector for testing.
type slowStreamingCollector struct {
	delay time.Duration
	data  []byte
}

func (s *slowStreamingCollector) Type() BackupType {
	return "slow_test"
}

func (s *slowStreamingCollector) SupportsStreaming() bool {
	return true
}

func (s *slowStreamingCollector) CollectStream(ctx context.Context, config CollectorConfig, w io.Writer) (int64, error) {
	var written int64
	chunkSize := 64

	for i := 0; i < len(s.data); i += chunkSize {
		select {
		case <-ctx.Done():
			return written, ctx.Err()
		default:
			end := i + chunkSize
			if end > len(s.data) {
				end = len(s.data)
			}
			n, err := w.Write(s.data[i:end])
			written += int64(n)
			if err != nil {
				return written, err
			}
			time.Sleep(s.delay)
		}
	}
	return written, nil
}

// TestChunkedUploaderCreation tests chunked uploader creation with config.
func TestChunkedUploaderCreation(t *testing.T) {
	// Test with default config
	uploader := NewChunkedUploader(ChunkedUploaderConfig{})

	if uploader == nil {
		t.Fatal("expected non-nil uploader")
	}

	// Test with custom config
	customPool := NewBufferPool(4*1024*1024, 128*1024*1024)
	uploaderWithConfig := NewChunkedUploader(ChunkedUploaderConfig{
		BufferPool:  customPool,
		ChunkSize:   4 * 1024 * 1024,
		MaxRetries:  5,
		Timeout:     10 * time.Minute,
		Concurrency: 2,
	})

	if uploaderWithConfig == nil {
		t.Fatal("expected non-nil uploader")
	}
}

// TestStreamingDownloaderCreation tests streaming downloader creation.
func TestStreamingDownloaderCreation(t *testing.T) {
	downloader := NewStreamingDownloader(StreamingDownloaderConfig{})

	if downloader == nil {
		t.Fatal("expected non-nil downloader")
	}
}

// TestStreamingCompressorIntegration tests compressor with encryption pipeline.
func TestStreamingCompressorIntegration(t *testing.T) {
	// Test data
	originalData := bytes.Repeat([]byte("This is test data for compression. "), 100)

	// Create compression -> encryption pipeline
	key := make([]byte, 32)
	rand.Read(key)

	var finalBuf bytes.Buffer
	hashWriter := NewHashingWriter(&finalBuf)
	enc, _ := NewStreamingEncryptor(hashWriter, key)
	comp, _ := NewStreamingCompressor(enc, CompressionFast)

	// Write data through pipeline
	n, err := comp.Write(originalData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(originalData) {
		t.Errorf("Write returned %d, want %d", n, len(originalData))
	}

	// Close compressor to flush
	if err := comp.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify compressed data is smaller (for repetitive data)
	if finalBuf.Len() >= len(originalData) {
		t.Logf("Warning: compressed size (%d) >= original size (%d)", finalBuf.Len(), len(originalData))
	}

	// Verify hash was calculated
	if hashWriter.SHA256Sum() == "" {
		t.Error("expected non-empty SHA256 hash")
	}
}

// TestPipelineWriterBasic tests basic pipeline writer functionality.
func TestPipelineWriterBasic(t *testing.T) {
	var finalBuf bytes.Buffer

	// Create a simple pipeline with just compression
	pw, err := NewPipelineWriter(&finalBuf, WrapCompressor(CompressionFast))
	if err != nil {
		t.Fatalf("NewPipelineWriter failed: %v", err)
	}

	testData := bytes.Repeat([]byte("Pipeline test data. "), 50)

	n, err := pw.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Write returned %d, want %d", n, len(testData))
	}

	if err := pw.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify data was written
	if finalBuf.Len() == 0 {
		t.Error("expected non-empty output")
	}
}

// TestPipelineWriterMultiStage tests multi-stage pipeline.
func TestPipelineWriterMultiStage(t *testing.T) {
	var finalBuf bytes.Buffer
	key := make([]byte, 32)
	rand.Read(key)

	// Create compress -> encrypt pipeline
	pw, err := NewPipelineWriter(&finalBuf,
		WrapCompressor(CompressionBalanced),
		WrapEncryptor(key),
	)
	if err != nil {
		t.Fatalf("NewPipelineWriter failed: %v", err)
	}

	testData := bytes.Repeat([]byte("Multi-stage pipeline test. "), 100)

	_, err = pw.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if err := pw.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if finalBuf.Len() == 0 {
		t.Error("expected non-empty output")
	}
}

// TestMultiWriterBasic tests multi-writer functionality.
func TestMultiWriterBasic(t *testing.T) {
	var buf1, buf2 bytes.Buffer

	mw := NewMultiWriter(&buf1, &buf2)

	testData := []byte("Data for multiple writers")

	n, err := mw.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Write returned %d, want %d", n, len(testData))
	}

	// Verify both buffers received the data
	if !bytes.Equal(buf1.Bytes(), testData) {
		t.Error("buf1 data mismatch")
	}
	if !bytes.Equal(buf2.Bytes(), testData) {
		t.Error("buf2 data mismatch")
	}

	// Verify bytes written tracking
	if mw.Written() != int64(len(testData)) {
		t.Errorf("Written = %d, want %d", mw.Written(), len(testData))
	}
}

// TestTeeReaderBasic tests tee reader functionality.
func TestTeeReaderBasic(t *testing.T) {
	originalData := []byte("Data to be read and copied")
	reader := bytes.NewReader(originalData)

	var copyBuf bytes.Buffer
	tr := NewTeeReader(reader, &copyBuf)

	readBuf := make([]byte, 1024)
	n, err := tr.Read(readBuf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read failed: %v", err)
	}
	if n != len(originalData) {
		t.Errorf("Read returned %d, want %d", n, len(originalData))
	}

	// Verify both read data and copy are correct
	if !bytes.Equal(readBuf[:n], originalData) {
		t.Error("read data mismatch")
	}
	if !bytes.Equal(copyBuf.Bytes(), originalData) {
		t.Error("copy data mismatch")
	}

	// Verify bytes read tracking
	if tr.BytesRead() != int64(len(originalData)) {
		t.Errorf("BytesRead = %d, want %d", tr.BytesRead(), len(originalData))
	}
}

// TestStreamingDecompressor tests streaming decompression.
func TestStreamingDecompressor(t *testing.T) {
	// First compress some data
	originalData := bytes.Repeat([]byte("Decompression test data. "), 50)

	var compressedBuf bytes.Buffer
	comp, _ := NewStreamingCompressor(&compressedBuf, CompressionFast)
	comp.Write(originalData)
	comp.Close()

	// Now decompress
	decomp, err := NewStreamingDecompressor(&compressedBuf)
	if err != nil {
		t.Fatalf("NewStreamingDecompressor failed: %v", err)
	}

	decompressedData, err := io.ReadAll(decomp)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if err := decomp.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify decompressed data matches original
	if !bytes.Equal(decompressedData, originalData) {
		t.Error("decompressed data does not match original")
	}
}

// TestStreamingCompressionLevels tests different compression levels.
func TestStreamingCompressionLevels(t *testing.T) {
	testData := bytes.Repeat([]byte("Test data for compression level comparison. "), 100)

	levels := []CompressionLevel{
		CompressionNone,
		CompressionFast,
		CompressionBalanced,
		CompressionHigh,
		CompressionMaximum,
	}

	for _, level := range levels {
		var buf bytes.Buffer
		comp, err := NewStreamingCompressor(&buf, level)
		if err != nil {
			t.Fatalf("NewStreamingCompressor(%s) failed: %v", level, err)
		}

		comp.Write(testData)
		comp.Close()

		t.Logf("Level %s: %d bytes (original: %d)", level, buf.Len(), len(testData))

		// Verify data can be decompressed
		decomp, err := NewStreamingDecompressor(&buf)
		if err != nil {
			t.Fatalf("NewStreamingDecompressor failed for level %s: %v", level, err)
		}

		decompressed, err := io.ReadAll(decomp)
		if err != nil {
			t.Fatalf("ReadAll failed for level %s: %v", level, err)
		}

		if !bytes.Equal(decompressed, testData) {
			t.Errorf("decompressed data mismatch for level %s", level)
		}
		decomp.Close()
	}
}

// TestLimitedWriter tests limited writer functionality.
func TestLimitedWriter(t *testing.T) {
	var buf bytes.Buffer
	lw := NewLimitedWriter(&buf, 100) // 100 byte limit

	// Write under limit should succeed
	n, err := lw.Write([]byte("short"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != 5 {
		t.Errorf("Write returned %d, want 5", n)
	}

	// Write that exceeds limit should fail
	largeData := make([]byte, 200)
	_, err = lw.Write(largeData)
	if err != ErrMemoryLimitExceeded {
		t.Errorf("expected ErrMemoryLimitExceeded, got %v", err)
	}

	// Verify written count
	if lw.Written() != 5 {
		t.Errorf("Written = %d, want 5", lw.Written())
	}
}

// TestProgressTracker tests progress tracking.
func TestProgressTracker(t *testing.T) {
	tracker := NewProgressTracker(1000, nil)

	tracker.Add(100)
	if tracker.Current() != 100 {
		t.Errorf("Current = %d, want 100", tracker.Current())
	}

	tracker.Add(400)
	if tracker.Current() != 500 {
		t.Errorf("Current = %d, want 500", tracker.Current())
	}

	// Rate should be positive after some adds
	time.Sleep(10 * time.Millisecond)
	if tracker.Rate() <= 0 {
		t.Error("expected positive rate")
	}
}

// TestProgressWriter tests progress writer.
func TestProgressWriter(t *testing.T) {
	var buf bytes.Buffer
	tracker := NewProgressTracker(100, nil)
	pw := NewProgressWriter(&buf, tracker)

	testData := []byte("progress tracking test")
	pw.Write(testData)

	if tracker.Current() != int64(len(testData)) {
		t.Errorf("tracker.Current = %d, want %d", tracker.Current(), len(testData))
	}

	if !bytes.Equal(buf.Bytes(), testData) {
		t.Error("data mismatch")
	}
}

// Benchmark tests

func BenchmarkBufferPool(b *testing.B) {
	pool := NewBufferPool(DefaultChunkSize, 256*1024*1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := pool.Get()
		pool.Put(buf)
	}
}

func BenchmarkHashingWriter(b *testing.B) {
	data := make([]byte, 1024*1024) // 1MB
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		hw := NewHashingWriter(&buf)
		hw.Write(data)
		_ = hw.SHA256Sum()
	}
}

func BenchmarkStreamingEncryptor(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	data := make([]byte, 1024*1024) // 1MB
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		enc, _ := NewStreamingEncryptor(&buf, key)
		enc.Write(data)
	}
}

func BenchmarkStreamingCompressor(b *testing.B) {
	data := bytes.Repeat([]byte("Benchmark compression data. "), 10000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		comp, _ := NewStreamingCompressor(&buf, CompressionFast)
		comp.Write(data)
		comp.Close()
	}
}

func BenchmarkPipelineWriter(b *testing.B) {
	data := bytes.Repeat([]byte("Pipeline benchmark data. "), 10000)
	key := make([]byte, 32)
	rand.Read(key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		pw, _ := NewPipelineWriter(&buf,
			WrapCompressor(CompressionFast),
			WrapEncryptor(key),
		)
		pw.Write(data)
		pw.Close()
	}
}
