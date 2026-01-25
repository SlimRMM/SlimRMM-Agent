package backup

import (
	"bytes"
	"compress/gzip"
	"io"
)

// CompressionLevel defines the compression levels supported.
type CompressionLevel string

const (
	CompressionNone     CompressionLevel = "none"
	CompressionFast     CompressionLevel = "fast"
	CompressionBalanced CompressionLevel = "balanced"
	CompressionHigh     CompressionLevel = "high"
	CompressionMaximum  CompressionLevel = "maximum"
)

// compressionLevelToGzip maps compression levels to gzip compression levels.
var compressionLevelToGzip = map[CompressionLevel]int{
	CompressionNone:     gzip.NoCompression,
	CompressionFast:     gzip.BestSpeed,
	CompressionBalanced: gzip.DefaultCompression,
	CompressionHigh:     7,
	CompressionMaximum:  gzip.BestCompression,
}

// Compressor provides compression/decompression services.
type Compressor interface {
	// Compress compresses data using the specified level.
	Compress(data []byte, level CompressionLevel) ([]byte, error)

	// Decompress decompresses gzip data.
	Decompress(data []byte) ([]byte, error)
}

// GzipCompressor implements Compressor using gzip.
type GzipCompressor struct{}

// NewGzipCompressor creates a new gzip compressor.
func NewGzipCompressor() *GzipCompressor {
	return &GzipCompressor{}
}

// Compress compresses data using gzip.
func (c *GzipCompressor) Compress(data []byte, level CompressionLevel) ([]byte, error) {
	gzipLevel, ok := compressionLevelToGzip[level]
	if !ok {
		gzipLevel = gzip.DefaultCompression
	}

	if level == CompressionNone {
		return data, nil
	}

	var buf bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buf, gzipLevel)
	if err != nil {
		return nil, &ErrCompressionFailed{Err: err}
	}

	if _, err := writer.Write(data); err != nil {
		writer.Close()
		return nil, &ErrCompressionFailed{Err: err}
	}

	if err := writer.Close(); err != nil {
		return nil, &ErrCompressionFailed{Err: err}
	}

	return buf.Bytes(), nil
}

// Decompress decompresses gzip data.
func (c *GzipCompressor) Decompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, &ErrCompressionFailed{Err: err}
	}
	defer reader.Close()

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return nil, &ErrCompressionFailed{Err: err}
	}

	return decompressed, nil
}

// GetGzipLevel returns the gzip compression level for a CompressionLevel.
func GetGzipLevel(level CompressionLevel) int {
	if l, ok := compressionLevelToGzip[level]; ok {
		return l
	}
	return gzip.DefaultCompression
}
