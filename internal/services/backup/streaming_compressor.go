// Package backup provides streaming compression for backup operations.
package backup

import (
	"compress/gzip"
	"fmt"
	"io"
)

// StreamingCompressor wraps a writer with gzip compression.
// Data written to this compressor is compressed on-the-fly and written to the underlying writer.
type StreamingCompressor struct {
	gw      *gzip.Writer
	level   int
	written int64
}

// NewStreamingCompressor creates a new streaming compressor with the specified level.
func NewStreamingCompressor(w io.Writer, level CompressionLevel) (*StreamingCompressor, error) {
	gzLevel := gzip.DefaultCompression

	switch level {
	case CompressionNone:
		gzLevel = gzip.NoCompression
	case CompressionFast:
		gzLevel = gzip.BestSpeed
	case CompressionBalanced:
		gzLevel = gzip.DefaultCompression
	case CompressionHigh:
		gzLevel = 7
	case CompressionMaximum:
		gzLevel = gzip.BestCompression
	}

	gw, err := gzip.NewWriterLevel(w, gzLevel)
	if err != nil {
		return nil, fmt.Errorf("creating gzip writer: %w", err)
	}

	return &StreamingCompressor{
		gw:    gw,
		level: gzLevel,
	}, nil
}

// Write implements io.Writer with compression.
func (sc *StreamingCompressor) Write(p []byte) (n int, err error) {
	n, err = sc.gw.Write(p)
	sc.written += int64(n)
	return n, err
}

// Close flushes and closes the compressor.
func (sc *StreamingCompressor) Close() error {
	return sc.gw.Close()
}

// Flush flushes the compressor.
func (sc *StreamingCompressor) Flush() error {
	return sc.gw.Flush()
}

// Written returns the number of uncompressed bytes written.
func (sc *StreamingCompressor) Written() int64 {
	return sc.written
}

// StreamingDecompressor wraps a reader with gzip decompression.
type StreamingDecompressor struct {
	gr   *gzip.Reader
	read int64
}

// NewStreamingDecompressor creates a new streaming decompressor.
func NewStreamingDecompressor(r io.Reader) (*StreamingDecompressor, error) {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("creating gzip reader: %w", err)
	}

	return &StreamingDecompressor{
		gr: gr,
	}, nil
}

// Read implements io.Reader with decompression.
func (sd *StreamingDecompressor) Read(p []byte) (n int, err error) {
	n, err = sd.gr.Read(p)
	sd.read += int64(n)
	return n, err
}

// Close closes the decompressor.
func (sd *StreamingDecompressor) Close() error {
	return sd.gr.Close()
}

// Read returns the number of decompressed bytes read.
func (sd *StreamingDecompressor) Decompressed() int64 {
	return sd.read
}

// PipelineWriter chains multiple writers for streaming backup pipeline.
// Usage: source -> compress -> encrypt -> hash -> upload
type PipelineWriter struct {
	writers []io.WriteCloser
	final   io.Writer
}

// NewPipelineWriter creates a chained pipeline of writers.
// Writers are called in order: first writer wraps the second, etc.
func NewPipelineWriter(final io.Writer, wrappers ...func(io.Writer) (io.WriteCloser, error)) (*PipelineWriter, error) {
	pw := &PipelineWriter{
		final:   final,
		writers: make([]io.WriteCloser, 0, len(wrappers)),
	}

	// Build chain from final to first
	current := final
	for i := len(wrappers) - 1; i >= 0; i-- {
		w, err := wrappers[i](current)
		if err != nil {
			// Close any already-created writers
			for _, closer := range pw.writers {
				closer.Close()
			}
			return nil, fmt.Errorf("creating pipeline stage %d: %w", i, err)
		}
		pw.writers = append([]io.WriteCloser{w}, pw.writers...)
		current = w
	}

	return pw, nil
}

// Write writes to the first stage of the pipeline.
func (pw *PipelineWriter) Write(p []byte) (n int, err error) {
	if len(pw.writers) > 0 {
		return pw.writers[0].Write(p)
	}
	return pw.final.Write(p)
}

// Close closes all writers in the pipeline in order.
func (pw *PipelineWriter) Close() error {
	var firstErr error
	for _, w := range pw.writers {
		if err := w.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// WriteCloserFunc adapts a writer and close function to io.WriteCloser.
type WriteCloserFunc struct {
	io.Writer
	closeFunc func() error
}

// Close calls the close function.
func (wcf *WriteCloserFunc) Close() error {
	if wcf.closeFunc != nil {
		return wcf.closeFunc()
	}
	return nil
}

// WrapCompressor returns a pipeline wrapper function for compression.
func WrapCompressor(level CompressionLevel) func(io.Writer) (io.WriteCloser, error) {
	return func(w io.Writer) (io.WriteCloser, error) {
		return NewStreamingCompressor(w, level)
	}
}

// WrapEncryptor returns a pipeline wrapper function for encryption.
func WrapEncryptor(key []byte) func(io.Writer) (io.WriteCloser, error) {
	return func(w io.Writer) (io.WriteCloser, error) {
		enc, err := NewStreamingEncryptor(w, key)
		if err != nil {
			return nil, err
		}
		return &WriteCloserFunc{Writer: enc, closeFunc: nil}, nil
	}
}

// WrapHasher returns a pipeline wrapper function for hashing.
func WrapHasher() func(io.Writer) (io.WriteCloser, *HashingWriter, error) {
	return func(w io.Writer) (io.WriteCloser, *HashingWriter, error) {
		hw := NewHashingWriter(w)
		return &WriteCloserFunc{Writer: hw, closeFunc: nil}, hw, nil
	}
}

// MultiWriter writes to multiple writers simultaneously.
// Unlike io.MultiWriter, this tracks bytes written and handles errors better.
type MultiWriter struct {
	writers []io.Writer
	written int64
}

// NewMultiWriter creates a writer that writes to all provided writers.
func NewMultiWriter(writers ...io.Writer) *MultiWriter {
	return &MultiWriter{
		writers: writers,
	}
}

// Write implements io.Writer.
func (mw *MultiWriter) Write(p []byte) (n int, err error) {
	for _, w := range mw.writers {
		n, err = w.Write(p)
		if err != nil {
			return n, err
		}
		if n != len(p) {
			return n, io.ErrShortWrite
		}
	}
	mw.written += int64(len(p))
	return len(p), nil
}

// Written returns total bytes written.
func (mw *MultiWriter) Written() int64 {
	return mw.written
}

// TeeReader wraps a reader and writes all read data to a writer.
// Similar to io.TeeReader but with byte counting.
type TeeReader struct {
	r    io.Reader
	w    io.Writer
	read int64
}

// NewTeeReader creates a TeeReader.
func NewTeeReader(r io.Reader, w io.Writer) *TeeReader {
	return &TeeReader{r: r, w: w}
}

// Read implements io.Reader.
func (tr *TeeReader) Read(p []byte) (n int, err error) {
	n, err = tr.r.Read(p)
	if n > 0 {
		if _, werr := tr.w.Write(p[:n]); werr != nil {
			return n, werr
		}
		tr.read += int64(n)
	}
	return n, err
}

// BytesRead returns total bytes read.
func (tr *TeeReader) BytesRead() int64 {
	return tr.read
}
