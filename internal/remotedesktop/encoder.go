//go:build cgo

package remotedesktop

import (
	"bytes"
	"image"
	"image/jpeg"
	"sync"
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// JPEGEncoder encodes frames to JPEG format for WebSocket transport.
type JPEGEncoder struct {
	quality int
	mu      sync.Mutex
}

// NewJPEGEncoder creates a new JPEG encoder.
func NewJPEGEncoder(quality int) *JPEGEncoder {
	if quality < 1 {
		quality = 50
	}
	if quality > 100 {
		quality = 100
	}
	return &JPEGEncoder{
		quality: quality,
	}
}

// Encode encodes an RGBA image to JPEG.
func (e *JPEGEncoder) Encode(img *image.RGBA) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufferPool.Put(buf)

	opts := &jpeg.Options{Quality: e.quality}
	if err := jpeg.Encode(buf, img, opts); err != nil {
		return nil, err
	}

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// SetQuality updates the JPEG quality (1-100).
func (e *JPEGEncoder) SetQuality(quality int) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if quality < 1 {
		quality = 50
	}
	if quality > 100 {
		quality = 100
	}
	e.quality = quality
}

// Close releases encoder resources.
func (e *JPEGEncoder) Close() error {
	return nil
}
