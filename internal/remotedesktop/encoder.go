//go:build cgo

package remotedesktop

import (
	"bytes"
	"image"
	"image/jpeg"
	"sync"
)

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

	var buf bytes.Buffer
	opts := &jpeg.Options{Quality: e.quality}
	if err := jpeg.Encode(&buf, img, opts); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
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
