//go:build cgo

package remotedesktop

import (
	"bytes"
	"image"
	"image/jpeg"
	"sync"
)

// VP8Encoder encodes frames - currently outputs JPEG until VP8 is properly set up.
// TODO: Implement real VP8 encoding with libvpx when build infrastructure is ready.
type VP8Encoder struct {
	width       int
	height      int
	bitrate     int
	quality     int
	frameCount  uint32
	keyInterval int
	mu          sync.Mutex
}

// NewVP8Encoder creates a new encoder.
func NewVP8Encoder(width, height, fps, bitrate int) (*VP8Encoder, error) {
	// Calculate JPEG quality from bitrate
	quality := 50
	if bitrate >= 4_000_000 {
		quality = 85
	} else if bitrate >= 2_000_000 {
		quality = 75
	} else if bitrate >= 1_000_000 {
		quality = 65
	}

	return &VP8Encoder{
		width:       width,
		height:      height,
		bitrate:     bitrate,
		quality:     quality,
		keyInterval: fps * 2,
	}, nil
}

// Encode encodes an RGBA image.
// NOTE: This currently returns nil to signal that video track encoding is not available.
// The video will be sent via data channel instead.
func (e *VP8Encoder) Encode(img *image.RGBA) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Return nil to signal video track encoding not available
	// This causes the video track to not send frames
	// Frames will be sent via data channel instead
	return nil, nil
}

// EncodeJPEG encodes an image to JPEG for data channel transport.
func (e *VP8Encoder) EncodeJPEG(img *image.RGBA) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var buf bytes.Buffer
	opts := &jpeg.Options{Quality: e.quality}
	if err := jpeg.Encode(&buf, img, opts); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// SetBitrate updates the encoder bitrate.
func (e *VP8Encoder) SetBitrate(bitrate int) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.bitrate = bitrate

	if bitrate >= 4_000_000 {
		e.quality = 85
	} else if bitrate >= 2_000_000 {
		e.quality = 75
	} else if bitrate >= 1_000_000 {
		e.quality = 65
	} else {
		e.quality = 50
	}
}

// SetDimensions updates the encoder dimensions.
func (e *VP8Encoder) SetDimensions(width, height int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.width = width
	e.height = height
}

// Close releases encoder resources.
func (e *VP8Encoder) Close() error {
	return nil
}
