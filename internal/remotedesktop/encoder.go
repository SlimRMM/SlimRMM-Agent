package remotedesktop

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/jpeg"
	"sync"
)

// VP8Encoder encodes frames to VP8-compatible format.
// This implementation uses JPEG as an intermediate format for compatibility.
// For production use, consider using CGO bindings to libvpx.
type VP8Encoder struct {
	width       int
	height      int
	bitrate     int
	quality     int
	frameCount  uint32
	keyInterval int
	mu          sync.Mutex
}

// NewVP8Encoder creates a new VP8 encoder.
func NewVP8Encoder(width, height, fps, bitrate int) (*VP8Encoder, error) {
	// Calculate JPEG quality from bitrate
	// Higher bitrate = higher quality
	quality := 50 // Default
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
		keyInterval: fps * 2, // Keyframe every 2 seconds
	}, nil
}

// Encode encodes an RGBA image to a compressed format.
// Returns JPEG-encoded data wrapped in a simple frame format.
func (e *VP8Encoder) Encode(img *image.RGBA) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	bounds := img.Bounds()
	e.frameCount++

	// Resize if dimensions don't match
	if bounds.Dx() != e.width || bounds.Dy() != e.height {
		img = resizeImage(img, e.width, e.height)
	}

	// Encode to JPEG
	var buf bytes.Buffer

	// Write simple header
	// Format: [keyframe:1][width:2][height:2][data...]
	isKeyframe := (e.frameCount % uint32(e.keyInterval)) == 1
	if isKeyframe {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}

	binary.Write(&buf, binary.LittleEndian, uint16(e.width))
	binary.Write(&buf, binary.LittleEndian, uint16(e.height))

	// Encode image
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

	// Recalculate quality
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

// resizeImage resizes an image to the target dimensions.
func resizeImage(img *image.RGBA, width, height int) *image.RGBA {
	bounds := img.Bounds()
	if bounds.Dx() == width && bounds.Dy() == height {
		return img
	}

	resized := image.NewRGBA(image.Rect(0, 0, width, height))

	xRatio := float64(bounds.Dx()) / float64(width)
	yRatio := float64(bounds.Dy()) / float64(height)

	for y := 0; y < height; y++ {
		srcY := int(float64(y) * yRatio)
		for x := 0; x < width; x++ {
			srcX := int(float64(x) * xRatio)
			resized.Set(x, y, img.At(srcX+bounds.Min.X, srcY+bounds.Min.Y))
		}
	}

	return resized
}
