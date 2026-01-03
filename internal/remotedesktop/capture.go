//go:build cgo && !darwin

package remotedesktop

import (
	"fmt"
	"image"
	"image/draw"
	"sync"

	"github.com/kbinani/screenshot"
)

// ScreenCapture handles screen capture operations.
type ScreenCapture struct {
	monitors []Monitor
	mu       sync.RWMutex
}

// NewScreenCapture creates a new screen capture instance.
func NewScreenCapture() (*ScreenCapture, error) {
	sc := &ScreenCapture{}
	sc.updateMonitors()

	if len(sc.monitors) == 0 {
		return nil, fmt.Errorf("no displays found")
	}

	return sc, nil
}

// updateMonitors refreshes the list of available monitors.
func (sc *ScreenCapture) updateMonitors() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	n := screenshot.NumActiveDisplays()
	sc.monitors = make([]Monitor, 0, n)

	for i := 0; i < n; i++ {
		bounds := screenshot.GetDisplayBounds(i)
		sc.monitors = append(sc.monitors, Monitor{
			ID:      i + 1, // 1-based index like Python implementation
			Left:    bounds.Min.X,
			Top:     bounds.Min.Y,
			Width:   bounds.Dx(),
			Height:  bounds.Dy(),
			Name:    fmt.Sprintf("Monitor %d", i+1),
			Primary: i == 0,
		})
	}
}

// GetMonitors returns the list of available monitors.
func (sc *ScreenCapture) GetMonitors() []Monitor {
	sc.updateMonitors()

	sc.mu.RLock()
	defer sc.mu.RUnlock()

	result := make([]Monitor, len(sc.monitors))
	copy(result, sc.monitors)
	return result
}

// GetMonitor returns a specific monitor by ID.
func (sc *ScreenCapture) GetMonitor(monitorID int) *Monitor {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	for _, m := range sc.monitors {
		if m.ID == monitorID {
			mon := m
			return &mon
		}
	}
	return nil
}

// CaptureFrame captures a single frame from the specified monitor.
func (sc *ScreenCapture) CaptureFrame(monitorID int) (*image.RGBA, error) {
	idx := monitorID - 1 // Convert to 0-based index

	n := screenshot.NumActiveDisplays()
	if idx < 0 || idx >= n {
		return nil, fmt.Errorf("invalid monitor ID: %d (available: 1-%d)", monitorID, n)
	}

	bounds := screenshot.GetDisplayBounds(idx)
	img, err := screenshot.CaptureRect(bounds)
	if err != nil {
		return nil, fmt.Errorf("capturing screen: %w", err)
	}

	return img, nil
}

// CaptureAll captures all monitors as a single image.
func (sc *ScreenCapture) CaptureAll() (*image.RGBA, error) {
	n := screenshot.NumActiveDisplays()
	if n == 0 {
		return nil, fmt.Errorf("no displays found")
	}

	// Calculate total bounds
	var minX, minY, maxX, maxY int
	for i := 0; i < n; i++ {
		bounds := screenshot.GetDisplayBounds(i)
		if i == 0 || bounds.Min.X < minX {
			minX = bounds.Min.X
		}
		if i == 0 || bounds.Min.Y < minY {
			minY = bounds.Min.Y
		}
		if i == 0 || bounds.Max.X > maxX {
			maxX = bounds.Max.X
		}
		if i == 0 || bounds.Max.Y > maxY {
			maxY = bounds.Max.Y
		}
	}

	totalBounds := image.Rect(minX, minY, maxX, maxY)
	combined := image.NewRGBA(totalBounds)

	// Capture each display and composite
	for i := 0; i < n; i++ {
		bounds := screenshot.GetDisplayBounds(i)
		img, err := screenshot.CaptureRect(bounds)
		if err != nil {
			continue
		}
		draw.Draw(combined, bounds, img, bounds.Min, draw.Src)
	}

	return combined, nil
}

// ScaleImage scales an image by the given factor.
func ScaleImage(img *image.RGBA, scale float64) *image.RGBA {
	if scale >= 1.0 {
		return img
	}

	bounds := img.Bounds()
	newWidth := int(float64(bounds.Dx()) * scale)
	newHeight := int(float64(bounds.Dy()) * scale)

	if newWidth < 1 {
		newWidth = 1
	}
	if newHeight < 1 {
		newHeight = 1
	}

	scaled := image.NewRGBA(image.Rect(0, 0, newWidth, newHeight))

	// Simple nearest-neighbor scaling for performance
	xRatio := float64(bounds.Dx()) / float64(newWidth)
	yRatio := float64(bounds.Dy()) / float64(newHeight)

	for y := 0; y < newHeight; y++ {
		srcY := int(float64(y) * yRatio)
		for x := 0; x < newWidth; x++ {
			srcX := int(float64(x) * xRatio)
			scaled.Set(x, y, img.At(srcX+bounds.Min.X, srcY+bounds.Min.Y))
		}
	}

	return scaled
}

// Close releases resources.
func (sc *ScreenCapture) Close() {
	// No resources to release for kbinani/screenshot
}
