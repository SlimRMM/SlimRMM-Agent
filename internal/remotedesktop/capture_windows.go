//go:build cgo && windows

package remotedesktop

import (
	"bytes"
	"fmt"
	"image"
	"image/draw"
	"image/jpeg"
	"log"
	"sync"

	"github.com/kbinani/screenshot"
	"github.com/slimrmm/slimrmm-agent/internal/helper"
)

// ScreenCapture handles screen capture operations on Windows.
// It uses the helper process when running as a service (Session 0).
type ScreenCapture struct {
	monitors     []Monitor
	mu           sync.RWMutex
	helperClient *helper.Client
	useHelper    bool
}

// NewScreenCapture creates a new screen capture instance.
func NewScreenCapture() (*ScreenCapture, error) {
	sc := &ScreenCapture{}

	// Try direct capture first
	if err := sc.tryDirectCapture(); err == nil {
		log.Printf("Using direct screen capture")
		sc.useHelper = false
	} else {
		// Direct capture failed (likely Session 0), try helper
		log.Printf("Direct capture failed (%v), starting helper", err)
		sc.helperClient = helper.NewClient()
		if err := sc.helperClient.Start(); err != nil {
			return nil, fmt.Errorf("starting helper: %w", err)
		}
		sc.useHelper = true
		log.Printf("Using helper process for screen capture")
	}

	sc.updateMonitors()

	if len(sc.monitors) == 0 {
		if sc.helperClient != nil {
			sc.helperClient.Stop()
		}
		return nil, fmt.Errorf("no displays found")
	}

	return sc, nil
}

// tryDirectCapture tests if direct screen capture works
func (sc *ScreenCapture) tryDirectCapture() error {
	n := screenshot.NumActiveDisplays()
	if n == 0 {
		return fmt.Errorf("no displays")
	}

	bounds := screenshot.GetDisplayBounds(0)
	_, err := screenshot.CaptureRect(bounds)
	return err
}

// updateMonitors refreshes the list of available monitors.
func (sc *ScreenCapture) updateMonitors() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.useHelper && sc.helperClient != nil {
		monitors, err := sc.helperClient.GetMonitors()
		if err != nil {
			log.Printf("Helper GetMonitors failed: %v", err)
			return
		}

		sc.monitors = make([]Monitor, 0, len(monitors))
		for _, m := range monitors {
			sc.monitors = append(sc.monitors, Monitor{
				ID:      m.ID,
				Left:    m.Left,
				Top:     m.Top,
				Width:   m.Width,
				Height:  m.Height,
				Name:    fmt.Sprintf("Monitor %d", m.ID),
				Primary: m.Primary,
			})
		}
		return
	}

	// Direct capture
	n := screenshot.NumActiveDisplays()
	sc.monitors = make([]Monitor, 0, n)

	for i := 0; i < n; i++ {
		bounds := screenshot.GetDisplayBounds(i)
		sc.monitors = append(sc.monitors, Monitor{
			ID:      i + 1,
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
	if sc.useHelper && sc.helperClient != nil {
		return sc.captureViaHelper(monitorID)
	}
	return sc.captureDirectly(monitorID)
}

// captureViaHelper captures screen through the helper process
func (sc *ScreenCapture) captureViaHelper(monitorID int) (*image.RGBA, error) {
	data, resp, err := sc.helperClient.CaptureScreen(monitorID, 90, 1.0)
	if err != nil {
		// Try to reconnect and retry once
		log.Printf("Capture failed, reconnecting helper: %v", err)
		if err := sc.helperClient.Reconnect(); err != nil {
			return nil, fmt.Errorf("helper reconnect failed: %w", err)
		}
		data, resp, err = sc.helperClient.CaptureScreen(monitorID, 90, 1.0)
		if err != nil {
			return nil, fmt.Errorf("capture after reconnect: %w", err)
		}
	}

	if resp.Format != "jpeg" {
		return nil, fmt.Errorf("unexpected format: %s", resp.Format)
	}

	// Decode JPEG
	img, err := jpeg.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decoding jpeg: %w", err)
	}

	// Convert to RGBA
	bounds := img.Bounds()
	rgba := image.NewRGBA(bounds)
	draw.Draw(rgba, bounds, img, bounds.Min, draw.Src)

	return rgba, nil
}

// captureDirectly captures screen using kbinani/screenshot
func (sc *ScreenCapture) captureDirectly(monitorID int) (*image.RGBA, error) {
	idx := monitorID - 1

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
	if sc.useHelper && sc.helperClient != nil {
		// For helper mode, capture each monitor and combine
		sc.mu.RLock()
		monitors := make([]Monitor, len(sc.monitors))
		copy(monitors, sc.monitors)
		sc.mu.RUnlock()

		if len(monitors) == 0 {
			return nil, fmt.Errorf("no monitors available")
		}

		// Calculate total bounds
		var minX, minY, maxX, maxY int
		for i, m := range monitors {
			if i == 0 || m.Left < minX {
				minX = m.Left
			}
			if i == 0 || m.Top < minY {
				minY = m.Top
			}
			right := m.Left + m.Width
			bottom := m.Top + m.Height
			if i == 0 || right > maxX {
				maxX = right
			}
			if i == 0 || bottom > maxY {
				maxY = bottom
			}
		}

		totalBounds := image.Rect(minX, minY, maxX, maxY)
		combined := image.NewRGBA(totalBounds)

		// Capture each monitor
		for _, m := range monitors {
			img, err := sc.captureViaHelper(m.ID)
			if err != nil {
				continue
			}
			destRect := image.Rect(m.Left, m.Top, m.Left+m.Width, m.Top+m.Height)
			draw.Draw(combined, destRect, img, image.Point{}, draw.Src)
		}

		return combined, nil
	}

	// Direct capture
	n := screenshot.NumActiveDisplays()
	if n == 0 {
		return nil, fmt.Errorf("no displays found")
	}

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

// HandleInput sends input event to helper (Windows-specific)
func (sc *ScreenCapture) HandleInput(event helper.InputEvent) error {
	if !sc.useHelper || sc.helperClient == nil {
		return nil // Direct input handled elsewhere
	}
	return sc.helperClient.SendInput(event)
}

// IsUsingHelper returns whether the helper is being used
func (sc *ScreenCapture) IsUsingHelper() bool {
	return sc.useHelper
}

// ConfigureInputController sets up the input controller to use the helper if needed
func (sc *ScreenCapture) ConfigureInputController(ic *InputController) {
	if sc.useHelper && sc.helperClient != nil {
		ic.SetHelper(sc.helperClient, true)
	}
}

// Close releases resources.
func (sc *ScreenCapture) Close() {
	if sc.helperClient != nil {
		sc.helperClient.Stop()
		sc.helperClient = nil
	}
}
