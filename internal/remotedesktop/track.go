package remotedesktop

import (
	"image"
	"log/slog"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
)

const (
	videoClockRate = 90000
)

// VideoTrack wraps a TrackLocalStaticSample for screen capture streaming.
type VideoTrack struct {
	track     *webrtc.TrackLocalStaticSample
	capture   *ScreenCapture
	monitorID int
	quality   string
	fps       int

	encoder *VP8Encoder
	logger  *slog.Logger

	running bool
	stopCh  chan struct{}
	mu      sync.RWMutex
}

// NewVideoTrack creates a new video track for screen capture.
func NewVideoTrack(capture *ScreenCapture, monitorID int, quality string, logger *slog.Logger) (*VideoTrack, error) {
	if logger == nil {
		logger = slog.Default()
	}

	settings := QualityPresets[quality]

	// Get initial frame dimensions for encoder setup
	frame, err := capture.CaptureFrame(monitorID)
	if err != nil {
		return nil, err
	}

	scaledFrame := ScaleImage(frame, settings.Scale)
	bounds := scaledFrame.Bounds()

	encoder, err := NewVP8Encoder(bounds.Dx(), bounds.Dy(), settings.FPS, settings.Bitrate)
	if err != nil {
		return nil, err
	}

	// Create a static sample track
	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{
			MimeType:  webrtc.MimeTypeVP8,
			ClockRate: videoClockRate,
		},
		"video",  // Track ID
		"screen", // Stream ID
	)
	if err != nil {
		return nil, err
	}

	return &VideoTrack{
		track:     track,
		capture:   capture,
		monitorID: monitorID,
		quality:   quality,
		fps:       settings.FPS,
		encoder:   encoder,
		logger:    logger,
		stopCh:    make(chan struct{}),
		running:   false,
	}, nil
}

// Track returns the underlying WebRTC track.
func (t *VideoTrack) Track() *webrtc.TrackLocalStaticSample {
	return t.track
}

// Start begins the capture loop.
func (t *VideoTrack) Start() {
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return
	}
	t.running = true
	t.mu.Unlock()

	go t.captureLoop()
}

// captureLoop continuously captures frames and sends them over WebRTC.
func (t *VideoTrack) captureLoop() {
	t.mu.RLock()
	fps := t.fps
	t.mu.RUnlock()

	ticker := time.NewTicker(time.Second / time.Duration(fps))
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.mu.RLock()
			if !t.running {
				t.mu.RUnlock()
				return
			}
			monitorID := t.monitorID
			quality := t.quality
			currentFPS := t.fps
			t.mu.RUnlock()

			// Update ticker if FPS changed
			if currentFPS != fps {
				fps = currentFPS
				ticker.Reset(time.Second / time.Duration(fps))
			}

			// Capture frame
			frame, err := t.capture.CaptureFrame(monitorID)
			if err != nil {
				t.logger.Error("capturing frame", "error", err)
				continue
			}

			// Scale if needed
			settings := QualityPresets[quality]
			if settings.Scale < 1.0 {
				frame = ScaleImage(frame, settings.Scale)
			}

			// Encode frame
			data, err := t.encodeFrame(frame)
			if err != nil {
				t.logger.Error("encoding frame", "error", err)
				continue
			}

			if len(data) == 0 {
				continue
			}

			// Write sample to track
			if err := t.track.WriteSample(media.Sample{
				Data:     data,
				Duration: time.Second / time.Duration(fps),
			}); err != nil {
				t.logger.Debug("writing sample", "error", err)
			}
		}
	}
}

// encodeFrame converts an image to encoded video data.
func (t *VideoTrack) encodeFrame(img *image.RGBA) ([]byte, error) {
	t.mu.RLock()
	encoder := t.encoder
	t.mu.RUnlock()

	if encoder == nil {
		return nil, nil
	}

	return encoder.Encode(img)
}

// SetQuality changes the video quality preset.
func (t *VideoTrack) SetQuality(quality string) {
	settings, ok := QualityPresets[quality]
	if !ok {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	t.quality = quality
	t.fps = settings.FPS

	// Update encoder bitrate
	if t.encoder != nil {
		t.encoder.SetBitrate(settings.Bitrate)
	}

	t.logger.Info("video quality changed",
		"quality", quality,
		"fps", settings.FPS,
		"scale", settings.Scale,
		"bitrate", settings.Bitrate,
	)
}

// SetMonitor switches to a different monitor.
func (t *VideoTrack) SetMonitor(monitorID int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.monitorID = monitorID
	t.logger.Info("video monitor changed", "monitor_id", monitorID)
}

// Stop terminates the video track.
func (t *VideoTrack) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.running {
		return
	}

	t.running = false
	close(t.stopCh)

	if t.encoder != nil {
		t.encoder.Close()
		t.encoder = nil
	}

	t.logger.Info("video track stopped")
}

// IsRunning returns whether the track is active.
func (t *VideoTrack) IsRunning() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.running
}
