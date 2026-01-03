//go:build cgo

package remotedesktop

import (
	"context"
	"fmt"
	"sync"

	"golang.design/x/clipboard"
)

// ClipboardManager handles clipboard synchronization.
type ClipboardManager struct {
	initialized bool
	mu          sync.Mutex
}

// NewClipboardManager creates a new clipboard manager.
func NewClipboardManager() (*ClipboardManager, error) {
	cm := &ClipboardManager{}

	if err := clipboard.Init(); err != nil {
		return nil, fmt.Errorf("initializing clipboard: %w", err)
	}

	cm.initialized = true
	return cm, nil
}

// GetText returns the current clipboard text content.
func (cm *ClipboardManager) GetText() (string, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if !cm.initialized {
		return "", fmt.Errorf("clipboard not initialized")
	}

	data := clipboard.Read(clipboard.FmtText)
	return string(data), nil
}

// SetText sets the clipboard text content.
func (cm *ClipboardManager) SetText(text string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if !cm.initialized {
		return fmt.Errorf("clipboard not initialized")
	}

	clipboard.Write(clipboard.FmtText, []byte(text))
	return nil
}

// GetImage returns the current clipboard image content.
func (cm *ClipboardManager) GetImage() ([]byte, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if !cm.initialized {
		return nil, fmt.Errorf("clipboard not initialized")
	}

	data := clipboard.Read(clipboard.FmtImage)
	return data, nil
}

// SetImage sets the clipboard image content.
func (cm *ClipboardManager) SetImage(data []byte) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if !cm.initialized {
		return fmt.Errorf("clipboard not initialized")
	}

	clipboard.Write(clipboard.FmtImage, data)
	return nil
}

// Watch starts watching for clipboard changes.
func (cm *ClipboardManager) Watch(ctx context.Context, onChange func(format string, data []byte)) {
	go func() {
		textCh := clipboard.Watch(ctx, clipboard.FmtText)
		for data := range textCh {
			onChange("text", data)
		}
	}()
}

// Close releases clipboard resources.
func (cm *ClipboardManager) Close() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.initialized = false
}
