//go:build darwin && cgo

package remotedesktop

/*
#cgo CFLAGS: -x objective-c -Wno-deprecated-declarations
#cgo LDFLAGS: -framework CoreGraphics -framework CoreFoundation

#include <CoreGraphics/CoreGraphics.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>

// Image options matching mss Python library
static const uint32_t kImageOptions = (1 << 0) | (1 << 1) | (1 << 4); // BoundsIgnoreFraming | ShouldBeOpaque | NominalResolution

// Function pointer type for CGWindowListCreateImage
typedef CGImageRef (*CGWindowListCreateImageFunc)(CGRect, uint32_t, uint32_t, uint32_t);

// Dynamically loaded function pointer
static CGWindowListCreateImageFunc _CGWindowListCreateImage = NULL;
static int _initialized = 0;

// Initialize dynamic loading
static void initCapture() {
    if (_initialized) return;
    _initialized = 1;

    // Load CoreGraphics framework
    void* handle = dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", RTLD_LAZY);
    if (handle) {
        _CGWindowListCreateImage = (CGWindowListCreateImageFunc)dlsym(handle, "CGWindowListCreateImage");
    }
}

// Get number of active displays
int GetDisplayCount() {
    uint32_t count = 0;
    CGGetActiveDisplayList(0, NULL, &count);
    return (int)count;
}

// Get display bounds
void GetDisplayBounds(int index, int* x, int* y, int* width, int* height) {
    uint32_t count = 0;
    CGGetActiveDisplayList(0, NULL, &count);

    if (index < 0 || index >= (int)count) {
        *x = 0; *y = 0; *width = 0; *height = 0;
        return;
    }

    CGDirectDisplayID* displays = (CGDirectDisplayID*)malloc(count * sizeof(CGDirectDisplayID));
    CGGetActiveDisplayList(count, displays, &count);

    CGRect bounds = CGDisplayBounds(displays[index]);
    bounds = CGRectStandardize(bounds);

    *x = (int)bounds.origin.x;
    *y = (int)bounds.origin.y;
    *width = (int)bounds.size.width;
    *height = (int)bounds.size.height;

    free(displays);
}

// Capture screen region using CGWindowListCreateImage (loaded dynamically to work on macOS 15+)
// Returns pixel data in BGRA format, or NULL on failure
// Caller must free() the returned buffer
unsigned char* CaptureRect(int x, int y, int width, int height, int* outWidth, int* outHeight, int* outBytesPerRow) {
    initCapture();

    if (_CGWindowListCreateImage == NULL) {
        return NULL;
    }

    CGRect rect = CGRectMake(x, y, width, height);

    // Use CGWindowListCreateImage via dynamic loading
    // Parameters: rect, listOption (kCGWindowListOptionOnScreenOnly=1), windowID (0=all), imageOption
    CGImageRef image = _CGWindowListCreateImage(rect, 1, 0, kImageOptions);

    if (image == NULL) {
        return NULL;
    }

    size_t imgWidth = CGImageGetWidth(image);
    size_t imgHeight = CGImageGetHeight(image);
    size_t bytesPerRow = CGImageGetBytesPerRow(image);
    size_t bitsPerPixel = CGImageGetBitsPerPixel(image);
    size_t bytesPerPixel = (bitsPerPixel + 7) / 8;

    CGDataProviderRef provider = CGImageGetDataProvider(image);
    CFDataRef data = CGDataProviderCopyData(provider);

    if (data == NULL) {
        CGImageRelease(image);
        return NULL;
    }

    const UInt8* srcData = CFDataGetBytePtr(data);
    size_t dataLen = CFDataGetLength(data);

    // Allocate output buffer (we need width * height * 4 bytes for BGRA)
    size_t outSize = imgWidth * imgHeight * 4;
    unsigned char* outData = (unsigned char*)malloc(outSize);

    if (outData == NULL) {
        CFRelease(data);
        CGImageRelease(image);
        return NULL;
    }

    // Copy data, removing any row padding
    if (bytesPerPixel * imgWidth == bytesPerRow) {
        // No padding, direct copy
        memcpy(outData, srcData, outSize < dataLen ? outSize : dataLen);
    } else {
        // Has padding, copy row by row
        for (size_t row = 0; row < imgHeight; row++) {
            size_t srcOffset = row * bytesPerRow;
            size_t dstOffset = row * imgWidth * bytesPerPixel;
            memcpy(outData + dstOffset, srcData + srcOffset, imgWidth * bytesPerPixel);
        }
    }

    *outWidth = (int)imgWidth;
    *outHeight = (int)imgHeight;
    *outBytesPerRow = (int)(imgWidth * 4);

    CFRelease(data);
    CGImageRelease(image);

    return outData;
}

void FreeImageData(unsigned char* data) {
    if (data != NULL) {
        free(data);
    }
}
*/
import "C"

import (
	"fmt"
	"image"
	"sync"
	"unsafe"
)

// ScreenCapture handles screen capture operations on macOS.
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

	n := int(C.GetDisplayCount())
	sc.monitors = make([]Monitor, 0, n)

	for i := 0; i < n; i++ {
		var x, y, width, height C.int
		C.GetDisplayBounds(C.int(i), &x, &y, &width, &height)

		sc.monitors = append(sc.monitors, Monitor{
			ID:      i + 1, // 1-based index
			Left:    int(x),
			Top:     int(y),
			Width:   int(width),
			Height:  int(height),
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
	sc.mu.RLock()
	var monitor *Monitor
	for _, m := range sc.monitors {
		if m.ID == monitorID {
			mon := m
			monitor = &mon
			break
		}
	}
	sc.mu.RUnlock()

	if monitor == nil {
		// Refresh monitors and try again
		sc.updateMonitors()
		sc.mu.RLock()
		for _, m := range sc.monitors {
			if m.ID == monitorID {
				mon := m
				monitor = &mon
				break
			}
		}
		sc.mu.RUnlock()
	}

	if monitor == nil {
		return nil, fmt.Errorf("monitor %d not found", monitorID)
	}

	var outWidth, outHeight, outBytesPerRow C.int
	data := C.CaptureRect(
		C.int(monitor.Left),
		C.int(monitor.Top),
		C.int(monitor.Width),
		C.int(monitor.Height),
		&outWidth, &outHeight, &outBytesPerRow,
	)

	if data == nil {
		return nil, fmt.Errorf("cannot capture display")
	}
	defer C.FreeImageData(data)

	width := int(outWidth)
	height := int(outHeight)

	// Create Go image from C data
	// Data is in BGRA format, we need to convert to RGBA
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Copy and convert BGRA -> RGBA
	srcSlice := unsafe.Slice((*byte)(unsafe.Pointer(data)), width*height*4)
	for i := 0; i < width*height; i++ {
		srcIdx := i * 4
		// BGRA -> RGBA: swap B and R
		img.Pix[srcIdx+0] = srcSlice[srcIdx+2] // R <- B
		img.Pix[srcIdx+1] = srcSlice[srcIdx+1] // G <- G
		img.Pix[srcIdx+2] = srcSlice[srcIdx+0] // B <- R
		img.Pix[srcIdx+3] = srcSlice[srcIdx+3] // A <- A
	}

	return img, nil
}

// CaptureAll captures all monitors as a single image.
func (sc *ScreenCapture) CaptureAll() (*image.RGBA, error) {
	// For now, just capture the primary monitor
	return sc.CaptureFrame(1)
}

// Close releases resources.
func (sc *ScreenCapture) Close() {
	// No persistent resources to release
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
