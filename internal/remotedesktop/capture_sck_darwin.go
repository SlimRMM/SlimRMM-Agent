//go:build darwin && cgo

package remotedesktop

/*
#cgo CFLAGS: -x objective-c -Wno-deprecated-declarations -fobjc-arc
// We weak-link ScreenCaptureKit so the binary can load on older macOS versions
// that lack the framework.  The -weak_framework flag tells the linker to mark
// the dependency as optional.
#cgo LDFLAGS: -framework CoreGraphics -framework CoreFoundation -framework AppKit -weak_framework ScreenCaptureKit -framework CoreMedia -framework CoreVideo

// Conditionally compile ScreenCaptureKit code only when the SDK header is
// available.  On older SDKs or when cross-compiling the code gracefully
// compiles but the SCK functions return "not available".

#include <TargetConditionals.h>
#include <Availability.h>
#include <CoreGraphics/CoreGraphics.h>
#include <AppKit/AppKit.h>
#include <dispatch/dispatch.h>
#include <string.h>
#include <stdlib.h>

// ---------- Compile-time availability gate ----------
#if __has_include(<ScreenCaptureKit/ScreenCaptureKit.h>)

#include <ScreenCaptureKit/ScreenCaptureKit.h>
#define SCK_SDK_AVAILABLE 1
#else
#define SCK_SDK_AVAILABLE 0
#endif

// ---------- Runtime availability check ----------
static int sck_is_available() {
#if SCK_SDK_AVAILABLE
    // At runtime we rely on @available which checks the OS version.
    if (@available(macOS 12.3, *)) {
        return 1;
    }
#endif
    return 0;
}

// ---------- SCK capture implementation ----------

// Capture a single display via ScreenCaptureKit and return the raw BGRA pixel
// buffer.  |displayIndex| is the 0-based index into the CGGetActiveDisplayList.
// On success the caller must free() the returned buffer.
static unsigned char* sck_capture_display(int displayIndex,
                                          int* outWidth,
                                          int* outHeight,
                                          int* outBytesPerRow,
                                          char** outError) {
    *outWidth = 0;
    *outHeight = 0;
    *outBytesPerRow = 0;
    *outError = NULL;

#if !SCK_SDK_AVAILABLE
    *outError = strdup("ScreenCaptureKit SDK not available at compile time");
    return NULL;
#else
    if (!sck_is_available()) {
        *outError = strdup("ScreenCaptureKit requires macOS 12.3 or later");
        return NULL;
    }

    // Resolve the target CGDirectDisplayID from the index.
    uint32_t displayCount = 0;
    CGGetActiveDisplayList(0, NULL, &displayCount);
    if (displayIndex < 0 || displayIndex >= (int)displayCount) {
        *outError = strdup("display index out of range");
        return NULL;
    }
    CGDirectDisplayID *displays = (CGDirectDisplayID *)malloc(displayCount * sizeof(CGDirectDisplayID));
    CGGetActiveDisplayList(displayCount, displays, &displayCount);
    CGDirectDisplayID targetID = displays[displayIndex];
    free(displays);

    // We need to use @available again in the block scope for the compiler.
    if (@available(macOS 12.3, *)) {
        __block unsigned char* resultData = NULL;
        __block int rWidth = 0, rHeight = 0, rBytesPerRow = 0;
        __block char* rError = NULL;

        dispatch_semaphore_t sem = dispatch_semaphore_create(0);

        // 1. Enumerate shareable content to find the matching display.
        [SCShareableContent getShareableContentWithCompletionHandler:^(SCShareableContent * _Nullable content, NSError * _Nullable error) {
            if (error != nil || content == nil) {
                rError = strdup([[NSString stringWithFormat:@"SCShareableContent error: %@",
                                  error ? error.localizedDescription : @"nil content"] UTF8String]);
                dispatch_semaphore_signal(sem);
                return;
            }

            // Find the SCDisplay matching our CGDirectDisplayID.
            SCDisplay *targetDisplay = nil;
            for (SCDisplay *d in content.displays) {
                if (d.displayID == targetID) {
                    targetDisplay = d;
                    break;
                }
            }

            if (targetDisplay == nil) {
                rError = strdup("target display not found in SCShareableContent");
                dispatch_semaphore_signal(sem);
                return;
            }

            // 2. Build filter and configuration.
            SCContentFilter *filter = [[SCContentFilter alloc] initWithDisplay:targetDisplay excludingWindows:@[]];

            SCStreamConfiguration *config = [[SCStreamConfiguration alloc] init];
            config.width = (NSUInteger)targetDisplay.width;
            config.height = (NSUInteger)targetDisplay.height;
            config.pixelFormat = kCVPixelFormatType_32BGRA;
            config.showsCursor = YES;

            // 3. Capture a single screenshot.
            if (@available(macOS 14.0, *)) {
                // macOS 14+ has SCScreenshotManager
                [SCScreenshotManager captureImageWithFilter:filter
                                              configuration:config
                                          completionHandler:^(CGImageRef _Nullable image, NSError * _Nullable captureError) {
                    if (captureError != nil || image == NULL) {
                        rError = strdup([[NSString stringWithFormat:@"SCScreenshotManager error: %@",
                                          captureError ? captureError.localizedDescription : @"nil image"] UTF8String]);
                        dispatch_semaphore_signal(sem);
                        return;
                    }

                    // Extract pixel data from CGImage.
                    size_t w = CGImageGetWidth(image);
                    size_t h = CGImageGetHeight(image);

                    // Create a bitmap context in BGRA to draw the image into.
                    size_t bpr = w * 4;
                    unsigned char* buf = (unsigned char*)malloc(h * bpr);
                    if (buf == NULL) {
                        rError = strdup("malloc failed");
                        dispatch_semaphore_signal(sem);
                        return;
                    }

                    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
                    CGContextRef ctx = CGBitmapContextCreate(buf, w, h, 8, bpr,
                        cs, kCGImageAlphaPremultipliedFirst | kCGBitmapByteOrder32Little);
                    CGColorSpaceRelease(cs);

                    if (ctx == NULL) {
                        free(buf);
                        rError = strdup("failed to create bitmap context");
                        dispatch_semaphore_signal(sem);
                        return;
                    }

                    CGContextDrawImage(ctx, CGRectMake(0, 0, w, h), image);
                    CGContextRelease(ctx);

                    rWidth = (int)w;
                    rHeight = (int)h;
                    rBytesPerRow = (int)bpr;
                    resultData = buf;

                    dispatch_semaphore_signal(sem);
                }];
            } else {
                // macOS 12.3 – 13.x: no SCScreenshotManager, use SCStream to grab one frame.
                // Fall back to legacy capture for simplicity.
                rError = strdup("SCScreenshotManager requires macOS 14.0+, falling back to legacy");
                dispatch_semaphore_signal(sem);
            }
        }];

        // Wait up to 5 seconds for the async capture.
        long result = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
        if (result != 0) {
            *outError = strdup("ScreenCaptureKit capture timed out");
            return NULL;
        }

        if (rError != NULL) {
            *outError = rError;
            return NULL;
        }

        *outWidth = rWidth;
        *outHeight = rHeight;
        *outBytesPerRow = rBytesPerRow;
        return resultData;
    }

    *outError = strdup("ScreenCaptureKit requires macOS 12.3 or later");
    return NULL;
#endif // SCK_SDK_AVAILABLE
}

static void sck_free_error(char* err) {
    if (err != NULL) free(err);
}
*/
import "C"

import (
	"fmt"
	"image"
	"unsafe"
)

// IsScreenCaptureKitAvailable returns true if ScreenCaptureKit is available
// on the current system (macOS 12.3+) and was compiled with SDK support.
func IsScreenCaptureKitAvailable() bool {
	return C.sck_is_available() != 0
}

// CaptureWithSCK captures a single frame from the specified display using
// ScreenCaptureKit. displayIndex is 0-based. Returns an RGBA image or an error.
func CaptureWithSCK(displayIndex int) (*image.RGBA, error) {
	var outWidth, outHeight, outBytesPerRow C.int
	var cErr *C.char

	data := C.sck_capture_display(
		C.int(displayIndex),
		&outWidth, &outHeight, &outBytesPerRow,
		&cErr,
	)

	if cErr != nil {
		errMsg := C.GoString(cErr)
		C.sck_free_error(cErr)
		return nil, fmt.Errorf("sck: %s", errMsg)
	}

	if data == nil {
		return nil, fmt.Errorf("sck: capture returned nil without error")
	}
	defer C.free(unsafe.Pointer(data))

	width := int(outWidth)
	height := int(outHeight)

	// Create Go image from the BGRA pixel buffer.
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	srcSlice := unsafe.Slice((*byte)(unsafe.Pointer(data)), width*height*4)
	for i := 0; i < width*height; i++ {
		srcIdx := i * 4
		// BGRA -> RGBA: swap B and R channels
		img.Pix[srcIdx+0] = srcSlice[srcIdx+2] // R <- B
		img.Pix[srcIdx+1] = srcSlice[srcIdx+1] // G <- G
		img.Pix[srcIdx+2] = srcSlice[srcIdx+0] // B <- R
		img.Pix[srcIdx+3] = srcSlice[srcIdx+3] // A <- A
	}

	return img, nil
}
