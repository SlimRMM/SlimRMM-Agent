//go:build windows

package remotedesktop

import (
	"fmt"
	"log/slog"
	"syscall"
	"unsafe"
)

var (
	moduser32        = syscall.NewLazyDLL("user32.dll")
	procOpenDesktop  = moduser32.NewProc("OpenDesktopW")
	procSetThreadDsk = moduser32.NewProc("SetThreadDesktop")
	procCloseDesktop = moduser32.NewProc("CloseDesktop")
)

type DesktopName string

const (
	DesktopDefault     DesktopName = "Default"
	DesktopWinlogon    DesktopName = "Winlogon"
	DesktopScreenSaver DesktopName = "Screen-saver"
)

func SwitchToDesktop(name DesktopName) error {
	namePtr, err := syscall.UTF16PtrFromString(string(name))
	if err != nil {
		return fmt.Errorf("UTF16: %w", err)
	}

	// DESKTOP_SWITCHDESKTOP=0x0100, DESKTOP_READOBJECTS=0x0001, GENERIC_ALL for full access
	const desiredAccess = 0x0100 | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0040 | 0x0080
	hDesktop, _, callErr := procOpenDesktop.Call(
		uintptr(unsafe.Pointer(namePtr)),
		0,
		0,
		desiredAccess,
	)
	if hDesktop == 0 {
		return fmt.Errorf("OpenDesktop(%s): %v", name, callErr)
	}

	ret, _, callErr := procSetThreadDsk.Call(hDesktop)
	if ret == 0 {
		procCloseDesktop.Call(hDesktop)
		return fmt.Errorf("SetThreadDesktop(%s): %v", name, callErr)
	}

	slog.Debug("switched desktop", "desktop", name)
	return nil
}

func DetectActiveDesktop() DesktopName {
	// Try to open Winlogon desktop - if it succeeds, the lock/login screen is active
	namePtr, _ := syscall.UTF16PtrFromString(string(DesktopWinlogon))
	hDesktop, _, _ := procOpenDesktop.Call(
		uintptr(unsafe.Pointer(namePtr)),
		0, 0, 0x0100,
	)
	if hDesktop != 0 {
		procCloseDesktop.Call(hDesktop)
		return DesktopWinlogon
	}
	return DesktopDefault
}
