//go:build !windows

package remotedesktop

type DesktopName string

const (
	DesktopDefault     DesktopName = "Default"
	DesktopWinlogon    DesktopName = "Winlogon"
	DesktopScreenSaver DesktopName = "Screen-saver"
)

func SwitchToDesktop(name DesktopName) error { return nil }
func DetectActiveDesktop() DesktopName       { return DesktopDefault }
