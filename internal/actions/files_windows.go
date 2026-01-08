//go:build windows
// +build windows

package actions

import (
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// getFileOwnership returns owner and group for a file on Windows.
// Windows doesn't use Unix-style uid/gid, so we return empty strings.
func getFileOwnership(info os.FileInfo) (owner, group string) {
	// Windows uses ACLs instead of Unix permissions
	// Could be extended with Windows-specific code if needed
	return "", ""
}

// listWindowsDrives returns a list of available drive letters on Windows.
func listWindowsDrives() (*ListDirResult, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getLogicalDrives := kernel32.NewProc("GetLogicalDrives")

	ret, _, _ := getLogicalDrives.Call()
	bitmask := uint32(ret)

	result := &ListDirResult{
		CurrentPath: "/",
		Entries:     make([]FileInfo, 0),
	}

	for i := 0; i < 26; i++ {
		if bitmask&(1<<uint(i)) != 0 {
			driveLetter := string(rune('A'+i)) + ":"
			drivePath := driveLetter + "\\"

			// Check if drive is accessible
			_, err := os.Stat(drivePath)
			if err != nil {
				continue
			}

			// Get drive type for name
			driveType := getDriveType(drivePath)

			fi := FileInfo{
				Name: driveLetter,
				Path: drivePath,
				Type: "directory",
			}

			// Add drive type as part of name for display
			switch driveType {
			case 2:
				fi.Name = driveLetter + " (Removable)"
			case 3:
				fi.Name = driveLetter + " (Local Disk)"
			case 4:
				fi.Name = driveLetter + " (Network)"
			case 5:
				fi.Name = driveLetter + " (CD-ROM)"
			case 6:
				fi.Name = driveLetter + " (RAM Disk)"
			}

			result.Entries = append(result.Entries, fi)
		}
	}

	result.Count = len(result.Entries)
	return result, nil
}

// getDriveType returns the type of drive.
func getDriveType(path string) uint32 {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getDriveTypeW := kernel32.NewProc("GetDriveTypeW")

	pathPtr, _ := syscall.UTF16PtrFromString(path)
	ret, _, _ := getDriveTypeW.Call(uintptr(unsafe.Pointer(pathPtr)))
	return uint32(ret)
}

// isRootPath checks if the path is a root path request (/ or empty).
func isRootPath(path string) bool {
	return path == "/" || path == "\\" || path == ""
}

// listDirectoryWindows handles directory listing on Windows, including root path.
func listDirectoryWindows(path string) (*ListDirResult, error) {
	// Handle root path - list drives
	if isRootPath(path) {
		return listWindowsDrives()
	}

	// Clean and normalize path
	path = filepath.Clean(path)

	// Validate path
	if err := pathValidator.Validate(path); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	result := &ListDirResult{
		CurrentPath: path,
		Entries:     make([]FileInfo, 0, len(entries)),
		Count:       len(entries),
	}

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		fileType := "file"
		if entry.IsDir() {
			fileType = "directory"
		}

		fi := FileInfo{
			Name:        entry.Name(),
			Path:        filepath.Join(path, entry.Name()),
			Type:        fileType,
			Size:        info.Size(),
			Modified:    info.ModTime().Format("2006-01-02T15:04:05Z07:00"),
			Permissions: info.Mode().String(),
		}

		if info.Mode()&os.ModeSymlink != 0 {
			fi.IsSymlink = true
			if target, err := os.Readlink(fi.Path); err == nil {
				fi.SymlinkTarget = target
			}
		}

		fi.Owner, fi.Group = getFileOwnership(info)
		result.Entries = append(result.Entries, fi)
	}

	return result, nil
}
