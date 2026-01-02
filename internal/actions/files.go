// Package actions provides file operation handlers.
package actions

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/security/pathval"
)

// FileInfo contains information about a file or directory.
type FileInfo struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	IsDir       bool   `json:"is_dir"`
	Mode        string `json:"mode"`
	ModTime     string `json:"mod_time"`
	Owner       string `json:"owner,omitempty"`
	Group       string `json:"group,omitempty"`
	IsSymlink   bool   `json:"is_symlink"`
	SymlinkTarget string `json:"symlink_target,omitempty"`
}

// ListDirResult contains the result of a directory listing.
type ListDirResult struct {
	Path    string     `json:"path"`
	Files   []FileInfo `json:"files"`
	Count   int        `json:"count"`
}

var pathValidator = pathval.New()

// ListDirectory lists the contents of a directory.
func ListDirectory(path string) (*ListDirResult, error) {
	// Validate path
	if err := pathValidator.Validate(path); err != nil {
		return nil, fmt.Errorf("path validation failed: %w", err)
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("reading directory: %w", err)
	}

	result := &ListDirResult{
		Path:  path,
		Files: make([]FileInfo, 0, len(entries)),
		Count: len(entries),
	}

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		fi := FileInfo{
			Name:    entry.Name(),
			Path:    filepath.Join(path, entry.Name()),
			Size:    info.Size(),
			IsDir:   entry.IsDir(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime().Format(time.RFC3339),
		}

		// Check for symlink
		if info.Mode()&os.ModeSymlink != 0 {
			fi.IsSymlink = true
			if target, err := os.Readlink(fi.Path); err == nil {
				fi.SymlinkTarget = target
			}
		}

		// Get owner/group on Unix
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			if u, err := user.LookupId(strconv.Itoa(int(stat.Uid))); err == nil {
				fi.Owner = u.Username
			}
			if g, err := user.LookupGroupId(strconv.Itoa(int(stat.Gid))); err == nil {
				fi.Group = g.Name
			}
		}

		result.Files = append(result.Files, fi)
	}

	return result, nil
}

// CreateFolder creates a new directory.
func CreateFolder(path string, mode os.FileMode) error {
	if err := pathValidator.Validate(filepath.Dir(path)); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}

	if mode == 0 {
		mode = 0755
	}

	return os.MkdirAll(path, mode)
}

// DeleteEntry deletes a file or directory.
func DeleteEntry(path string, recursive bool) error {
	if err := pathValidator.ValidateWithSymlinkResolution(path); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if info.IsDir() {
		if recursive {
			return os.RemoveAll(path)
		}
		return os.Remove(path)
	}

	return os.Remove(path)
}

// RenameEntry renames a file or directory.
func RenameEntry(oldPath, newPath string) error {
	if err := pathValidator.ValidateWithSymlinkResolution(oldPath); err != nil {
		return fmt.Errorf("source path validation failed: %w", err)
	}
	if err := pathValidator.Validate(filepath.Dir(newPath)); err != nil {
		return fmt.Errorf("destination path validation failed: %w", err)
	}

	return os.Rename(oldPath, newPath)
}

// Chmod changes file permissions.
func Chmod(path string, mode string) error {
	if err := pathValidator.ValidateWithSymlinkResolution(path); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}

	// Parse octal mode string
	modeInt, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		return fmt.Errorf("invalid mode: %w", err)
	}

	return os.Chmod(path, os.FileMode(modeInt))
}

// Chown changes file ownership.
func Chown(path string, owner, group string) error {
	if err := pathValidator.ValidateWithSymlinkResolution(path); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}

	uid := -1
	gid := -1

	if owner != "" {
		u, err := user.Lookup(owner)
		if err != nil {
			// Try as numeric UID
			if uidInt, err := strconv.Atoi(owner); err == nil {
				uid = uidInt
			} else {
				return fmt.Errorf("unknown user: %s", owner)
			}
		} else {
			uid, _ = strconv.Atoi(u.Uid)
		}
	}

	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			// Try as numeric GID
			if gidInt, err := strconv.Atoi(group); err == nil {
				gid = gidInt
			} else {
				return fmt.Errorf("unknown group: %s", group)
			}
		} else {
			gid, _ = strconv.Atoi(g.Gid)
		}
	}

	return os.Chown(path, uid, gid)
}

// ReadFile reads file contents.
func ReadFile(path string, offset, limit int64) ([]byte, error) {
	if err := pathValidator.ValidateWithSymlinkResolution(path); err != nil {
		return nil, fmt.Errorf("path validation failed: %w", err)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil, err
		}
	}

	if limit <= 0 {
		limit = 1024 * 1024 // Default 1 MB
	}

	data := make([]byte, limit)
	n, err := f.Read(data)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return data[:n], nil
}

// WriteFile writes data to a file.
func WriteFile(path string, data []byte, mode os.FileMode) error {
	if err := pathValidator.Validate(filepath.Dir(path)); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}

	if mode == 0 {
		mode = 0644
	}

	return os.WriteFile(path, data, mode)
}

// CopyFile copies a file from src to dst.
func CopyFile(src, dst string) error {
	if err := pathValidator.ValidateWithSymlinkResolution(src); err != nil {
		return fmt.Errorf("source path validation failed: %w", err)
	}
	if err := pathValidator.Validate(filepath.Dir(dst)); err != nil {
		return fmt.Errorf("destination path validation failed: %w", err)
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// GetFileInfo returns information about a file.
func GetFileInfo(path string) (*FileInfo, error) {
	if err := pathValidator.Validate(path); err != nil {
		return nil, fmt.Errorf("path validation failed: %w", err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}

	fi := &FileInfo{
		Name:    info.Name(),
		Path:    path,
		Size:    info.Size(),
		IsDir:   info.IsDir(),
		Mode:    info.Mode().String(),
		ModTime: info.ModTime().Format(time.RFC3339),
	}

	if info.Mode()&os.ModeSymlink != 0 {
		fi.IsSymlink = true
		if target, err := os.Readlink(path); err == nil {
			fi.SymlinkTarget = target
		}
	}

	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if u, err := user.LookupId(strconv.Itoa(int(stat.Uid))); err == nil {
			fi.Owner = u.Username
		}
		if g, err := user.LookupGroupId(strconv.Itoa(int(stat.Gid))); err == nil {
			fi.Group = g.Name
		}
	}

	return fi, nil
}
