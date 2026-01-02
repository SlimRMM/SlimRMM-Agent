//go:build !windows
// +build !windows

package actions

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// getFileOwnership returns owner and group for a file on Unix systems.
func getFileOwnership(info os.FileInfo) (owner, group string) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if u, err := user.LookupId(strconv.Itoa(int(stat.Uid))); err == nil {
			owner = u.Username
		}
		if g, err := user.LookupGroupId(strconv.Itoa(int(stat.Gid))); err == nil {
			group = g.Name
		}
	}
	return
}
