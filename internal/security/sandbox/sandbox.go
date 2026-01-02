// Package sandbox provides command whitelisting for secure command execution.
// Only explicitly allowed commands can be executed to prevent arbitrary code execution.
package sandbox

import (
	"errors"
	"path/filepath"
	"strings"
)

var (
	ErrCommandNotAllowed = errors.New("command not in whitelist")
	ErrEmptyCommand      = errors.New("empty command")
)

// Whitelist contains allowed commands organized by category.
var Whitelist = map[string][]string{
	"system_info": {
		"uname", "hostname", "whoami", "id", "uptime", "date", "cal",
		"lsb_release", "cat /etc/os-release", "sw_vers",
	},
	"hardware_info": {
		"lscpu", "lspci", "lsusb", "lsblk", "df", "free", "top", "htop",
		"vmstat", "iostat", "sar", "system_profiler",
	},
	"network": {
		"ip", "ifconfig", "netstat", "ss", "ping", "traceroute", "tracepath",
		"dig", "nslookup", "host", "curl", "wget", "arp", "route",
		"networksetup",
	},
	"process": {
		"ps", "pgrep", "pidof", "kill", "pkill", "nice", "renice",
	},
	"file_read": {
		"ls", "cat", "head", "tail", "less", "more", "file", "stat",
		"find", "locate", "which", "whereis", "wc", "diff", "md5sum",
		"sha256sum", "sha1sum",
	},
	"file_write": {
		"touch", "mkdir", "cp", "mv", "rm", "chmod", "chown",
	},
	"archive": {
		"tar", "gzip", "gunzip", "zip", "unzip", "bzip2", "xz",
	},
	"package_debian": {
		"apt", "apt-get", "apt-cache", "dpkg", "dpkg-query",
	},
	"package_rhel": {
		"yum", "dnf", "rpm",
	},
	"package_arch": {
		"pacman",
	},
	"package_macos": {
		"brew", "softwareupdate",
	},
	"package_windows": {
		"choco", "winget",
	},
	"service": {
		"systemctl", "service", "launchctl", "sc",
	},
	"misc": {
		"echo", "printf", "env", "printenv", "set", "export",
		"grep", "awk", "sed", "sort", "uniq", "cut", "tr",
	},
}

// flatWhitelist is a pre-computed flat list of all allowed commands.
var flatWhitelist map[string]bool

func init() {
	flatWhitelist = make(map[string]bool)
	for _, commands := range Whitelist {
		for _, cmd := range commands {
			// Extract the base command (first word)
			parts := strings.Fields(cmd)
			if len(parts) > 0 {
				flatWhitelist[parts[0]] = true
			}
		}
	}
}

// IsAllowed checks if a command is in the whitelist.
func IsAllowed(command string) bool {
	command = strings.TrimSpace(command)
	if command == "" {
		return false
	}

	// Extract the base command
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return false
	}

	baseCmd := filepath.Base(parts[0])
	return flatWhitelist[baseCmd]
}

// ValidateCommand validates a command and returns an error if not allowed.
func ValidateCommand(command string) error {
	if strings.TrimSpace(command) == "" {
		return ErrEmptyCommand
	}

	if !IsAllowed(command) {
		return ErrCommandNotAllowed
	}

	return nil
}

// GetAllowedCommands returns a list of all allowed commands.
func GetAllowedCommands() []string {
	commands := make([]string, 0, len(flatWhitelist))
	for cmd := range flatWhitelist {
		commands = append(commands, cmd)
	}
	return commands
}

// GetCommandsByCategory returns commands for a specific category.
func GetCommandsByCategory(category string) []string {
	if commands, ok := Whitelist[category]; ok {
		return commands
	}
	return nil
}
