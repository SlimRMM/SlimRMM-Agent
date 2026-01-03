// Package sandbox provides command whitelisting and dangerous pattern blocking
// for secure command execution. It implements a multi-layer security approach:
// 1. Whitelist: Only explicitly allowed commands can be executed
// 2. Blacklist: Specific dangerous commands are always blocked
// 3. Pattern detection: Dangerous patterns like shell injection are detected
// 4. Sensitive commands: Some commands require explicit server authorization
package sandbox

import (
	"errors"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// ErrCommandNotAllowed is returned when a command is not in the whitelist.
	ErrCommandNotAllowed = errors.New("command not in whitelist")
	// ErrEmptyCommand is returned when the command string is empty.
	ErrEmptyCommand = errors.New("empty command")
	// ErrCommandBlocked is returned when a command matches a blocked pattern.
	ErrCommandBlocked = errors.New("command blocked for security reasons")
	// ErrDangerousPattern is returned when a dangerous pattern is detected.
	ErrDangerousPattern = errors.New("dangerous command pattern detected")
	// ErrSensitiveCommand is returned when a sensitive command requires authorization.
	ErrSensitiveCommand = errors.New("sensitive command requires server authorization")
)

// ValidationResult contains the result of command validation.
type ValidationResult struct {
	IsAllowed         bool
	IsSensitive       bool
	BlockReason       string
	SanitizedCommand  string
	RequiresAuthToken bool
}

// BlockedCommands contains commands that are always blocked regardless of whitelist.
// These are destructive or dangerous commands that should never be executed remotely.
var BlockedCommands = map[string]struct{}{
	"rm -rf /":           {},
	"rm -rf /*":          {},
	"rm -fr /":           {},
	"rm -fr /*":          {},
	"mkfs":               {},
	"mkfs.ext4":          {},
	"mkfs.ext3":          {},
	"mkfs.xfs":           {},
	"mkfs.btrfs":         {},
	"dd if=/dev/zero":    {},
	"dd if=/dev/random":  {},
	"dd if=/dev/urandom": {},
	":(){:|:&};:":        {}, // Fork bomb
	"chmod -R 777 /":     {},
	"chmod 777 /":        {},
	"chown -R":           {},
	"shutdown":           {},
	"reboot":             {},
	"init 0":             {},
	"init 6":             {},
	"halt":               {},
	"poweroff":           {},
	"telinit 0":          {},
	"telinit 6":          {},
	"systemctl halt":     {},
	"systemctl poweroff": {},
	"systemctl reboot":   {},
}

// DangerousPatterns contains regex patterns for dangerous command constructs.
// These patterns detect attempts to execute malicious code through various means.
var DangerousPatterns = []*regexp.Regexp{
	// Disk and device manipulation
	regexp.MustCompile(`>\s*/dev/sd[a-z]`),
	regexp.MustCompile(`dd\s+if=.*of=/dev/`),
	regexp.MustCompile(`dd\s+of=/dev/`),

	// Download and execute patterns (shell injection)
	regexp.MustCompile(`wget\s+.*\|\s*sh`),
	regexp.MustCompile(`wget\s+.*\|\s*bash`),
	regexp.MustCompile(`curl\s+.*\|\s*sh`),
	regexp.MustCompile(`curl\s+.*\|\s*bash`),
	regexp.MustCompile(`curl\s+.*\|\s*sudo`),
	regexp.MustCompile(`wget\s+.*\|\s*sudo`),

	// Command substitution with network tools
	regexp.MustCompile(`\$\(\s*curl`),
	regexp.MustCompile(`\$\(\s*wget`),
	regexp.MustCompile("`\\s*curl"),
	regexp.MustCompile("`\\s*wget"),

	// Eval with variables (potential code injection)
	regexp.MustCompile(`eval\s+\$`),
	regexp.MustCompile(`eval\s+"\$`),
	regexp.MustCompile(`eval\s+'\$`),

	// Base64 decode and execute
	regexp.MustCompile(`base64\s+-d.*\|\s*sh`),
	regexp.MustCompile(`base64\s+-d.*\|\s*bash`),
	regexp.MustCompile(`base64\s+--decode.*\|\s*sh`),
	regexp.MustCompile(`base64\s+--decode.*\|\s*bash`),

	// Reverse shell patterns
	regexp.MustCompile(`nc\s+-e`),
	regexp.MustCompile(`nc\s+.*-e\s+/bin`),
	regexp.MustCompile(`ncat\s+-e`),
	regexp.MustCompile(`netcat\s+-e`),
	regexp.MustCompile(`/dev/tcp/`),
	regexp.MustCompile(`/dev/udp/`),

	// Script interpreter code execution
	regexp.MustCompile(`python\s+.*-c\s+.*exec`),
	regexp.MustCompile(`python3\s+.*-c\s+.*exec`),
	regexp.MustCompile(`perl\s+.*-e`),
	regexp.MustCompile(`ruby\s+.*-e`),
	regexp.MustCompile(`php\s+.*-r`),
	regexp.MustCompile(`node\s+.*-e`),

	// Sensitive file overwrites
	regexp.MustCompile(`>\s*/etc/passwd`),
	regexp.MustCompile(`>\s*/etc/shadow`),
	regexp.MustCompile(`>\s*/etc/sudoers`),
	regexp.MustCompile(`>\s*/etc/hosts`),
	regexp.MustCompile(`>\s*/etc/resolv.conf`),
	regexp.MustCompile(`>\s*/etc/ssh/`),

	// Crontab manipulation
	regexp.MustCompile(`crontab\s+-r`),
	regexp.MustCompile(`rm\s+.*crontab`),

	// SSH key manipulation
	regexp.MustCompile(`>\s*.*\.ssh/authorized_keys`),
	regexp.MustCompile(`>\s*.*\.ssh/id_rsa`),

	// Recursive destructive operations at root
	regexp.MustCompile(`rm\s+-[rf]{2,}\s+/\s*$`),
	regexp.MustCompile(`rm\s+-[rf]{2,}\s+/\*`),
	regexp.MustCompile(`find\s+/\s+-.*-delete`),
	regexp.MustCompile(`find\s+/\s+-.*-exec\s+rm`),

	// Privilege escalation attempts
	regexp.MustCompile(`chmod\s+[0-7]*[4-7][0-7][0-7]\s+/`),
	regexp.MustCompile(`chmod\s+u\+s`),
	regexp.MustCompile(`chmod\s+g\+s`),

	// Environment manipulation
	regexp.MustCompile(`export\s+LD_PRELOAD=`),
	regexp.MustCompile(`export\s+PATH=.*:`),
}

// SensitiveCommands contains commands that require explicit server authorization.
// These commands can modify system state significantly but may be legitimately needed.
var SensitiveCommands = map[string]struct{}{
	// File operations
	"rm":    {},
	"rmdir": {},
	"mv":    {},
	"cp":    {},
	"chmod": {},
	"chown": {},
	"dd":    {},

	// Process control
	"kill":    {},
	"pkill":   {},
	"killall": {},

	// Package management
	"apt":       {},
	"apt-get":   {},
	"dnf":       {},
	"yum":       {},
	"rpm":       {},
	"dpkg":      {},
	"pacman":    {},
	"brew":      {},
	"snap":      {},
	"flatpak":   {},
	"pip":       {},
	"pip3":      {},
	"npm":       {},
	"gem":       {},
	"cargo":     {},
	"go":        {},
	"composer":  {},
	"choco":     {},
	"winget":    {},
	"scoop":     {},

	// Service control
	"systemctl": {},
	"service":   {},
	"launchctl": {},
	"sc":        {},

	// User management
	"useradd":  {},
	"userdel":  {},
	"usermod":  {},
	"groupadd": {},
	"groupdel": {},
	"passwd":   {},

	// Network configuration
	"iptables":  {},
	"ip6tables": {},
	"ufw":       {},
	"firewalld": {},
	"nft":       {},

	// Privilege escalation
	"sudo": {},
	"su":   {},
	"doas": {},

	// Disk operations
	"mount":   {},
	"umount":  {},
	"fdisk":   {},
	"parted":  {},
	"lvm":     {},
	"cryptsetup": {},

	// Docker/Container operations
	"docker":  {},
	"podman":  {},
	"kubectl": {},
}

// Whitelist contains allowed commands organized by category.
var Whitelist = map[string][]string{
	"system_info": {
		"uname", "hostname", "whoami", "id", "uptime", "date", "cal",
		"lsb_release", "cat /etc/os-release", "sw_vers", "ver",
		"hostnamectl", "timedatectl",
	},
	"hardware_info": {
		"lscpu", "lspci", "lsusb", "lsblk", "df", "free", "top", "htop",
		"vmstat", "iostat", "sar", "system_profiler", "lshw", "dmidecode",
		"inxi", "nproc", "lsmem", "numactl",
	},
	"network": {
		"ip", "ifconfig", "netstat", "ss", "ping", "traceroute", "tracepath",
		"dig", "nslookup", "host", "curl", "wget", "arp", "route",
		"networksetup", "iwconfig", "ethtool", "mtr", "whois",
	},
	"process": {
		"ps", "pgrep", "pidof", "kill", "pkill", "nice", "renice",
		"jobs", "bg", "fg", "nohup", "disown",
	},
	"file_read": {
		"ls", "cat", "head", "tail", "less", "more", "file", "stat",
		"find", "locate", "which", "whereis", "wc", "diff", "md5sum",
		"sha256sum", "sha1sum", "readlink", "realpath", "basename",
		"dirname", "tree", "du", "pwd",
	},
	"file_write": {
		"touch", "mkdir", "cp", "mv", "rm", "chmod", "chown",
		"ln", "install", "rsync",
	},
	"archive": {
		"tar", "gzip", "gunzip", "zip", "unzip", "bzip2", "xz",
		"7z", "rar", "unrar", "zcat", "zless",
	},
	"package_debian": {
		"apt", "apt-get", "apt-cache", "dpkg", "dpkg-query",
		"aptitude", "snap",
	},
	"package_rhel": {
		"yum", "dnf", "rpm", "yum-config-manager",
	},
	"package_arch": {
		"pacman", "yay", "paru",
	},
	"package_macos": {
		"brew", "softwareupdate", "mas",
	},
	"package_windows": {
		"choco", "winget", "scoop",
	},
	"service": {
		"systemctl", "service", "launchctl", "sc", "journalctl",
		"chkconfig", "update-rc.d",
	},
	"text_processing": {
		"grep", "awk", "sed", "sort", "uniq", "cut", "tr",
		"tee", "xargs", "column", "fmt", "expand", "unexpand",
		"paste", "join", "comm", "split", "csplit",
	},
	"misc": {
		"echo", "printf", "env", "printenv", "set", "export",
		"source", "test", "expr", "bc", "true", "false",
		"sleep", "timeout", "watch", "yes", "seq",
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

// IsAllowed checks if a command's base executable is in the whitelist.
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

// IsBlocked checks if a command matches any blocked command or pattern.
func IsBlocked(command string) (bool, string) {
	command = strings.TrimSpace(command)
	if command == "" {
		return false, ""
	}

	// Normalize command for comparison
	normalizedCmd := normalizeCommand(command)

	// Check exact blocked commands
	if _, blocked := BlockedCommands[normalizedCmd]; blocked {
		return true, "command is explicitly blocked"
	}

	// Check if command starts with a blocked command
	for blockedCmd := range BlockedCommands {
		if strings.HasPrefix(normalizedCmd, blockedCmd) {
			return true, "command matches blocked prefix: " + blockedCmd
		}
	}

	// Check dangerous patterns
	for _, pattern := range DangerousPatterns {
		if pattern.MatchString(command) {
			return true, "dangerous pattern detected: " + pattern.String()
		}
	}

	return false, ""
}

// IsSensitive checks if a command's base executable is a sensitive command.
func IsSensitive(command string) bool {
	command = strings.TrimSpace(command)
	if command == "" {
		return false
	}

	parts := strings.Fields(command)
	if len(parts) == 0 {
		return false
	}

	baseCmd := filepath.Base(parts[0])
	_, sensitive := SensitiveCommands[baseCmd]
	return sensitive
}

// ValidateCommand performs comprehensive command validation.
// It returns a ValidationResult with detailed information about the command.
func ValidateCommand(command string) (*ValidationResult, error) {
	result := &ValidationResult{
		SanitizedCommand: strings.TrimSpace(command),
	}

	if strings.TrimSpace(command) == "" {
		return result, ErrEmptyCommand
	}

	// Check if blocked first (highest priority)
	if blocked, reason := IsBlocked(command); blocked {
		result.BlockReason = reason
		return result, ErrCommandBlocked
	}

	// Check if in whitelist
	if !IsAllowed(command) {
		return result, ErrCommandNotAllowed
	}

	// Check if sensitive
	if IsSensitive(command) {
		result.IsSensitive = true
		result.RequiresAuthToken = true
	}

	result.IsAllowed = true
	return result, nil
}

// ValidateCommandWithAuth validates a command with optional authorization token.
// If the command is sensitive and no auth token is provided, it returns an error.
func ValidateCommandWithAuth(command string, authToken string) (*ValidationResult, error) {
	result, err := ValidateCommand(command)
	if err != nil {
		return result, err
	}

	// If command is sensitive and requires authorization
	if result.IsSensitive && result.RequiresAuthToken && authToken == "" {
		return result, ErrSensitiveCommand
	}

	return result, nil
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

// GetSensitiveCommands returns a list of all sensitive commands.
func GetSensitiveCommands() []string {
	commands := make([]string, 0, len(SensitiveCommands))
	for cmd := range SensitiveCommands {
		commands = append(commands, cmd)
	}
	return commands
}

// normalizeCommand normalizes a command string for comparison.
func normalizeCommand(cmd string) string {
	// Remove extra whitespace
	parts := strings.Fields(cmd)
	return strings.Join(parts, " ")
}

// SanitizeCommand removes potentially dangerous characters from a command.
// This is a secondary defense and should not be relied upon as the primary security measure.
func SanitizeCommand(command string) string {
	// Remove null bytes
	command = strings.ReplaceAll(command, "\x00", "")

	// Remove ANSI escape sequences
	ansiEscape := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	command = ansiEscape.ReplaceAllString(command, "")

	return strings.TrimSpace(command)
}
