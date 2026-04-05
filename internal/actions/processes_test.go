package actions

import (
	"context"
	"strings"
	"testing"
)

func TestRedactCmdLine(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		mustNotHave []string
		mustHave    []string
	}{
		{
			name:        "java -Dpassword flag is redacted",
			input:       "java -Dpassword=secret -jar Foo.jar",
			mustNotHave: []string{"secret"},
			mustHave:    []string{"-Dpassword=***REDACTED***"},
		},
		{
			name:        "java -Dspring.datasource.password is redacted",
			input:       "java -Dspring.datasource.password=hunter2 -jar app.jar",
			mustNotHave: []string{"hunter2"},
			mustHave:    []string{"***REDACTED***"},
		},
		{
			name:        "docker env var with password is redacted",
			input:       "docker run -e DB_PASSWORD=xxx image:latest",
			mustNotHave: []string{"xxx"},
			mustHave:    []string{"***REDACTED***"},
		},
		{
			name:        "api-key long flag is redacted",
			input:       "myapp --api-key=abc123DEF",
			mustNotHave: []string{"abc123DEF"},
			mustHave:    []string{"***REDACTED***"},
		},
		{
			name:        "api_key underscore variant is redacted",
			input:       "svc --api_key=ZZZ987",
			mustNotHave: []string{"ZZZ987"},
			mustHave:    []string{"***REDACTED***"},
		},
		{
			name:        "token kv pair is redacted",
			input:       "agent --token=tok_abc_def_ghi start",
			mustNotHave: []string{"tok_abc_def_ghi"},
			mustHave:    []string{"***REDACTED***"},
		},
		{
			name:        "secret kv with colon is redacted",
			input:       "worker secret: s3cr3tPAYLOAD run",
			mustNotHave: []string{"s3cr3tPAYLOAD"},
			mustHave:    []string{"***REDACTED***"},
		},
		{
			name:        "bearer token is redacted",
			input:       "client --bearer=eyJhbGciOiJIUzI1NiJ9.payload.sig go",
			mustNotHave: []string{"eyJhbGciOiJIUzI1NiJ9.payload.sig"},
			mustHave:    []string{"***REDACTED***"},
		},
		{
			name:        "benign cmdline is unchanged",
			input:       "node app.js",
			mustNotHave: []string{"REDACTED"},
			mustHave:    []string{"node app.js"},
		},
		{
			name:        "benign cmdline with flags is unchanged",
			input:       "nginx -g daemon off;",
			mustNotHave: []string{"REDACTED"},
			mustHave:    []string{"nginx", "daemon"},
		},
		{
			name:        "empty stays empty",
			input:       "",
			mustNotHave: []string{"REDACTED"},
			mustHave:    nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := redactCmdLine(tt.input)
			for _, forbidden := range tt.mustNotHave {
				if forbidden == "" {
					continue
				}
				if strings.Contains(got, forbidden) {
					t.Errorf("redactCmdLine(%q) = %q; must NOT contain %q",
						tt.input, got, forbidden)
				}
			}
			for _, needed := range tt.mustHave {
				if !strings.Contains(got, needed) {
					t.Errorf("redactCmdLine(%q) = %q; expected substring %q",
						tt.input, got, needed)
				}
			}
		})
	}
}

// TestListProcessesRedactsOwnCmdLine is a light smoke test: it verifies that
// ListProcesses actually routes CmdLine values through the redactor. We look
// at our own process (the test binary) — its cmdline will not contain any
// of the secret markers, but we can still assert the invariant that no entry
// contains a bare "password=<value>" pattern with a non-redacted tail.
func TestListProcessesRedactsOwnCmdLine(t *testing.T) {
	procs, err := ListProcesses(context.Background())
	if err != nil {
		t.Skipf("ListProcesses failed on this host: %v", err)
	}
	for _, p := range procs {
		if p.CmdLine == "" {
			continue
		}
		// If a cmdline mentions "password=" etc., the tail MUST be redacted.
		lower := strings.ToLower(p.CmdLine)
		for _, marker := range []string{"password=", "passwd=", "secret=", "token=", "api-key=", "api_key=", "bearer="} {
			idx := strings.Index(lower, marker)
			if idx < 0 {
				continue
			}
			tail := p.CmdLine[idx+len(marker):]
			if !strings.HasPrefix(tail, "***REDACTED***") {
				t.Errorf("pid=%d cmdline contains unredacted %q: %q",
					p.PID, marker, p.CmdLine)
			}
		}
	}
}
