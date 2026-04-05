// Package actions - process listing.
//
// This file exposes ListProcesses which enumerates running processes using
// gopsutil. It is intentionally lightweight: the result is marshalled directly
// to JSON and sent over the WebSocket in response to the "list_processes"
// action. The Python backend consumes a compatible shape at
// GET /agents/{id}/processes.
package actions

import (
	"context"
	"regexp"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

// javaDPropRedactRegex matches Java-style -D system properties that carry
// secrets (e.g. -Dpassword=secret, -Dapi.key=abc). The dot is allowed so that
// property names like "spring.datasource.password" are covered.
var javaDPropRedactRegex = regexp.MustCompile(`(?i)(-D[\w.]*(password|passwd|secret|token|api[_-]?key|bearer)[\w.]*)=\S+`)

// redactCmdLine applies secret-redaction to a process command line before it
// is sent to the backend. It layers the shared sanitizeOutput() redactions
// (key=value / key: value style) on top of a Java-style -Dprop=secret pass,
// so that command lines such as
//
//	java -Dpassword=hunter2 -jar app.jar
//	docker run -e DB_PASSWORD=xxx image
//	myapp --api-key=abc123
//
// never leak plaintext credentials. Empty input is returned as-is.
func redactCmdLine(s string) string {
	if s == "" {
		return s
	}
	s = javaDPropRedactRegex.ReplaceAllString(s, "$1=***REDACTED***")
	return sanitizeOutput(s)
}

// ProcessInfo is a JSON-friendly snapshot of a single running process. All
// numeric fields use signed types (int64) to avoid Python-side parsing issues
// with very large uint64 values.
type ProcessInfo struct {
	PID         int32   `json:"pid"`
	PPID        int32   `json:"ppid,omitempty"`
	Name        string  `json:"name"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemoryBytes int64   `json:"memory_bytes"`
	Status      string  `json:"status,omitempty"`
	Username    string  `json:"username,omitempty"`
	CreateTime  int64   `json:"create_time,omitempty"` // unix millis
	CmdLine     string  `json:"cmdline,omitempty"`
}

// maxCmdLineLen caps the stored command line to avoid huge payloads when a
// process has a pathologically long argv (e.g. Java apps, browser renderers).
const maxCmdLineLen = 512

// ListProcesses enumerates currently-running processes and returns a slice of
// ProcessInfo snapshots. Best-effort: per-process field collection errors are
// swallowed so one broken process doesn't kill the whole listing.
func ListProcesses(ctx context.Context) ([]ProcessInfo, error) {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]ProcessInfo, 0, len(procs))
	for _, p := range procs {
		// Honour context cancellation between iterations.
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		info := ProcessInfo{PID: p.Pid}
		if name, err := p.NameWithContext(ctx); err == nil {
			info.Name = name
		}
		if ppid, err := p.PpidWithContext(ctx); err == nil {
			info.PPID = ppid
		}
		if cpu, err := p.CPUPercentWithContext(ctx); err == nil {
			info.CPUPercent = cpu
		}
		if mem, err := p.MemoryInfoWithContext(ctx); err == nil && mem != nil {
			info.MemoryBytes = int64(mem.RSS)
		}
		if statuses, err := p.StatusWithContext(ctx); err == nil && len(statuses) > 0 {
			info.Status = statuses[0]
		}
		if user, err := p.UsernameWithContext(ctx); err == nil {
			info.Username = user
		}
		if ct, err := p.CreateTimeWithContext(ctx); err == nil {
			info.CreateTime = ct
		}
		if cmd, err := p.CmdlineWithContext(ctx); err == nil {
			if len(cmd) > maxCmdLineLen {
				cmd = cmd[:maxCmdLineLen] + "..."
			}
			// Redact secrets (passwords, tokens, API keys, bearer tokens,
			// Java -Dpassword=... style flags) BEFORE storing the cmdline,
			// so plaintext credentials never reach the backend.
			info.CmdLine = redactCmdLine(strings.TrimSpace(cmd))
		}

		result = append(result, info)
	}

	return result, nil
}
