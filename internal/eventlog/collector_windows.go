//go:build windows

package eventlog

import (
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"
)

// wevtEvent represents a single Event element from wevtutil RenderedXml output.
type wevtEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     int `xml:"EventID"`
		Level       int `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Channel string `xml:"Channel"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
	RenderingInfo struct {
		Message  string `xml:"Message"`
		Level    string `xml:"Level"`
		Task     string `xml:"Task"`
		Opcode   string `xml:"Opcode"`
		Channel  string `xml:"Channel"`
		Provider string `xml:"Provider"`
	} `xml:"RenderingInfo"`
}

// wevtEvents is a wrapper for parsing multiple Event elements.
type wevtEvents struct {
	Events []wevtEvent `xml:"Event"`
}

// WindowsCollector collects events from Windows Event Log using wevtutil.
type WindowsCollector struct{}

// NewPlatformCollector returns a new WindowsCollector.
func NewPlatformCollector() Collector {
	return &WindowsCollector{}
}

// Collect queries the specified Windows Event Log channel for events since the
// given time. It returns the matching entries and the timestamp of the latest
// event (for bookmark tracking).
func (c *WindowsCollector) Collect(channel string, since time.Time) ([]EventEntry, time.Time, error) {
	sinceUTC := since.UTC().Format("2006-01-02T15:04:05.000Z")

	xpath := fmt.Sprintf("*[System[TimeCreated[@SystemTime>='%s']]]", sinceUTC)

	cmd := exec.Command("wevtutil", "qe", channel,
		"/q:"+xpath,
		"/f:RenderedXml",
		"/rd:true",
		"/c:500",
	)

	output, err := cmd.Output()
	if err != nil {
		// wevtutil may return exit code 1 when no events match; treat empty
		// stderr / empty output as "no events" rather than a hard error.
		if len(output) == 0 {
			return nil, since, nil
		}
		return nil, since, fmt.Errorf("wevtutil failed for channel %s: %w", channel, err)
	}

	raw := strings.TrimSpace(string(output))
	if raw == "" {
		return nil, since, nil
	}

	// RenderedXml wraps events with an xmlns attribute that can confuse Go's
	// XML decoder. Strip it before parsing.
	raw = strings.ReplaceAll(raw, ` xmlns='http://schemas.microsoft.com/win/2004/08/events/event'`, "")
	raw = strings.ReplaceAll(raw, ` xmlns="http://schemas.microsoft.com/win/2004/08/events/event"`, "")

	// Sanitize invalid UTF-8 bytes that wevtutil may produce on non-English
	// Windows installations (e.g. German Umlaute in CP1252 encoding).
	raw = sanitizeUTF8(raw)

	// wevtutil outputs individual <Event> elements without a root wrapper.
	// Wrap them so the XML decoder can parse them in one pass.
	wrapped := "<Events>" + raw + "</Events>"

	var parsed wevtEvents
	if err := xml.Unmarshal([]byte(wrapped), &parsed); err != nil {
		return nil, since, fmt.Errorf("failed to parse wevtutil XML for channel %s: %w", channel, err)
	}

	if len(parsed.Events) == 0 {
		return nil, since, nil
	}

	latestTime := since
	entries := make([]EventEntry, 0, len(parsed.Events))

	for _, evt := range parsed.Events {
		ts, err := time.Parse(time.RFC3339Nano, evt.System.TimeCreated.SystemTime)
		if err != nil {
			// Some timestamps may use a slightly different format; try
			// the common Windows variant with 7 fractional digits.
			ts, err = time.Parse("2006-01-02T15:04:05.0000000Z", evt.System.TimeCreated.SystemTime)
			if err != nil {
				continue // skip unparseable entries
			}
		}

		if ts.After(latestTime) {
			latestTime = ts
		}

		// Build a human-readable message from EventData fields.
		rawData := make(map[string]string, len(evt.EventData.Data))
		var messageParts []string
		for _, d := range evt.EventData.Data {
			val := strings.TrimSpace(d.Value)
			if val == "" {
				continue
			}
			key := d.Name
			if key == "" {
				key = "Data"
			}
			rawData[key] = val
			messageParts = append(messageParts, val)
		}

		// Prefer the rendered message from RenderingInfo (human-readable)
		message := strings.TrimSpace(evt.RenderingInfo.Message)
		if message == "" {
			// Fallback: build message from EventData fields
			message = strings.Join(messageParts, " | ")
		}

		if evt.RenderingInfo.Task != "" {
			rawData["_task"] = evt.RenderingInfo.Task
		}
		if evt.RenderingInfo.Opcode != "" {
			rawData["_opcode"] = evt.RenderingInfo.Opcode
		}

		// Use RenderingInfo.Provider as fallback if System.Provider.Name is empty.
		provider := evt.System.Provider.Name
		if provider == "" {
			provider = evt.RenderingInfo.Provider
		}

		entries = append(entries, EventEntry{
			EventID:   evt.System.EventID,
			Channel:   evt.System.Channel,
			Provider:  provider,
			Level:     windowsLevelToString(evt.System.Level),
			Message:   message,
			Timestamp: ts.UTC().Format(time.RFC3339),
			RawData:   rawData,
		})
	}

	return entries, latestTime, nil
}

// sanitizeUTF8 replaces invalid UTF-8 sequences with the Unicode replacement
// character (U+FFFD). wevtutil on non-English Windows may emit event messages
// encoded in the system's ANSI codepage (e.g. CP1252) instead of UTF-8.
func sanitizeUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteRune('\uFFFD')
		} else {
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// windowsLevelToString converts a Windows event level integer to a string.
func windowsLevelToString(level int) string {
	switch level {
	case 1:
		return "critical"
	case 2:
		return "error"
	case 3:
		return "warning"
	case 4:
		return "info"
	case 5:
		return "verbose"
	default:
		return "info"
	}
}
