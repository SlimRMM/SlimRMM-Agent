// Package handler — JSON safety helpers.
//
// validateJSONDepth is a cheap, single-pass byte-level guard that rejects
// WebSocket payloads whose structural nesting exceeds MaxJSONDepth. It runs
// *before* json.Unmarshal so a compromised/malicious server cannot trigger
// pathological recursion, O(n^2) parser behaviour, or stack exhaustion by
// sending deeply nested "JSON bomb" payloads such as `[[[[[[[[[[...]]]]]]]]]`.
package handler

import "fmt"

// MaxJSONDepth is the maximum allowed structural depth of an incoming JSON
// message. Real RMM control messages rarely exceed 6–8 levels of nesting;
// 32 leaves headroom for legitimate payloads while cutting off abusive ones.
const MaxJSONDepth = 32

// validateJSONDepth scans data for the maximum nesting depth of JSON objects
// and arrays and returns an error if it exceeds maxDepth. The scanner is
// intentionally simple and does not fully validate JSON — that is delegated
// to encoding/json — but it correctly honours string escaping so brackets
// inside string literals do not inflate the depth.
//
// Complexity: O(n) time, O(1) memory. Safe to call on untrusted input.
func validateJSONDepth(data []byte, maxDepth int) error {
	if maxDepth <= 0 {
		maxDepth = MaxJSONDepth
	}
	depth := 0
	inString := false
	escaped := false
	for _, b := range data {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			switch b {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > maxDepth {
				return fmt.Errorf("JSON nesting depth %d exceeds maximum %d", depth, maxDepth)
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return nil
}
