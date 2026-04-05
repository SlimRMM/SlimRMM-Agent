package handler

import (
	"strings"
	"testing"
)

func TestValidateJSONDepth(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxDepth int
		wantErr  bool
	}{
		{"empty object", "{}", 32, false},
		{"empty array", "[]", 32, false},
		{"shallow object", `{"a":1}`, 32, false},
		{"shallow array", `[1,2,3]`, 32, false},
		{"nested object ok", `{"a":{"b":{"c":1}}}`, 32, false},
		{"deep at limit", strings.Repeat(`{"a":`, 32) + `1` + strings.Repeat(`}`, 32), 32, false},
		{"too deep rejects", strings.Repeat(`{"a":`, 33) + `1` + strings.Repeat(`}`, 33), 32, true},
		{"array bomb rejects", strings.Repeat(`[`, 100) + strings.Repeat(`]`, 100), 32, true},
		{"mixed nesting", `{"a":[{"b":[1,2]}]}`, 32, false},
		{"brackets in string ignored", `{"a":"[[[[[[["}`, 5, false},
		{"escaped quote in string", `{"a":"foo\"[[[[["}`, 5, false},
		{"escaped backslash before quote", `{"a":"x\\","b":1}`, 5, false},
		{"strict limit 1 flat", `{"a":1}`, 1, false},
		{"strict limit 1 too deep", `{"a":{"b":1}}`, 1, true},
		{"zero maxDepth uses default", `{"a":1}`, 0, false},
		{"negative maxDepth uses default", `{"a":1}`, -1, false},
		{"exact MaxJSONDepth limit", strings.Repeat(`[`, MaxJSONDepth) + strings.Repeat(`]`, MaxJSONDepth), MaxJSONDepth, false},
		{"one over MaxJSONDepth", strings.Repeat(`[`, MaxJSONDepth+1) + strings.Repeat(`]`, MaxJSONDepth+1), MaxJSONDepth, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateJSONDepth([]byte(tt.input), tt.maxDepth)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateJSONDepth(%q, %d) err=%v, wantErr=%v", tt.input, tt.maxDepth, err, tt.wantErr)
			}
		})
	}
}
