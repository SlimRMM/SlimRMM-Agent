// Package compliance provides compliance check services.
package compliance

import "testing"

func TestComparator_CompareQueryResult(t *testing.T) {
	c := NewComparator()

	tests := []struct {
		name       string
		actualRows []map[string]interface{}
		expected   interface{}
		operator   string
		wantPassed bool
	}{
		{
			name:       "exists with results",
			actualRows: []map[string]interface{}{{"key": "value"}},
			expected:   nil,
			operator:   "exists",
			wantPassed: true,
		},
		{
			name:       "exists without results",
			actualRows: []map[string]interface{}{},
			expected:   nil,
			operator:   "exists",
			wantPassed: false,
		},
		{
			name:       "not_exists without results",
			actualRows: []map[string]interface{}{},
			expected:   nil,
			operator:   "not_exists",
			wantPassed: true,
		},
		{
			name:       "not_exists with results",
			actualRows: []map[string]interface{}{{"key": "value"}},
			expected:   nil,
			operator:   "not_exists",
			wantPassed: false,
		},
		{
			name:       "equals match",
			actualRows: []map[string]interface{}{{"name": "test", "value": "1"}},
			expected:   map[string]interface{}{"name": "test"},
			operator:   "equals",
			wantPassed: true,
		},
		{
			name:       "equals no match",
			actualRows: []map[string]interface{}{{"name": "other", "value": "1"}},
			expected:   map[string]interface{}{"name": "test"},
			operator:   "equals",
			wantPassed: false,
		},
		{
			name:       "not_equals different value",
			actualRows: []map[string]interface{}{{"name": "other"}},
			expected:   map[string]interface{}{"name": "test"},
			operator:   "not_equals",
			wantPassed: true,
		},
		{
			name:       "not_equals same value",
			actualRows: []map[string]interface{}{{"name": "test"}},
			expected:   map[string]interface{}{"name": "test"},
			operator:   "not_equals",
			wantPassed: false,
		},
		{
			name:       "contains subset",
			actualRows: []map[string]interface{}{{"name": "test", "value": "1", "extra": "data"}},
			expected:   map[string]interface{}{"name": "test"},
			operator:   "contains",
			wantPassed: true,
		},
		{
			name:       "gte numeric pass",
			actualRows: []map[string]interface{}{{"count": "10"}},
			expected:   map[string]interface{}{"count": 5},
			operator:   "gte",
			wantPassed: true,
		},
		{
			name:       "gte numeric fail",
			actualRows: []map[string]interface{}{{"count": "3"}},
			expected:   map[string]interface{}{"count": 5},
			operator:   "gte",
			wantPassed: false,
		},
		{
			name:       "lt numeric pass",
			actualRows: []map[string]interface{}{{"count": "3"}},
			expected:   map[string]interface{}{"count": 5},
			operator:   "lt",
			wantPassed: true,
		},
		{
			name:       "nil expected always passes",
			actualRows: []map[string]interface{}{{"key": "value"}},
			expected:   nil,
			operator:   "equals",
			wantPassed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.CompareQueryResult(tt.actualRows, tt.expected, tt.operator)
			if result.Passed != tt.wantPassed {
				t.Errorf("CompareQueryResult() passed = %v, want %v, message = %s",
					result.Passed, tt.wantPassed, result.Message)
			}
		})
	}
}

func TestComparator_CompareRegistryResult(t *testing.T) {
	c := NewComparator()

	tests := []struct {
		name       string
		actual     interface{}
		expected   interface{}
		operator   string
		wantPassed bool
	}{
		{
			name:       "equals match string",
			actual:     "enabled",
			expected:   "enabled",
			operator:   "equals",
			wantPassed: true,
		},
		{
			name:       "equals no match",
			actual:     "disabled",
			expected:   "enabled",
			operator:   "equals",
			wantPassed: false,
		},
		{
			name:       "contains substring",
			actual:     "Windows 10 Pro",
			expected:   "Windows",
			operator:   "contains",
			wantPassed: true,
		},
		{
			name:       "contains no substring",
			actual:     "macOS",
			expected:   "Windows",
			operator:   "contains",
			wantPassed: false,
		},
		{
			name:       "exists with value",
			actual:     "some value",
			expected:   nil,
			operator:   "exists",
			wantPassed: true,
		},
		{
			name:       "exists empty string",
			actual:     "",
			expected:   nil,
			operator:   "exists",
			wantPassed: false,
		},
		{
			name:       "not_exists nil",
			actual:     nil,
			expected:   nil,
			operator:   "not_exists",
			wantPassed: true,
		},
		{
			name:       "gte numeric integers",
			actual:     10,
			expected:   5,
			operator:   "gte",
			wantPassed: true,
		},
		{
			name:       "gte numeric strings",
			actual:     "10",
			expected:   "5",
			operator:   "gte",
			wantPassed: true,
		},
		{
			name:       "lt numeric",
			actual:     3,
			expected:   5,
			operator:   "lt",
			wantPassed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := c.CompareRegistryResult(tt.actual, tt.expected, tt.operator)
			if result.Passed != tt.wantPassed {
				t.Errorf("CompareRegistryResult() passed = %v, want %v, message = %s",
					result.Passed, tt.wantPassed, result.Message)
			}
		})
	}
}

func TestToFloat64(t *testing.T) {
	tests := []struct {
		name    string
		value   interface{}
		want    float64
		wantErr bool
	}{
		{"float64", float64(3.14), 3.14, false},
		{"float32", float32(3.14), float64(float32(3.14)), false},
		{"int", 42, 42.0, false},
		{"int64", int64(42), 42.0, false},
		{"int32", int32(42), 42.0, false},
		{"string number", "42.5", 42.5, false},
		{"invalid string", "not a number", 0, true},
		{"unsupported type", []int{1, 2, 3}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toFloat64(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("toFloat64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("toFloat64() = %v, want %v", got, tt.want)
			}
		})
	}
}
