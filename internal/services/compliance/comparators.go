// Package compliance provides compliance check services.
package compliance

import (
	"fmt"
	"strings"
)

// Comparator provides comparison operations for compliance checks.
type Comparator struct{}

// NewComparator creates a new Comparator instance.
func NewComparator() *Comparator {
	return &Comparator{}
}

// CompareQueryResult compares actual osquery results against expected values.
func (c *Comparator) CompareQueryResult(actualRows []map[string]interface{}, expected interface{}, operator string) ComparisonResult {
	// Handle existence operators first - they don't need an expected value
	switch operator {
	case "exists", "not_empty":
		if len(actualRows) > 0 {
			return ComparisonResult{Passed: true, Message: "result exists with data"}
		}
		return ComparisonResult{Passed: false, Message: "no results found"}

	case "not_exists", "empty":
		if len(actualRows) == 0 {
			return ComparisonResult{Passed: true, Message: "no results (expected)"}
		}
		return ComparisonResult{Passed: false, Message: fmt.Sprintf("found %d results but expected none", len(actualRows))}
	}

	// For all other operators, nil expected means pass (no comparison needed)
	if expected == nil {
		return ComparisonResult{Passed: true, Message: "no expected result specified"}
	}

	switch operator {
	case "equals", "eq", "":
		// Compare actual against expected map
		expectedMap, ok := expected.(map[string]interface{})
		if !ok {
			return ComparisonResult{Passed: false, Message: "expected result is not a valid map"}
		}
		for _, row := range actualRows {
			if c.mapsMatch(row, expectedMap) {
				return ComparisonResult{Passed: true, Message: "result matches expected values"}
			}
		}
		return ComparisonResult{Passed: false, Message: "no result matches expected values"}

	case "not_equals", "ne", "neq":
		expectedMap, ok := expected.(map[string]interface{})
		if !ok {
			return ComparisonResult{Passed: false, Message: "expected result is not a valid map"}
		}
		for _, row := range actualRows {
			if c.mapsMatch(row, expectedMap) {
				return ComparisonResult{Passed: false, Message: "found unexpected matching value"}
			}
		}
		return ComparisonResult{Passed: true, Message: "no results match the unexpected value"}

	case "contains":
		expectedMap, ok := expected.(map[string]interface{})
		if !ok {
			return ComparisonResult{Passed: false, Message: "expected result is not a valid map"}
		}
		for _, row := range actualRows {
			if c.mapContains(row, expectedMap) {
				return ComparisonResult{Passed: true, Message: "result contains expected values"}
			}
		}
		return ComparisonResult{Passed: false, Message: "no result contains expected values"}

	case "gte", ">=":
		return c.compareNumeric(actualRows, expected, ">=")

	case "lte", "<=":
		return c.compareNumeric(actualRows, expected, "<=")

	case "gt", ">":
		return c.compareNumeric(actualRows, expected, ">")

	case "lt", "<":
		return c.compareNumeric(actualRows, expected, "<")

	default:
		return ComparisonResult{Passed: false, Message: fmt.Sprintf("unsupported comparison operator: %s", operator)}
	}
}

// mapsMatch checks if all keys in expected exist in actual with matching values.
func (c *Comparator) mapsMatch(actual, expected map[string]interface{}) bool {
	for key, expectedVal := range expected {
		actualVal, exists := actual[key]
		if !exists {
			return false
		}
		if !c.valuesEqual(actualVal, expectedVal) {
			return false
		}
	}
	return true
}

// mapContains checks if actual contains all key-value pairs from expected.
func (c *Comparator) mapContains(actual, expected map[string]interface{}) bool {
	return c.mapsMatch(actual, expected)
}

// valuesEqual compares two values for equality, handling type conversions.
func (c *Comparator) valuesEqual(a, b interface{}) bool {
	// Handle nil cases
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// Convert to strings for comparison (osquery returns strings)
	aStr := fmt.Sprintf("%v", a)
	bStr := fmt.Sprintf("%v", b)
	return aStr == bStr
}

// compareNumeric compares numeric values from query results.
func (c *Comparator) compareNumeric(rows []map[string]interface{}, expected interface{}, op string) ComparisonResult {
	expectedMap, ok := expected.(map[string]interface{})
	if !ok {
		return ComparisonResult{Passed: false, Message: "expected result is not a valid map"}
	}

	for key, expectedVal := range expectedMap {
		for _, row := range rows {
			if actualVal, exists := row[key]; exists {
				passed, err := c.compareNumbers(actualVal, expectedVal, op)
				if err != nil {
					return ComparisonResult{Passed: false, Message: err.Error()}
				}
				if passed {
					return ComparisonResult{Passed: true, Message: fmt.Sprintf("%s %s %v: passed", key, op, expectedVal)}
				}
				return ComparisonResult{Passed: false, Message: fmt.Sprintf("%s %s %v: actual value is %v", key, op, expectedVal, actualVal)}
			}
		}
	}
	return ComparisonResult{Passed: false, Message: "key not found in results"}
}

// compareNumbers compares two numbers with the given operator.
func (c *Comparator) compareNumbers(a, b interface{}, op string) (bool, error) {
	aFloat, err := toFloat64(a)
	if err != nil {
		return false, err
	}
	bFloat, err := toFloat64(b)
	if err != nil {
		return false, err
	}

	switch op {
	case ">=", "gte":
		return aFloat >= bFloat, nil
	case "<=", "lte":
		return aFloat <= bFloat, nil
	case ">", "gt":
		return aFloat > bFloat, nil
	case "<", "lt":
		return aFloat < bFloat, nil
	default:
		return false, fmt.Errorf("unsupported numeric operator: %s", op)
	}
}

// CompareRegistryResult compares a registry value with the expected value.
func (c *Comparator) CompareRegistryResult(actual interface{}, expected interface{}, operator string) ComparisonResult {
	// Convert actual to string for comparison
	actualStr := fmt.Sprintf("%v", actual)

	// Handle existence operators first - they don't need an expected value
	switch operator {
	case "exists", "not_empty":
		if actual != nil && actualStr != "" {
			return ComparisonResult{Passed: true, Message: fmt.Sprintf("registry value exists: %q", actualStr)}
		}
		return ComparisonResult{Passed: false, Message: "registry value is empty or does not exist"}

	case "not_exists", "empty":
		if actual == nil || actualStr == "" {
			return ComparisonResult{Passed: true, Message: "registry value does not exist (expected)"}
		}
		return ComparisonResult{Passed: false, Message: fmt.Sprintf("registry value exists (%q) but should not", actualStr)}
	}

	// For all other operators, nil expected means pass (no comparison needed)
	if expected == nil {
		return ComparisonResult{Passed: true, Message: "no expected result specified"}
	}

	// Convert expected to string for comparison
	expectedStr := fmt.Sprintf("%v", expected)

	switch operator {
	case "equals", "eq", "":
		if actualStr == expectedStr {
			return ComparisonResult{Passed: true, Message: fmt.Sprintf("registry value %q matches expected %q", actualStr, expectedStr)}
		}
		return ComparisonResult{Passed: false, Message: fmt.Sprintf("registry value %q does not match expected %q", actualStr, expectedStr)}

	case "not_equals", "ne", "neq":
		if actualStr != expectedStr {
			return ComparisonResult{Passed: true, Message: fmt.Sprintf("registry value %q does not equal %q (expected)", actualStr, expectedStr)}
		}
		return ComparisonResult{Passed: false, Message: fmt.Sprintf("registry value %q equals %q but should not", actualStr, expectedStr)}

	case "contains":
		if strings.Contains(actualStr, expectedStr) {
			return ComparisonResult{Passed: true, Message: fmt.Sprintf("registry value contains %q", expectedStr)}
		}
		return ComparisonResult{Passed: false, Message: fmt.Sprintf("registry value %q does not contain %q", actualStr, expectedStr)}

	case "gte", ">=":
		actualFloat, err1 := toFloat64(actual)
		expectedFloat, err2 := toFloat64(expected)
		if err1 != nil || err2 != nil {
			return ComparisonResult{Passed: false, Message: "cannot compare non-numeric values with >= operator"}
		}
		if actualFloat >= expectedFloat {
			return ComparisonResult{Passed: true, Message: fmt.Sprintf("registry value %v >= %v", actualFloat, expectedFloat)}
		}
		return ComparisonResult{Passed: false, Message: fmt.Sprintf("registry value %v < %v", actualFloat, expectedFloat)}

	case "lte", "<=":
		actualFloat, err1 := toFloat64(actual)
		expectedFloat, err2 := toFloat64(expected)
		if err1 != nil || err2 != nil {
			return ComparisonResult{Passed: false, Message: "cannot compare non-numeric values with <= operator"}
		}
		if actualFloat <= expectedFloat {
			return ComparisonResult{Passed: true, Message: fmt.Sprintf("registry value %v <= %v", actualFloat, expectedFloat)}
		}
		return ComparisonResult{Passed: false, Message: fmt.Sprintf("registry value %v > %v", actualFloat, expectedFloat)}

	case "gt", ">":
		actualFloat, err1 := toFloat64(actual)
		expectedFloat, err2 := toFloat64(expected)
		if err1 != nil || err2 != nil {
			return ComparisonResult{Passed: false, Message: "cannot compare non-numeric values with > operator"}
		}
		if actualFloat > expectedFloat {
			return ComparisonResult{Passed: true, Message: fmt.Sprintf("registry value %v > %v", actualFloat, expectedFloat)}
		}
		return ComparisonResult{Passed: false, Message: fmt.Sprintf("registry value %v <= %v", actualFloat, expectedFloat)}

	case "lt", "<":
		actualFloat, err1 := toFloat64(actual)
		expectedFloat, err2 := toFloat64(expected)
		if err1 != nil || err2 != nil {
			return ComparisonResult{Passed: false, Message: "cannot compare non-numeric values with < operator"}
		}
		if actualFloat < expectedFloat {
			return ComparisonResult{Passed: true, Message: fmt.Sprintf("registry value %v < %v", actualFloat, expectedFloat)}
		}
		return ComparisonResult{Passed: false, Message: fmt.Sprintf("registry value %v >= %v", actualFloat, expectedFloat)}

	default:
		return ComparisonResult{Passed: false, Message: fmt.Sprintf("unsupported comparison operator: %s", operator)}
	}
}

// toFloat64 converts a value to float64.
func toFloat64(v interface{}) (float64, error) {
	switch n := v.(type) {
	case float64:
		return n, nil
	case float32:
		return float64(n), nil
	case int:
		return float64(n), nil
	case int64:
		return float64(n), nil
	case int32:
		return float64(n), nil
	case string:
		var f float64
		_, err := fmt.Sscanf(n, "%f", &f)
		if err != nil {
			return 0, fmt.Errorf("cannot convert %q to number", n)
		}
		return f, nil
	default:
		return 0, fmt.Errorf("cannot convert %T to number", v)
	}
}
