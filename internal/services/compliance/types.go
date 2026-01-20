// Package compliance provides compliance check services.
// This package extracts compliance check business logic from handlers
// following MVC patterns for proper separation of concerns.
package compliance

import "context"

// CheckResult represents the result of a single compliance check.
type CheckResult struct {
	CheckID     string `json:"check_id"`
	Name        string `json:"name,omitempty"`
	Passed      bool   `json:"passed"`
	Status      string `json:"status"` // passed, failed, error, skipped
	Message     string `json:"message,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Category    string `json:"category,omitempty"`
	ActualValue string `json:"actual_value,omitempty"`
}

// Check represents a single compliance check configuration.
type Check struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	Description    string      `json:"description,omitempty"`
	Severity       string      `json:"severity,omitempty"`
	Category       string      `json:"category,omitempty"`
	Type           string      `json:"type"` // osquery, registry, command
	Query          string      `json:"query,omitempty"`
	ExpectedResult interface{} `json:"expected_result,omitempty"`
	Operator       string      `json:"operator,omitempty"`
	// Registry-specific fields
	RegistryPath  string `json:"registry_path,omitempty"`
	RegistryValue string `json:"registry_value,omitempty"`
	// Command-specific fields
	Command     string `json:"command,omitempty"`
	CommandType string `json:"command_type,omitempty"`
}

// PolicyRequest represents a compliance policy check request.
type PolicyRequest struct {
	PolicyID   string  `json:"policy_id"`
	PolicyName string  `json:"policy_name,omitempty"`
	Checks     []Check `json:"checks"`
}

// PolicyResult represents the result of a compliance policy check.
type PolicyResult struct {
	PolicyID     string        `json:"policy_id"`
	PolicyName   string        `json:"policy_name,omitempty"`
	TotalChecks  int           `json:"total_checks"`
	PassedChecks int           `json:"passed_checks"`
	FailedChecks int           `json:"failed_checks"`
	ErrorChecks  int           `json:"error_checks"`
	OverallPass  bool          `json:"overall_pass"`
	Results      []CheckResult `json:"results"`
}

// ComparisonResult contains the result of a value comparison.
type ComparisonResult struct {
	Passed  bool
	Message string
}

// ComplianceService defines the interface for compliance checking operations.
type ComplianceService interface {
	// RunPolicyCheck executes all checks in a compliance policy.
	RunPolicyCheck(ctx context.Context, req *PolicyRequest) (*PolicyResult, error)

	// RunSingleCheck executes a single compliance check.
	RunSingleCheck(ctx context.Context, check *Check) (*CheckResult, error)
}

// QueryExecutor defines the interface for executing osquery queries.
type QueryExecutor interface {
	// ExecuteQuery executes an osquery query and returns the results.
	ExecuteQuery(ctx context.Context, query string) ([]map[string]interface{}, error)
}

// RegistryReader defines the interface for reading Windows registry values.
type RegistryReader interface {
	// ReadValue reads a value from the Windows registry.
	ReadValue(ctx context.Context, path, valueName string) (interface{}, error)
}

// CommandRunner defines the interface for executing system commands.
type CommandRunner interface {
	// Run executes a command and returns the output.
	Run(ctx context.Context, command string, args ...string) (string, error)
}
