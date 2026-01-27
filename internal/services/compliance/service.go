// Package compliance provides compliance check services.
package compliance

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

// DefaultComplianceService implements ComplianceService using platform-specific
// query executors, registry readers, and command runners.
type DefaultComplianceService struct {
	logger         *slog.Logger
	comparator     *Comparator
	queryExecutor  QueryExecutor
	registryReader RegistryReader
	commandRunner  CommandRunner
}

// ServiceOption is a functional option for configuring the service.
type ServiceOption func(*DefaultComplianceService)

// WithQueryExecutor sets the query executor for the service.
func WithQueryExecutor(executor QueryExecutor) ServiceOption {
	return func(s *DefaultComplianceService) {
		s.queryExecutor = executor
	}
}

// WithRegistryReader sets the registry reader for the service.
func WithRegistryReader(reader RegistryReader) ServiceOption {
	return func(s *DefaultComplianceService) {
		s.registryReader = reader
	}
}

// WithCommandRunner sets the command runner for the service.
func WithCommandRunner(runner CommandRunner) ServiceOption {
	return func(s *DefaultComplianceService) {
		s.commandRunner = runner
	}
}

// NewComplianceService creates a new compliance service with the provided options.
func NewComplianceService(logger *slog.Logger, opts ...ServiceOption) *DefaultComplianceService {
	s := &DefaultComplianceService{
		logger:     logger,
		comparator: NewComparator(),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// RunPolicyCheck executes all checks in a compliance policy.
func (s *DefaultComplianceService) RunPolicyCheck(ctx context.Context, req *PolicyRequest) (*PolicyResult, error) {
	s.logger.Info("running compliance policy check",
		"policy_id", req.PolicyID,
		"policy_name", req.PolicyName,
		"total_checks", len(req.Checks),
	)

	result := &PolicyResult{
		PolicyID:   req.PolicyID,
		PolicyName: req.PolicyName,
		Results:    make([]CheckResult, 0, len(req.Checks)),
	}

	for _, check := range req.Checks {
		checkResult, err := s.RunSingleCheck(ctx, &check)
		if err != nil {
			s.logger.Error("check execution failed",
				"check_id", check.ID,
				"error", err,
			)
			checkResult = &CheckResult{
				CheckID:  check.ID,
				Name:     check.Name,
				Passed:   false,
				Status:   "error",
				Message:  err.Error(),
				Severity: check.Severity,
				Category: check.Category,
			}
		}

		result.Results = append(result.Results, *checkResult)
		result.TotalChecks++

		switch checkResult.Status {
		case "passed":
			result.PassedChecks++
		case "failed":
			result.FailedChecks++
		case "error":
			result.ErrorChecks++
		}
	}

	result.OverallPass = result.FailedChecks == 0 && result.ErrorChecks == 0

	s.logger.Info("compliance policy check completed",
		"policy_id", req.PolicyID,
		"total", result.TotalChecks,
		"passed", result.PassedChecks,
		"failed", result.FailedChecks,
		"errors", result.ErrorChecks,
		"overall_pass", result.OverallPass,
	)

	return result, nil
}

// RunSingleCheck executes a single compliance check.
func (s *DefaultComplianceService) RunSingleCheck(ctx context.Context, check *Check) (*CheckResult, error) {
	s.logger.Debug("running single compliance check",
		"check_id", check.ID,
		"type", check.Type,
	)

	result := &CheckResult{
		CheckID:  check.ID,
		Name:     check.Name,
		Severity: check.Severity,
		Category: check.Category,
	}

	switch check.Type {
	case "osquery":
		return s.runOsqueryCheck(ctx, check, result)
	case "registry":
		return s.runRegistryCheck(ctx, check, result)
	case "command":
		return s.runCommandCheck(ctx, check, result)
	default:
		result.Status = "error"
		result.Message = fmt.Sprintf("unknown check type: %s", check.Type)
		return result, nil
	}
}

// validateOsqueryQuery validates an osquery query for security.
// SECURITY: Prevents execution of dangerous queries.
func validateOsqueryQuery(query string) error {
	// Normalize query for validation
	normalized := strings.ToLower(strings.TrimSpace(query))

	// SECURITY: Only allow SELECT statements
	if !strings.HasPrefix(normalized, "select ") {
		return fmt.Errorf("only SELECT queries are allowed")
	}

	// SECURITY: Block dangerous SQL keywords
	dangerousPatterns := []string{
		`\bdrop\b`, `\bdelete\b`, `\binsert\b`, `\bupdate\b`,
		`\bcreate\b`, `\balter\b`, `\btruncate\b`, `\bexec\b`,
		`\battach\b`, `\bdetach\b`, `\bload_extension\b`,
	}
	for _, pattern := range dangerousPatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(normalized) {
			return fmt.Errorf("query contains forbidden keyword")
		}
	}

	// SECURITY: Block access to highly sensitive tables that could be used for reconnaissance
	// These tables expose sensitive system information beyond compliance checking needs
	sensitiveTablePatterns := []string{
		`\bshadow\b`,              // Password hashes
		`\bcurl\b`,                // Can make network requests
		`\bcurl_certificate\b`,    // Network access
		`\bcarves\b`,              // File carving
		`\byara\b`,                // YARA scanning
		`\baugeas\b`,              // Config file manipulation
	}
	for _, pattern := range sensitiveTablePatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(normalized) {
			return fmt.Errorf("access to sensitive table is not allowed")
		}
	}

	// SECURITY: Limit query length to prevent resource exhaustion
	if len(query) > 4096 {
		return fmt.Errorf("query exceeds maximum allowed length")
	}

	return nil
}

// runOsqueryCheck executes an osquery-based compliance check.
func (s *DefaultComplianceService) runOsqueryCheck(ctx context.Context, check *Check, result *CheckResult) (*CheckResult, error) {
	if s.queryExecutor == nil {
		result.Status = "error"
		result.Message = "osquery executor not available"
		return result, nil
	}

	// SECURITY: Validate query before execution
	if err := validateOsqueryQuery(check.Query); err != nil {
		s.logger.Warn("compliance query validation failed",
			"check_id", check.ID,
			"error", err,
		)
		result.Status = "error"
		result.Message = fmt.Sprintf("query validation failed: %v", err)
		return result, nil
	}

	rows, err := s.queryExecutor.ExecuteQuery(ctx, check.Query)
	if err != nil {
		result.Status = "error"
		result.Message = fmt.Sprintf("query execution failed: %v", err)
		return result, nil
	}

	// Set actual value for reporting
	if len(rows) > 0 {
		result.ActualValue = fmt.Sprintf("%v", rows[0])
	}

	comparison := s.comparator.CompareQueryResult(rows, check.ExpectedResult, check.Operator)
	result.Passed = comparison.Passed
	result.Message = comparison.Message

	if comparison.Passed {
		result.Status = "passed"
	} else {
		result.Status = "failed"
	}

	return result, nil
}

// runRegistryCheck executes a Windows registry-based compliance check.
func (s *DefaultComplianceService) runRegistryCheck(ctx context.Context, check *Check, result *CheckResult) (*CheckResult, error) {
	if s.registryReader == nil {
		result.Status = "error"
		result.Message = "registry reader not available"
		return result, nil
	}

	value, err := s.registryReader.ReadValue(ctx, check.RegistryPath, check.RegistryValue)
	if err != nil {
		// Check if this is an "exists" check that expects the value not to exist
		if check.Operator == "not_exists" || check.Operator == "empty" {
			result.Status = "passed"
			result.Passed = true
			result.Message = "registry value does not exist (expected)"
			return result, nil
		}
		result.Status = "error"
		result.Message = fmt.Sprintf("failed to read registry: %v", err)
		return result, nil
	}

	// Set actual value for reporting
	result.ActualValue = fmt.Sprintf("%v", value)

	comparison := s.comparator.CompareRegistryResult(value, check.ExpectedResult, check.Operator)
	result.Passed = comparison.Passed
	result.Message = comparison.Message

	if comparison.Passed {
		result.Status = "passed"
	} else {
		result.Status = "failed"
	}

	return result, nil
}

// runCommandCheck executes a command-based compliance check.
func (s *DefaultComplianceService) runCommandCheck(ctx context.Context, check *Check, result *CheckResult) (*CheckResult, error) {
	if s.commandRunner == nil {
		result.Status = "error"
		result.Message = "command runner not available"
		return result, nil
	}

	output, err := s.commandRunner.Run(ctx, check.Command)
	if err != nil {
		result.Status = "error"
		result.Message = fmt.Sprintf("command execution failed: %v", err)
		return result, nil
	}

	result.ActualValue = output

	// For command checks, compare the output string
	comparison := s.comparator.CompareRegistryResult(output, check.ExpectedResult, check.Operator)
	result.Passed = comparison.Passed
	result.Message = comparison.Message

	if comparison.Passed {
		result.Status = "passed"
	} else {
		result.Status = "failed"
	}

	return result, nil
}
