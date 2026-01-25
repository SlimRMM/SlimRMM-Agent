// Package handler provides winget helper functions.
package handler

import (
	"context"
	"strings"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/actions"
)

// wingetPolicyContext holds context for winget policy execution.
type wingetPolicyContext struct {
	ExecutionID string
	PolicyID    string
	StartedAt   time.Time
	WingetPath  string
	Handler     *Handler
}

// newWingetPolicyContext creates a new winget policy context.
func newWingetPolicyContext(executionID, policyID, wingetPath string, h *Handler) *wingetPolicyContext {
	return &wingetPolicyContext{
		ExecutionID: executionID,
		PolicyID:    policyID,
		StartedAt:   time.Now(),
		WingetPath:  wingetPath,
		Handler:     h,
	}
}

// sendProgress sends a progress update for winget policy execution.
func (pc *wingetPolicyContext) sendProgress(currentPackage string, currentIndex, totalPackages int, packageStatus string) {
	msg := map[string]interface{}{
		"action":          "winget_policy_progress",
		"execution_id":    pc.ExecutionID,
		"policy_id":       pc.PolicyID,
		"current_package": currentPackage,
		"current_index":   currentIndex,
		"total_packages":  totalPackages,
	}
	if packageStatus != "" {
		msg["package_status"] = packageStatus
	}
	pc.Handler.SendRaw(msg)
}

// buildErrorResponse builds an error response for winget policy execution.
func (pc *wingetPolicyContext) buildErrorResponse(errorMsg string) map[string]interface{} {
	return map[string]interface{}{
		"action":       "winget_policy_result",
		"execution_id": pc.ExecutionID,
		"policy_id":    pc.PolicyID,
		"status":       "failed",
		"error":        errorMsg,
		"started_at":   pc.StartedAt.UTC().Format(time.RFC3339),
		"completed_at": time.Now().UTC().Format(time.RFC3339),
	}
}

// buildEmptyResponse builds a response when no updates need processing.
func (pc *wingetPolicyContext) buildEmptyResponse() map[string]interface{} {
	return map[string]interface{}{
		"action":         "winget_policy_result",
		"execution_id":   pc.ExecutionID,
		"policy_id":      pc.PolicyID,
		"status":         "completed",
		"total_packages": 0,
		"succeeded":      0,
		"failed":         0,
		"results":        []wingetUpdateResult{},
		"started_at":     pc.StartedAt.UTC().Format(time.RFC3339),
		"completed_at":   time.Now().UTC().Format(time.RFC3339),
		"duration_ms":    time.Since(pc.StartedAt).Milliseconds(),
	}
}

// buildFinalResponse builds the final response for winget policy execution.
func (pc *wingetPolicyContext) buildFinalResponse(results []wingetUpdateResult, succeeded, failed int) map[string]interface{} {
	completedAt := time.Now()
	status := determineWingetPolicyStatus(succeeded, failed)

	return map[string]interface{}{
		"action":         "winget_policy_result",
		"execution_id":   pc.ExecutionID,
		"policy_id":      pc.PolicyID,
		"status":         status,
		"total_packages": len(results),
		"succeeded":      succeeded,
		"failed":         failed,
		"results":        results,
		"started_at":     pc.StartedAt.UTC().Format(time.RFC3339),
		"completed_at":   completedAt.UTC().Format(time.RFC3339),
		"duration_ms":    completedAt.Sub(pc.StartedAt).Milliseconds(),
	}
}

// filterWingetUpdates extracts only winget source updates from a list of updates.
func filterWingetUpdates(updates []actions.Update) []actions.Update {
	var wingetUpdates []actions.Update
	for _, u := range updates {
		if u.Source == "winget" {
			wingetUpdates = append(wingetUpdates, u)
		}
	}
	return wingetUpdates
}

// applyWingetFilterMode applies whitelist/blacklist filtering to winget updates.
func applyWingetFilterMode(updates []actions.Update, filterMode string, packageFilters []string) []actions.Update {
	if filterMode == "" || filterMode == "all" {
		return updates
	}

	// Build filter set
	filterSet := make(map[string]bool)
	for _, id := range packageFilters {
		filterSet[strings.ToLower(id)] = true
	}

	var filtered []actions.Update
	for _, u := range updates {
		packageID := strings.ToLower(u.KB) // KB contains package ID for winget
		inFilter := filterSet[packageID]

		switch filterMode {
		case "whitelist":
			if inFilter {
				filtered = append(filtered, u)
			}
		case "blacklist":
			if !inFilter {
				filtered = append(filtered, u)
			}
		}
	}

	return filtered
}

// determineWingetPolicyStatus determines overall status based on succeeded/failed counts.
func determineWingetPolicyStatus(succeeded, failed int) string {
	if failed > 0 && succeeded == 0 {
		return "failed"
	} else if failed > 0 {
		return "partial"
	}
	return "completed"
}

// wingetPolicyResult holds the result of executing winget policy updates.
type wingetPolicyResult struct {
	Results   []wingetUpdateResult
	Succeeded int
	Failed    int
}

// executeWingetPolicyUpdates executes updates and collects results.
func (pc *wingetPolicyContext) executeWingetPolicyUpdates(ctx context.Context, updates []actions.Update) wingetPolicyResult {
	var result wingetPolicyResult

	for i, update := range updates {
		// Send progress before execution
		pc.sendProgress(update.Name, i+1, len(updates), "")

		// Execute winget upgrade for this package
		updateResult := pc.Handler.executeWingetUpgrade(ctx, pc.WingetPath, update)
		result.Results = append(result.Results, updateResult)

		if updateResult.Status == "success" {
			result.Succeeded++
		} else {
			result.Failed++
		}

		// Send progress with result
		pc.sendProgress(update.Name, i+1, len(updates), updateResult.Status)
	}

	return result
}

// wingetInstallPolicyContext holds context for winget install policy execution.
type wingetInstallPolicyContext struct {
	ExecutionID string
	PolicyID    string
	PolicyName  string
	StartedAt   time.Time
	WingetPath  string
	Handler     *Handler
}

// newWingetInstallPolicyContext creates a new winget install policy context.
func newWingetInstallPolicyContext(executionID, policyID, policyName, wingetPath string, h *Handler) *wingetInstallPolicyContext {
	return &wingetInstallPolicyContext{
		ExecutionID: executionID,
		PolicyID:    policyID,
		PolicyName:  policyName,
		StartedAt:   time.Now(),
		WingetPath:  wingetPath,
		Handler:     h,
	}
}

// sendProgress sends a progress update for winget install policy execution.
func (pc *wingetInstallPolicyContext) sendProgress(currentPackage string, currentIndex, totalPackages int, packageStatus string) {
	msg := map[string]interface{}{
		"action":          "winget_install_policy_progress",
		"execution_id":    pc.ExecutionID,
		"policy_id":       pc.PolicyID,
		"current_package": currentPackage,
		"current_index":   currentIndex,
		"total_packages":  totalPackages,
	}
	if packageStatus != "" {
		msg["package_status"] = packageStatus
	}
	pc.Handler.SendRaw(msg)
}

// buildErrorResponse builds an error response for winget install policy execution.
func (pc *wingetInstallPolicyContext) buildErrorResponse(errorMsg string) map[string]interface{} {
	return map[string]interface{}{
		"action":       "winget_install_policy_result",
		"execution_id": pc.ExecutionID,
		"policy_id":    pc.PolicyID,
		"status":       "failed",
		"error":        errorMsg,
		"started_at":   pc.StartedAt.UTC().Format(time.RFC3339),
		"completed_at": time.Now().UTC().Format(time.RFC3339),
	}
}

// buildFinalResponse builds the final response for winget install policy execution.
func (pc *wingetInstallPolicyContext) buildFinalResponse(results []wingetInstallResult, succeeded, failed, skipped int) map[string]interface{} {
	completedAt := time.Now()
	status := determineWingetPolicyStatus(succeeded, failed)

	return map[string]interface{}{
		"action":         "winget_install_policy_result",
		"execution_id":   pc.ExecutionID,
		"policy_id":      pc.PolicyID,
		"status":         status,
		"total_packages": len(results),
		"succeeded":      succeeded,
		"failed":         failed,
		"skipped":        skipped,
		"results":        results,
		"started_at":     pc.StartedAt.UTC().Format(time.RFC3339),
		"completed_at":   completedAt.UTC().Format(time.RFC3339),
		"duration_ms":    completedAt.Sub(pc.StartedAt).Milliseconds(),
	}
}

// wingetUpdateContext holds context for single package winget update.
type wingetUpdateContext struct {
	ExecutionID string
	PackageID   string
	PackageName string
	StartedAt   time.Time
	WingetPath  string
	Handler     *Handler
}

// newWingetUpdateContext creates a new winget update context.
func newWingetUpdateContext(executionID, packageID, packageName, wingetPath string, h *Handler) *wingetUpdateContext {
	return &wingetUpdateContext{
		ExecutionID: executionID,
		PackageID:   packageID,
		PackageName: packageName,
		StartedAt:   time.Now(),
		WingetPath:  wingetPath,
		Handler:     h,
	}
}

// sendOutput sends output to the client.
func (uc *wingetUpdateContext) sendOutput(output string) {
	uc.Handler.SendRaw(map[string]interface{}{
		"action":       "winget_update_output",
		"execution_id": uc.ExecutionID,
		"output":       output,
	})
}

// buildResponse builds a response for winget update.
func (uc *wingetUpdateContext) buildResponse(status, context, output, errorOutput, errorMsg string) map[string]interface{} {
	response := map[string]interface{}{
		"action":       "winget_update_result",
		"execution_id": uc.ExecutionID,
		"status":       status,
		"package_id":   uc.PackageID,
		"package_name": uc.PackageName,
		"context":      context,
		"started_at":   uc.StartedAt.UTC().Format(time.RFC3339),
		"completed_at": time.Now().UTC().Format(time.RFC3339),
		"duration_ms":  time.Since(uc.StartedAt).Milliseconds(),
	}

	if output != "" {
		response["output"] = output
	}
	if errorOutput != "" {
		response["error_output"] = errorOutput
	}
	if errorMsg != "" {
		response["error"] = errorMsg
	}

	return response
}

// buildSuccessResponse builds a success response for winget update.
func (uc *wingetUpdateContext) buildSuccessResponse(context, output string) map[string]interface{} {
	return uc.buildResponse("completed", context, output, "", "")
}

// buildFailedResponse builds a failed response for winget update.
func (uc *wingetUpdateContext) buildFailedResponse(context, output, errorOutput, errorMsg string) map[string]interface{} {
	return uc.buildResponse("failed", context, output, errorOutput, errorMsg)
}
