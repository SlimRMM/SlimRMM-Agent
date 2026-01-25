// Package backup provides backup collection services for the RMM agent.
package backup

// WebSocketProgressReporter implements ProgressReporter for WebSocket-based progress reporting.
type WebSocketProgressReporter struct {
	backupID    string
	sendFunc    func(msg map[string]interface{})
	errorFunc   func(err error)
	completeFunc func(result interface{})
}

// NewWebSocketProgressReporter creates a new WebSocket progress reporter.
func NewWebSocketProgressReporter(backupID string, sendFunc func(msg map[string]interface{})) *WebSocketProgressReporter {
	return &WebSocketProgressReporter{
		backupID: backupID,
		sendFunc: sendFunc,
	}
}

// SetErrorCallback sets the callback for error reporting.
func (r *WebSocketProgressReporter) SetErrorCallback(f func(err error)) {
	r.errorFunc = f
}

// SetCompleteCallback sets the callback for completion reporting.
func (r *WebSocketProgressReporter) SetCompleteCallback(f func(result interface{})) {
	r.completeFunc = f
}

// ReportProgress sends a progress update via WebSocket.
func (r *WebSocketProgressReporter) ReportProgress(phase string, percent int, message string, level string) {
	if r.sendFunc != nil {
		r.sendFunc(map[string]interface{}{
			"action":    "backup_progress",
			"backup_id": r.backupID,
			"phase":     phase,
			"percent":   percent,
			"message":   message,
			"level":     level,
		})
	}
}

// ReportError sends an error update via WebSocket.
func (r *WebSocketProgressReporter) ReportError(err error) {
	if r.errorFunc != nil {
		r.errorFunc(err)
	} else if r.sendFunc != nil {
		r.sendFunc(map[string]interface{}{
			"action":    "backup_error",
			"backup_id": r.backupID,
			"error":     err.Error(),
		})
	}
}

// ReportCompletion sends a completion update via WebSocket.
func (r *WebSocketProgressReporter) ReportCompletion(result interface{}) {
	if r.completeFunc != nil {
		r.completeFunc(result)
	}
}
