package backup

// ProgressReporter defines the interface for reporting backup/restore progress.
// This replaces direct WebSocket calls in handlers.
type ProgressReporter interface {
	// ReportProgress reports progress of an operation.
	// phase: current phase (e.g., "downloading", "encrypting", "uploading")
	// percent: progress percentage (0-100)
	// message: human-readable message
	// level: log level ("info", "warning", "error")
	ReportProgress(phase string, percent int, message string, level string)

	// ReportError reports an error during operation.
	ReportError(err error)

	// ReportCompletion reports successful completion.
	ReportCompletion(result interface{})
}

// NoOpProgressReporter is a progress reporter that does nothing.
type NoOpProgressReporter struct{}

func (r *NoOpProgressReporter) ReportProgress(phase string, percent int, message string, level string) {}
func (r *NoOpProgressReporter) ReportError(err error)                                                  {}
func (r *NoOpProgressReporter) ReportCompletion(result interface{})                                    {}

// ChannelProgressReporter sends progress updates to a channel.
type ChannelProgressReporter struct {
	progressCh chan<- ProgressUpdate
	errorCh    chan<- error
	resultCh   chan<- interface{}
}

// ProgressUpdate represents a progress update.
type ProgressUpdate struct {
	Phase   string
	Percent int
	Message string
	Level   string
}

// NewChannelProgressReporter creates a new channel-based progress reporter.
func NewChannelProgressReporter(
	progressCh chan<- ProgressUpdate,
	errorCh chan<- error,
	resultCh chan<- interface{},
) *ChannelProgressReporter {
	return &ChannelProgressReporter{
		progressCh: progressCh,
		errorCh:    errorCh,
		resultCh:   resultCh,
	}
}

func (r *ChannelProgressReporter) ReportProgress(phase string, percent int, message string, level string) {
	if r.progressCh != nil {
		select {
		case r.progressCh <- ProgressUpdate{
			Phase:   phase,
			Percent: percent,
			Message: message,
			Level:   level,
		}:
		default:
			// Channel full, skip update
		}
	}
}

func (r *ChannelProgressReporter) ReportError(err error) {
	if r.errorCh != nil {
		select {
		case r.errorCh <- err:
		default:
		}
	}
}

func (r *ChannelProgressReporter) ReportCompletion(result interface{}) {
	if r.resultCh != nil {
		select {
		case r.resultCh <- result:
		default:
		}
	}
}

// CallbackProgressReporter calls functions for progress updates.
type CallbackProgressReporter struct {
	onProgress   func(phase string, percent int, message string, level string)
	onError      func(err error)
	onCompletion func(result interface{})
}

// NewCallbackProgressReporter creates a new callback-based progress reporter.
func NewCallbackProgressReporter(
	onProgress func(phase string, percent int, message string, level string),
	onError func(err error),
	onCompletion func(result interface{}),
) *CallbackProgressReporter {
	return &CallbackProgressReporter{
		onProgress:   onProgress,
		onError:      onError,
		onCompletion: onCompletion,
	}
}

func (r *CallbackProgressReporter) ReportProgress(phase string, percent int, message string, level string) {
	if r.onProgress != nil {
		r.onProgress(phase, percent, message, level)
	}
}

func (r *CallbackProgressReporter) ReportError(err error) {
	if r.onError != nil {
		r.onError(err)
	}
}

func (r *CallbackProgressReporter) ReportCompletion(result interface{}) {
	if r.onCompletion != nil {
		r.onCompletion(result)
	}
}
