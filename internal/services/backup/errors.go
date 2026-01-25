package backup

import "fmt"

// ErrUnknownBackupType is returned when an unknown backup type is requested.
type ErrUnknownBackupType struct {
	Type string
}

func (e *ErrUnknownBackupType) Error() string {
	return fmt.Sprintf("unknown backup type: %s", e.Type)
}

// ErrCollectionFailed is returned when backup collection fails.
type ErrCollectionFailed struct {
	Type   BackupType
	Reason string
	Err    error
}

func (e *ErrCollectionFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("backup collection failed for %s: %s: %v", e.Type, e.Reason, e.Err)
	}
	return fmt.Sprintf("backup collection failed for %s: %s", e.Type, e.Reason)
}

func (e *ErrCollectionFailed) Unwrap() error {
	return e.Err
}

// ErrCompressionFailed is returned when compression fails.
type ErrCompressionFailed struct {
	Err error
}

func (e *ErrCompressionFailed) Error() string {
	return fmt.Sprintf("compression failed: %v", e.Err)
}

func (e *ErrCompressionFailed) Unwrap() error {
	return e.Err
}

// ErrEncryptionFailed is returned when encryption fails.
type ErrEncryptionFailed struct {
	Reason string
	Err    error
}

func (e *ErrEncryptionFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("encryption failed: %s: %v", e.Reason, e.Err)
	}
	return fmt.Sprintf("encryption failed: %s", e.Reason)
}

func (e *ErrEncryptionFailed) Unwrap() error {
	return e.Err
}

// ErrDecryptionFailed is returned when decryption fails.
type ErrDecryptionFailed struct {
	Reason string
	Err    error
}

func (e *ErrDecryptionFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("decryption failed: %s: %v", e.Reason, e.Err)
	}
	return fmt.Sprintf("decryption failed: %s", e.Reason)
}

func (e *ErrDecryptionFailed) Unwrap() error {
	return e.Err
}

// ErrUploadFailed is returned when upload fails.
type ErrUploadFailed struct {
	StatusCode int
	Message    string
	Err        error
}

func (e *ErrUploadFailed) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("upload failed with status %d: %s", e.StatusCode, e.Message)
	}
	if e.Err != nil {
		return fmt.Sprintf("upload failed: %v", e.Err)
	}
	return fmt.Sprintf("upload failed: %s", e.Message)
}

func (e *ErrUploadFailed) Unwrap() error {
	return e.Err
}

// ErrDownloadFailed is returned when download fails.
type ErrDownloadFailed struct {
	StatusCode int
	Message    string
	Err        error
}

func (e *ErrDownloadFailed) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("download failed with status %d: %s", e.StatusCode, e.Message)
	}
	if e.Err != nil {
		return fmt.Sprintf("download failed: %v", e.Err)
	}
	return fmt.Sprintf("download failed: %s", e.Message)
}

func (e *ErrDownloadFailed) Unwrap() error {
	return e.Err
}

// ErrPlatformUnsupported is returned when a feature is not supported on the current platform.
type ErrPlatformUnsupported struct {
	Feature  string
	Platform string
}

func (e *ErrPlatformUnsupported) Error() string {
	return fmt.Sprintf("%s is not supported on %s", e.Feature, e.Platform)
}

// ErrMissingParameter is returned when a required parameter is missing.
type ErrMissingParameter struct {
	Parameter string
	Context   string
}

func (e *ErrMissingParameter) Error() string {
	return fmt.Sprintf("%s is required for %s", e.Parameter, e.Context)
}

// ErrFeatureUnavailable is returned when a required feature is not available.
type ErrFeatureUnavailable struct {
	Feature string
	Reason  string
}

func (e *ErrFeatureUnavailable) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("%s is not available: %s", e.Feature, e.Reason)
	}
	return fmt.Sprintf("%s is not available on this system", e.Feature)
}
