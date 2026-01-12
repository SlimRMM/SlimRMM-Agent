package terminal

import "errors"

var (
	// ErrMaxSessionsReached indicates the maximum number of sessions has been reached.
	ErrMaxSessionsReached = errors.New("maximum terminal sessions reached")

	// ErrSessionNotFound indicates the session was not found.
	ErrSessionNotFound = errors.New("terminal session not found")

	// ErrShellNotAllowed indicates the requested shell is not allowed.
	ErrShellNotAllowed = errors.New("shell not allowed")

	// ErrInputTooLarge indicates the input exceeds the maximum size.
	ErrInputTooLarge = errors.New("terminal input too large")

	// ErrDangerousInput indicates potentially dangerous input sequences.
	ErrDangerousInput = errors.New("dangerous terminal input detected")

	// ErrSessionExpired indicates the session has expired due to inactivity.
	ErrSessionExpired = errors.New("terminal session expired")

	// ErrRateLimitExceeded indicates the input rate limit was exceeded.
	ErrRateLimitExceeded = errors.New("terminal input rate limit exceeded")
)
