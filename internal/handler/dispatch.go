package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// handleMessage processes an incoming message.
func (h *Handler) handleMessage(ctx context.Context, data []byte) {
	// Defence-in-depth: reject deeply nested JSON before handing it to
	// encoding/json. This guards against "JSON bomb" DoS payloads that can
	// otherwise trigger pathological parser behaviour or stack pressure.
	if err := validateJSONDepth(data, MaxJSONDepth); err != nil {
		h.logger.Warn("dropping message with excessive JSON nesting",
			"error", err,
			"max_depth", MaxJSONDepth,
			"size_bytes", len(data),
		)
		return
	}
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		h.logger.Error("parsing message", "error", err)
		return
	}
	// Store raw message for handlers that need to parse additional fields
	msg.Raw = data

	h.logger.Debug("received message", "action", msg.Action, "request_id", msg.RequestID, "scan_type", msg.ScanType)

	// Security Layer 1: Rate limiting
	if !h.rateLimiter.Allow(msg.Action) {
		h.logger.Warn("rate limit exceeded",
			"action", msg.Action,
			"request_id", msg.RequestID,
		)
		h.auditLogger.LogRateLimit(ctx, msg.Action, 0, 0)
		h.Send(Response{
			Action:    msg.Action,
			RequestID: msg.RequestID,
			Success:   false,
			Error:     "rate limit exceeded",
		})
		return
	}

	// Security Layer 2: Anti-replay protection (for requests with request_id)
	if msg.RequestID != "" {
		// Extract timestamp if present in message
		var msgWithTime struct {
			Timestamp int64 `json:"timestamp"`
		}
		json.Unmarshal(data, &msgWithTime)

		requestTime := time.Now()
		if msgWithTime.Timestamp > 0 {
			requestTime = time.Unix(msgWithTime.Timestamp, 0)
		}

		if err := h.antiReplay.ValidateRequest(msg.RequestID, requestTime); err != nil {
			h.logger.Warn("replay detection triggered",
				"action", msg.Action,
				"request_id", msg.RequestID,
				"error", err,
			)
			h.auditLogger.LogReplayAttempt(ctx, msg.RequestID, requestTime)
			h.Send(Response{
				Action:    msg.Action,
				RequestID: msg.RequestID,
				Success:   false,
				Error:     "request validation failed",
			})
			return
		}
	}

	handler, ok := h.handlers[msg.Action]
	if !ok {
		h.logger.Warn("unknown action", "action", msg.Action)
		h.Send(Response{
			Action:    msg.Action,
			RequestID: msg.RequestID,
			Success:   false,
			Error:     fmt.Sprintf("unknown action: %s", msg.Action),
		})
		return
	}

	// Log handler dispatch for software installation actions
	if msg.Action == "download_and_install_pkg" || msg.Action == "download_and_install_msi" ||
		msg.Action == "download_and_install_cask" || msg.Action == "install_software" {
		h.logger.Info("dispatching software installation action", "action", msg.Action)
	}

	// Determine what data to pass to the handler
	// Some actions have fields at the root level rather than in a nested "data" object
	var handlerData json.RawMessage
	rootLevelActions := map[string]bool{
		// osquery
		"run_osquery": true,
		"osquery":     true,
		// Terminal actions - fields are at root level (rows, cols, data, etc.)
		"terminal":        true,
		"terminal_input":  true,
		"terminal_resize": true,
		"start_terminal":  true,
		"stop_terminal":   true,
		"terminal_stop":   true,
		"terminal_output": true,
		// File browser actions - path, old_path, new_path at root
		"list_dir":      true,
		"create_folder": true,
		"create_dir":    true,
		"delete_entry":  true,
		"rename_entry":  true,
		"zip_entry":     true,
		"unzip_entry":   true,
		"download_file": true,
		"chmod":         true,
		"chown":         true,
		// Upload actions - path, data, offset, is_last at root
		"upload_chunk":   true,
		"start_upload":   true,
		"finish_upload":  true,
		"cancel_upload":  true,
		"download_chunk": true,
		"download_url":   true,
		// Compliance checks - policy_id, checks at root
		"run_compliance_check": true,
		// Software installation actions - all fields at root
		"install_software":          true,
		"download_and_install_msi":  true,
		"download_and_install_pkg":  true,
		"download_and_install_cask": true,
		"cancel_software_install":   true,
		// Software uninstallation actions - all fields at root
		"uninstall_software":        true,
		"uninstall_msi":             true,
		"uninstall_pkg":             true,
		"uninstall_cask":            true,
		"uninstall_deb":             true,
		"uninstall_rpm":             true,
		"cancel_software_uninstall": true,
	}
	if rootLevelActions[msg.Action] {
		handlerData = msg.Raw
	} else if len(msg.Data) > 0 {
		handlerData = msg.Data
	} else {
		// If no data field, pass the raw message so handlers can parse root-level fields
		handlerData = msg.Raw
	}

	// Apply a per-handler timeout so a slow handler cannot block the dispatcher
	// indefinitely. Long-running handlers (updates, scripts, transfers, patches)
	// get an extended timeout; everything else gets the default.
	handlerTimeout := defaultHandlerTimeout
	if longRunningActions[msg.Action] {
		handlerTimeout = longHandlerTimeout
	}
	handlerCtx, cancelHandler := context.WithTimeout(ctx, handlerTimeout)
	defer cancelHandler()

	type handlerOutcome struct {
		result interface{}
		err    error
	}
	// buffered ch (size 1) + defer recover ensures goroutine always exits,
	// even after parent returned on timeout. The buffer guarantees the goroutine
	// can always send its outcome without blocking, and defer cancel() above
	// cancels handlerCtx so the handler sees ctx.Done() and can unwind.
	outcomeCh := make(chan handlerOutcome, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				h.logger.Error("handler goroutine panic recovered",
					"action", msg.Action,
					"request_id", msg.RequestID,
					"panic", r,
				)
				// Non-blocking send: buffer=1 ensures we never block here even
				// if the select in the parent already consumed the ctx.Done()
				// branch and moved on.
				select {
				case outcomeCh <- handlerOutcome{nil, fmt.Errorf("handler panic: %v", r)}:
				default:
				}
			}
		}()
		res, hErr := handler(handlerCtx, handlerData)
		// Non-blocking send protects against the (rare) case where a panic
		// already wrote to the buffered channel before we got here.
		select {
		case outcomeCh <- handlerOutcome{res, hErr}:
		default:
		}
	}()

	var result interface{}
	var err error
	select {
	case outcome := <-outcomeCh:
		result, err = outcome.result, outcome.err
	case <-handlerCtx.Done():
		if handlerCtx.Err() == context.DeadlineExceeded {
			err = fmt.Errorf("handler timeout after %s for action %q", handlerTimeout, msg.Action)
			h.logger.Warn("handler timeout",
				"action", msg.Action,
				"request_id", msg.RequestID,
				"timeout", handlerTimeout,
			)
		} else {
			err = handlerCtx.Err()
		}
	}

	// For run_osquery, use the OsqueryResponse format expected by the backend
	if msg.Action == "run_osquery" {
		osqResp := OsqueryResponse{
			Action:    "run_osquery",
			ScanType:  msg.ScanType,
			Data:      result,
			RequestID: msg.RequestID,
		}
		if err != nil {
			osqResp.Data = map[string]string{"error": err.Error()}
		}
		h.SendRaw(osqResp)
		return
	}

	// Map request actions to response actions where needed
	responseAction := msg.Action
	if mapped, ok := actionToResponseAction[msg.Action]; ok {
		responseAction = mapped
	}

	resp := Response{
		Action:    responseAction,
		RequestID: msg.RequestID,
		Success:   err == nil,
		Data:      result,
	}
	if err != nil {
		resp.Error = err.Error()
	}

	h.Send(resp)
}
