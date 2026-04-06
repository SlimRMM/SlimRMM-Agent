package handler

import (
	"context"
	"fmt"
	"time"

	"github.com/gorilla/websocket"
)

// drainSendChannel removes all pending messages from the send channel.
// This prevents goroutines from blocking when the connection is lost.
func (h *Handler) drainSendChannel() {
	for {
		select {
		case <-h.sendCh:
			// Discard message
		default:
			return
		}
	}
}

// readPump handles incoming messages.
func (h *Handler) readPump(ctx context.Context) error {
	h.mu.RLock()
	conn := h.conn
	h.mu.RUnlock()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Enforce a hard read deadline independent of pong handling.
		// This ensures that even if a reverse proxy (e.g. Caddy) keeps
		// the TCP connection alive after the backend is stopped, the
		// agent will detect the dead connection within pongWait and
		// trigger a reconnect instead of hanging indefinitely.
		conn.SetReadDeadline(time.Now().Add(pongWait))

		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseServiceRestart) {
				return nil
			}
			return fmt.Errorf("reading message: %w", err)
		}

		// Acquire a concurrency slot before spawning the handler goroutine.
		// When all MaxConcurrentHandlers slots are in use this blocks the read
		// loop, which in turn stops consuming WebSocket frames and provides
		// natural backpressure to the server. This prevents goroutine-bomb DoS
		// where a malicious/compromised server floods us with messages faster
		// than we can process them.
		select {
		case h.msgSem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}

		go func(msg []byte) {
			defer func() { <-h.msgSem }()
			h.handleMessage(ctx, msg)
		}(message)
	}
}

// writePump handles outgoing messages.
func (h *Handler) writePump(ctx context.Context) error {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	h.mu.RLock()
	conn := h.conn
	h.mu.RUnlock()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case message := <-h.sendCh:
			conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return fmt.Errorf("writing message: %w", err)
			}
		case <-ticker.C:
			conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return fmt.Errorf("writing ping: %w", err)
			}
		}
	}
}
