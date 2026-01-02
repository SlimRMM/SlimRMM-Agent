// Package handler provides WebSocket message handling for the agent.
// It processes incoming messages and dispatches them to action handlers.
package handler

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kiefernetworks/slimrmm-agent/internal/actions"
	"github.com/kiefernetworks/slimrmm-agent/internal/config"
	"github.com/kiefernetworks/slimrmm-agent/internal/monitor"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	heartbeatPeriod = 30 * time.Second
	maxMessageSize = 10 * 1024 * 1024 // 10 MB
)

// Message represents a WebSocket message.
type Message struct {
	Action    string          `json:"action"`
	RequestID string          `json:"request_id,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
}

// Response represents a WebSocket response.
type Response struct {
	Action    string      `json:"action"`
	RequestID string      `json:"request_id,omitempty"`
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
}

// ActionHandler is a function that handles a specific action.
type ActionHandler func(ctx context.Context, data json.RawMessage) (interface{}, error)

// Handler manages WebSocket communication.
type Handler struct {
	cfg      *config.Config
	paths    config.Paths
	conn     *websocket.Conn
	tlsConfig *tls.Config
	monitor  *monitor.Monitor
	logger   *slog.Logger

	handlers        map[string]ActionHandler
	terminalManager *actions.TerminalManager
	uploadManager   *actions.UploadManager
	sendCh          chan []byte
	done            chan struct{}
	mu              sync.RWMutex
}

// New creates a new Handler.
func New(cfg *config.Config, paths config.Paths, tlsConfig *tls.Config, logger *slog.Logger) *Handler {
	h := &Handler{
		cfg:             cfg,
		paths:           paths,
		tlsConfig:       tlsConfig,
		monitor:         monitor.New(),
		logger:          logger,
		handlers:        make(map[string]ActionHandler),
		terminalManager: actions.NewTerminalManager(),
		uploadManager:   actions.NewUploadManager(),
		sendCh:          make(chan []byte, 256),
		done:            make(chan struct{}),
	}

	h.registerHandlers()
	return h
}

// Note: registerHandlers is defined in actions.go

// Connect establishes a WebSocket connection to the server.
func (h *Handler) Connect(ctx context.Context) error {
	serverURL := h.cfg.GetServer()
	u, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("parsing server URL: %w", err)
	}

	// Convert HTTP(S) to WS(S)
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}
	u.Path = "/api/v1/agents/ws"

	dialer := websocket.Dialer{
		TLSClientConfig:  h.tlsConfig,
		HandshakeTimeout: 10 * time.Second,
	}

	headers := http.Header{}
	headers.Set("X-Agent-UUID", h.cfg.GetUUID())

	h.logger.Info("connecting to server", "url", u.String())

	conn, resp, err := dialer.DialContext(ctx, u.String(), headers)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("connecting to server (status %d): %w", resp.StatusCode, err)
		}
		return fmt.Errorf("connecting to server: %w", err)
	}

	h.mu.Lock()
	h.conn = conn
	h.mu.Unlock()

	h.logger.Info("connected to server")
	return nil
}

// Run starts the message handling loops.
func (h *Handler) Run(ctx context.Context) error {
	h.mu.RLock()
	conn := h.conn
	h.mu.RUnlock()

	if conn == nil {
		return fmt.Errorf("not connected")
	}

	conn.SetReadLimit(maxMessageSize)
	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	// Start goroutines
	errCh := make(chan error, 3)

	go func() {
		errCh <- h.readPump(ctx)
	}()

	go func() {
		errCh <- h.writePump(ctx)
	}()

	go func() {
		errCh <- h.heartbeatPump(ctx)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
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

		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return nil
			}
			return fmt.Errorf("reading message: %w", err)
		}

		go h.handleMessage(ctx, message)
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

// heartbeatPump sends periodic heartbeats.
func (h *Handler) heartbeatPump(ctx context.Context) error {
	ticker := time.NewTicker(heartbeatPeriod)
	defer ticker.Stop()

	// Send initial heartbeat
	h.sendHeartbeat(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			h.sendHeartbeat(ctx)
		}
	}
}

// sendHeartbeat sends a heartbeat message.
func (h *Handler) sendHeartbeat(ctx context.Context) {
	stats, err := h.monitor.GetStats(ctx)
	if err != nil {
		h.logger.Error("getting stats for heartbeat", "error", err)
		return
	}

	h.Send(Response{
		Action:  "heartbeat",
		Success: true,
		Data:    stats,
	})
}

// handleMessage processes an incoming message.
func (h *Handler) handleMessage(ctx context.Context, data []byte) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		h.logger.Error("parsing message", "error", err)
		return
	}

	h.logger.Debug("received message", "action", msg.Action, "request_id", msg.RequestID)

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

	result, err := handler(ctx, msg.Data)
	resp := Response{
		Action:    msg.Action,
		RequestID: msg.RequestID,
		Success:   err == nil,
		Data:      result,
	}
	if err != nil {
		resp.Error = err.Error()
	}

	h.Send(resp)
}

// Send sends a response to the server.
func (h *Handler) Send(resp Response) {
	data, err := json.Marshal(resp)
	if err != nil {
		h.logger.Error("marshaling response", "error", err)
		return
	}

	select {
	case h.sendCh <- data:
	default:
		h.logger.Warn("send channel full, dropping message")
	}
}

// Close closes the WebSocket connection.
func (h *Handler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.conn != nil {
		h.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		return h.conn.Close()
	}
	return nil
}

// Basic handler implementations

func (h *Handler) handlePing(ctx context.Context, data json.RawMessage) (interface{}, error) {
	return map[string]string{"pong": "ok"}, nil
}

func (h *Handler) handleGetSystemStats(ctx context.Context, data json.RawMessage) (interface{}, error) {
	return h.monitor.GetStats(ctx)
}

func (h *Handler) handleHeartbeat(ctx context.Context, data json.RawMessage) (interface{}, error) {
	return h.monitor.GetStats(ctx)
}
