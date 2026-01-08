//go:build cgo

package remotedesktop

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/pion/webrtc/v4"
)

// Default STUN servers if none provided
var defaultICEServers = []ICEServer{
	{URLs: []string{"stun:stun.l.google.com:19302"}},
	{URLs: []string{"stun:stun1.l.google.com:19302"}},
}

// configuredICEServers holds the ICE servers set via SetICEServers
var (
	configuredICEServers []ICEServer
	iceServersMu         sync.RWMutex
)

// SetICEServers configures the ICE servers (STUN/TURN) to use for WebRTC.
func SetICEServers(servers []ICEServer) {
	iceServersMu.Lock()
	defer iceServersMu.Unlock()
	configuredICEServers = servers
}

// getWebRTCConfig returns the WebRTC configuration with STUN/TURN servers.
func getWebRTCConfig() webrtc.Configuration {
	iceServersMu.RLock()
	servers := configuredICEServers
	iceServersMu.RUnlock()

	if len(servers) == 0 {
		servers = defaultICEServers
		slog.Info("using default ICE servers (no custom servers configured)")
	}

	var iceServers []webrtc.ICEServer
	for _, s := range servers {
		ice := webrtc.ICEServer{URLs: s.URLs}
		hasCredentials := false
		if s.Username != "" {
			ice.Username = s.Username
			hasCredentials = true
		}
		if s.Credential != "" {
			ice.Credential = s.Credential
		}
		iceServers = append(iceServers, ice)

		// Log each ICE server (mask credentials)
		for _, url := range s.URLs {
			if hasCredentials {
				slog.Info("ICE server configured", "url", url, "username", s.Username, "has_credential", s.Credential != "")
			} else {
				slog.Info("ICE server configured", "url", url, "type", "STUN (no credentials)")
			}
		}
	}

	return webrtc.Configuration{
		ICEServers: iceServers,
	}
}

// Session represents an active remote desktop session.
type Session struct {
	sessionID    string
	sendCallback SendCallback
	logger       *slog.Logger

	pc          *webrtc.PeerConnection
	videoTrack  *VideoTrack
	dataChannel *webrtc.DataChannel

	capture   *ScreenCapture
	input     *InputController
	clipboard *ClipboardManager

	selectedMonitor int
	quality         string
	running         bool
	connectionInfo  *ConnectionInfo
	mu              sync.RWMutex
}

// NewSession creates a new remote desktop session.
func NewSession(sessionID string, sendCallback SendCallback, logger *slog.Logger) (*Session, error) {
	if logger == nil {
		logger = slog.Default()
	}

	capture, err := NewScreenCapture()
	if err != nil {
		return nil, fmt.Errorf("creating screen capture: %w", err)
	}

	monitors := capture.GetMonitors()
	input := NewInputController(monitors, logger)

	// Configure Windows helper if available
	if windowsHelperConfig != nil {
		windowsHelperConfig(capture, input)
	}

	var clipboardMgr *ClipboardManager
	clipboardMgr, err = NewClipboardManager()
	if err != nil {
		logger.Warn("clipboard not available", "error", err)
		// Continue without clipboard support
	}

	return &Session{
		sessionID:       sessionID,
		sendCallback:    sendCallback,
		logger:          logger,
		capture:         capture,
		input:           input,
		clipboard:       clipboardMgr,
		selectedMonitor: 1, // Default to primary monitor
		quality:         "balanced",
	}, nil
}

// Start initializes the WebRTC connection and returns the offer.
func (s *Session) Start() (*StartResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error

	// Create peer connection
	s.pc, err = webrtc.NewPeerConnection(getWebRTCConfig())
	if err != nil {
		return nil, fmt.Errorf("creating peer connection: %w", err)
	}

	// Handle ICE candidates
	s.pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			s.logger.Info("ICE gathering complete")
			return
		}

		s.logger.Info("ICE candidate generated", "type", c.Typ.String(), "address", c.Address, "port", c.Port, "protocol", c.Protocol.String())

		candidate := c.ToJSON()
		msg, _ := json.Marshal(map[string]interface{}{
			"action":     "ice_candidate",
			"session_id": s.sessionID,
			"candidate": map[string]interface{}{
				"candidate":     candidate.Candidate,
				"sdpMid":        candidate.SDPMid,
				"sdpMLineIndex": candidate.SDPMLineIndex,
			},
		})

		if err := s.sendCallback(msg); err != nil {
			s.logger.Error("sending ICE candidate", "error", err)
		}
	})

	// Handle connection state changes
	s.pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		s.logger.Info("WebRTC connection state changed", "state", state.String())

		switch state {
		case webrtc.PeerConnectionStateFailed:
			s.logger.Error("WebRTC connection failed")
			go s.Stop()
		case webrtc.PeerConnectionStateDisconnected:
			s.logger.Warn("WebRTC connection disconnected")
		case webrtc.PeerConnectionStateConnected:
			s.logger.Info("WebRTC connection established")
			// Start video capture NOW that connection is ready
			s.mu.RLock()
			vt := s.videoTrack
			s.mu.RUnlock()
			if vt != nil {
				s.logger.Info("Starting video track now that connection is established")
				vt.Start()
			}
			// Detect and report connection type
			go s.detectAndReportConnectionType()
		}
	})

	// Handle ICE connection state changes
	s.pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		s.logger.Info("ICE connection state changed", "state", state.String())
	})

	// Create video track
	s.videoTrack, err = NewVideoTrack(s.capture, s.selectedMonitor, s.quality, s.logger)
	if err != nil {
		s.pc.Close()
		return nil, fmt.Errorf("creating video track: %w", err)
	}

	// Add track to peer connection
	rtpSender, err := s.pc.AddTrack(s.videoTrack.Track())
	if err != nil {
		s.pc.Close()
		return nil, fmt.Errorf("adding track: %w", err)
	}

	// Read incoming RTCP packets (required for WebRTC to work properly)
	go func() {
		rtcpBuf := make([]byte, 1500)
		for {
			if _, _, err := rtpSender.Read(rtcpBuf); err != nil {
				return
			}
		}
	}()

	// Note: Video track is started in OnConnectionStateChange when connection is established
	// Starting it before the connection is ready causes WriteSample to fail silently

	// Create data channel for input events
	s.dataChannel, err = s.pc.CreateDataChannel("input", &webrtc.DataChannelInit{
		Ordered: func() *bool { b := true; return &b }(),
	})
	if err != nil {
		s.pc.Close()
		return nil, fmt.Errorf("creating data channel: %w", err)
	}

	s.dataChannel.OnOpen(func() {
		s.logger.Info("data channel opened")
		// Set up frame sending via data channel (for JPEG fallback when VP8 not available)
		if s.videoTrack != nil {
			s.videoTrack.SetFrameSendFunc(func(data []byte) error {
				if s.dataChannel != nil && s.dataChannel.ReadyState() == webrtc.DataChannelStateOpen {
					return s.dataChannel.Send(data)
				}
				return nil
			})
			s.logger.Info("configured video track to send frames via data channel")
		}
	})

	s.dataChannel.OnMessage(func(msg webrtc.DataChannelMessage) {
		s.handleDataChannelMessage(msg.Data)
	})

	s.dataChannel.OnClose(func() {
		s.logger.Info("data channel closed")
	})

	// Create offer
	offer, err := s.pc.CreateOffer(nil)
	if err != nil {
		s.pc.Close()
		return nil, fmt.Errorf("creating offer: %w", err)
	}

	// Set local description
	if err := s.pc.SetLocalDescription(offer); err != nil {
		s.pc.Close()
		return nil, fmt.Errorf("setting local description: %w", err)
	}

	// Wait for ICE gathering to complete
	gatherComplete := webrtc.GatheringCompletePromise(s.pc)
	<-gatherComplete

	s.running = true
	s.logger.Info("remote desktop session started", "session_id", s.sessionID)

	return &StartResult{
		Success: true,
		Offer: SessionDescription{
			Type: s.pc.LocalDescription().Type.String(),
			SDP:  s.pc.LocalDescription().SDP,
		},
		Monitors: s.capture.GetMonitors(),
	}, nil
}

// HandleAnswer processes the WebRTC answer from the frontend.
func (s *Session) HandleAnswer(answer SessionDescription) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pc == nil {
		return fmt.Errorf("peer connection not initialized")
	}

	sdpType := webrtc.SDPTypeAnswer
	if answer.Type == "offer" {
		sdpType = webrtc.SDPTypeOffer
	}

	return s.pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: sdpType,
		SDP:  answer.SDP,
	})
}

// HandleICECandidate processes an ICE candidate from the frontend.
func (s *Session) HandleICECandidate(candidate ICECandidate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pc == nil {
		return fmt.Errorf("peer connection not initialized")
	}

	// Empty candidate signals end of candidates
	if candidate.Candidate == "" {
		s.logger.Info("received end-of-candidates signal from frontend")
		return nil
	}

	candidatePreview := candidate.Candidate
	if len(candidatePreview) > 80 {
		candidatePreview = candidatePreview[:80] + "..."
	}
	s.logger.Info("received ICE candidate from frontend", "candidate", candidatePreview)

	init := webrtc.ICECandidateInit{
		Candidate: candidate.Candidate,
	}

	if candidate.SDPMid != nil {
		init.SDPMid = candidate.SDPMid
	}

	if candidate.SDPMLineIndex != nil {
		init.SDPMLineIndex = candidate.SDPMLineIndex
	}

	return s.pc.AddICECandidate(init)
}

// handleDataChannelMessage processes messages from the data channel.
func (s *Session) handleDataChannelMessage(data []byte) {
	var event InputEvent
	if err := json.Unmarshal(data, &event); err != nil {
		s.logger.Error("parsing data channel message", "error", err)
		return
	}

	s.handleInput(event)
}

// handleInput processes input events.
func (s *Session) handleInput(event InputEvent) {
	s.mu.RLock()
	monitorID := s.selectedMonitor
	s.mu.RUnlock()

	switch event.Type {
	case "mouse":
		s.input.HandleMouseEvent(event, monitorID)

	case "keyboard":
		s.input.HandleKeyboardEvent(event)

	case "clipboard":
		s.handleClipboardEvent(event)

	case "quality":
		s.SetQuality(event.Quality)

	case "monitor":
		s.SetMonitor(event.MonitorID)
	}
}

// handleClipboardEvent processes clipboard events.
func (s *Session) handleClipboardEvent(event InputEvent) {
	if s.clipboard == nil {
		return
	}

	switch event.Action {
	case "set":
		if err := s.clipboard.SetText(event.Text); err != nil {
			s.logger.Error("setting clipboard", "error", err)
		}

	case "get":
		text, err := s.clipboard.GetText()
		if err != nil {
			s.logger.Error("getting clipboard", "error", err)
			return
		}

		msg, _ := json.Marshal(map[string]interface{}{
			"action":     "clipboard_content",
			"session_id": s.sessionID,
			"text":       text,
		})

		if err := s.sendCallback(msg); err != nil {
			s.logger.Error("sending clipboard content", "error", err)
		}
	}
}

// SetQuality changes the video quality preset.
func (s *Session) SetQuality(quality string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := QualityPresets[quality]; !ok {
		s.logger.Warn("invalid quality preset", "quality", quality)
		return
	}

	s.quality = quality
	if s.videoTrack != nil {
		s.videoTrack.SetQuality(quality)
	}

	s.logger.Info("quality changed", "quality", quality)
}

// SetMonitor switches to a different monitor.
func (s *Session) SetMonitor(monitorID int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate monitor ID
	monitors := s.capture.GetMonitors()
	valid := false
	for _, m := range monitors {
		if m.ID == monitorID {
			valid = true
			break
		}
	}

	if !valid {
		s.logger.Warn("invalid monitor ID", "monitor_id", monitorID)
		return
	}

	s.selectedMonitor = monitorID
	if s.videoTrack != nil {
		s.videoTrack.SetMonitor(monitorID)
	}

	s.logger.Info("monitor changed", "monitor_id", monitorID)
}

// GetMonitors returns the list of available monitors.
func (s *Session) GetMonitors() []Monitor {
	return s.capture.GetMonitors()
}

// Stop terminates the remote desktop session.
func (s *Session) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.running = false

	if s.videoTrack != nil {
		s.videoTrack.Stop()
		s.videoTrack = nil
	}

	if s.dataChannel != nil {
		s.dataChannel.Close()
		s.dataChannel = nil
	}

	if s.pc != nil {
		s.pc.Close()
		s.pc = nil
	}

	if s.capture != nil {
		s.capture.Close()
	}

	if s.clipboard != nil {
		s.clipboard.Close()
	}

	s.logger.Info("remote desktop session stopped", "session_id", s.sessionID)
}

// IsRunning returns whether the session is active.
func (s *Session) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// GetConnectionInfo returns the current connection information.
func (s *Session) GetConnectionInfo() *ConnectionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.connectionInfo
}

// detectAndReportConnectionType detects the connection type from ICE candidates
// and sends it to the frontend.
func (s *Session) detectAndReportConnectionType() {
	s.mu.RLock()
	pc := s.pc
	s.mu.RUnlock()

	if pc == nil {
		return
	}

	// Get ICE connection stats to determine connection type
	stats := pc.GetStats()

	var connInfo *ConnectionInfo

	for _, stat := range stats {
		// Look for the selected candidate pair
		if candidatePair, ok := stat.(webrtc.ICECandidatePairStats); ok {
			if candidatePair.State == webrtc.StatsICECandidatePairStateSucceeded {
				// Find the local candidate to get its type
				for _, innerStat := range stats {
					if localCandidate, ok := innerStat.(webrtc.ICECandidateStats); ok {
						if localCandidate.ID == candidatePair.LocalCandidateID {
							connType := mapCandidateType(localCandidate.CandidateType)
							connInfo = &ConnectionInfo{
								Type:          connType,
								LocalAddress:  fmt.Sprintf("%s:%d", localCandidate.IP, localCandidate.Port),
								Protocol:      localCandidate.Protocol,
								IsP2P:         connType != ConnectionTypeRelay,
								RelayProtocol: localCandidate.RelayProtocol,
							}

							// Find remote candidate for address
							for _, remoteStat := range stats {
								if remoteCandidate, ok := remoteStat.(webrtc.ICECandidateStats); ok {
									if remoteCandidate.ID == candidatePair.RemoteCandidateID {
										connInfo.RemoteAddress = fmt.Sprintf("%s:%d", remoteCandidate.IP, remoteCandidate.Port)
										break
									}
								}
							}
							break
						}
					}
				}
				break
			}
		}
	}

	if connInfo == nil {
		connInfo = &ConnectionInfo{
			Type:  ConnectionTypeUnknown,
			IsP2P: false,
		}
	}

	// Store connection info
	s.mu.Lock()
	s.connectionInfo = connInfo
	s.mu.Unlock()

	// Log connection type
	if connInfo.IsP2P {
		s.logger.Info("WebRTC connection type: P2P",
			"type", connInfo.Type,
			"local", connInfo.LocalAddress,
			"remote", connInfo.RemoteAddress,
			"protocol", connInfo.Protocol,
		)
	} else {
		s.logger.Info("WebRTC connection type: Relay (TURN)",
			"type", connInfo.Type,
			"local", connInfo.LocalAddress,
			"remote", connInfo.RemoteAddress,
			"relay_protocol", connInfo.RelayProtocol,
		)
	}

	// Send connection info to frontend
	msg, _ := json.Marshal(map[string]interface{}{
		"action":          "connection_info",
		"session_id":      s.sessionID,
		"connection_type": connInfo.Type,
		"is_p2p":          connInfo.IsP2P,
		"local_address":   connInfo.LocalAddress,
		"remote_address":  connInfo.RemoteAddress,
		"protocol":        connInfo.Protocol,
		"relay_protocol":  connInfo.RelayProtocol,
	})

	if err := s.sendCallback(msg); err != nil {
		s.logger.Error("sending connection info", "error", err)
	}
}

// mapCandidateType maps WebRTC candidate type to our ConnectionType.
func mapCandidateType(candidateType webrtc.ICECandidateType) ConnectionType {
	switch candidateType {
	case webrtc.ICECandidateTypeHost:
		return ConnectionTypeHost
	case webrtc.ICECandidateTypeSrflx:
		return ConnectionTypeSRFLX
	case webrtc.ICECandidateTypePrflx:
		return ConnectionTypePRFLX
	case webrtc.ICECandidateTypeRelay:
		return ConnectionTypeRelay
	default:
		return ConnectionTypeUnknown
	}
}
