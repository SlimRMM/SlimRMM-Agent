// Package handler provides WebSocket message handling tests for the agent.
package handler

import (
	"encoding/json"
	"testing"
)

// TestMessageParsing tests that incoming messages are correctly parsed.
func TestMessageParsing(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected Message
	}{
		{
			name:  "osquery action",
			input: `{"action":"run_osquery","scan_type":"software","query":"SELECT * FROM programs"}`,
			expected: Message{
				Action:   "run_osquery",
				ScanType: "software",
				Query:    "SELECT * FROM programs",
			},
		},
		{
			name:  "ping action",
			input: `{"action":"ping"}`,
			expected: Message{
				Action: "ping",
			},
		},
		{
			name:  "action with request_id",
			input: `{"action":"get_system_stats","request_id":"req-123"}`,
			expected: Message{
				Action:    "get_system_stats",
				RequestID: "req-123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var msg Message
			err := json.Unmarshal([]byte(tt.input), &msg)
			if err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			if msg.Action != tt.expected.Action {
				t.Errorf("action mismatch: got %s, want %s", msg.Action, tt.expected.Action)
			}
			if msg.ScanType != tt.expected.ScanType {
				t.Errorf("scan_type mismatch: got %s, want %s", msg.ScanType, tt.expected.ScanType)
			}
			if msg.RequestID != tt.expected.RequestID {
				t.Errorf("request_id mismatch: got %s, want %s", msg.RequestID, tt.expected.RequestID)
			}
		})
	}
}

// TestResponseStructure tests that responses are correctly structured.
func TestResponseStructure(t *testing.T) {
	tests := []struct {
		name     string
		response Response
		validate func(t *testing.T, data []byte)
	}{
		{
			name: "success response",
			response: Response{
				Action:    "ping",
				RequestID: "req-123",
				Success:   true,
				Data:      map[string]string{"pong": "ok"},
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("failed to unmarshal: %v", err)
				}
				if result["success"] != true {
					t.Error("success should be true")
				}
				if result["action"] != "ping" {
					t.Error("action should be ping")
				}
			},
		},
		{
			name: "error response",
			response: Response{
				Action:    "unknown",
				RequestID: "req-456",
				Success:   false,
				Error:     "unknown action",
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("failed to unmarshal: %v", err)
				}
				if result["success"] != false {
					t.Error("success should be false")
				}
				if result["error"] == nil || result["error"] == "" {
					t.Error("error should be set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.response)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			tt.validate(t, data)
		})
	}
}

// TestOsqueryResponseStructure tests osquery response format.
func TestOsqueryResponseStructure(t *testing.T) {
	osqResp := OsqueryResponse{
		Action:    "run_osquery",
		ScanType:  "software",
		RequestID: "req-789",
		Data: []map[string]string{
			{"name": "python", "version": "3.14.0"},
			{"name": "nodejs", "version": "22.0.0"},
		},
	}

	data, err := json.Marshal(osqResp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result["action"] != "run_osquery" {
		t.Error("action should be run_osquery")
	}
	if result["scan_type"] != "software" {
		t.Error("scan_type should be software")
	}
	if result["data"] == nil {
		t.Error("data should not be nil")
	}
}

// TestHeartbeatMessageStructure tests heartbeat message format.
func TestHeartbeatMessageStructure(t *testing.T) {
	heartbeat := HeartbeatMessage{
		Action:       "heartbeat",
		AgentVersion: "1.0.0",
		Stats: HeartbeatStats{
			CPUPercent:    45.5,
			MemoryPercent: 62.3,
			MemoryUsed:    8000000000,
			MemoryTotal:   16000000000,
			Disk: []HeartbeatDisk{
				{
					Device:      "/dev/sda1",
					Mountpoint:  "/",
					Total:       500000000000,
					Used:        250000000000,
					Free:        250000000000,
					UsedPercent: 50.0,
				},
			},
			NetworkIO: &HeartbeatNetworkIO{
				BytesSent:   1000000,
				BytesRecv:   2000000,
				PacketsSent: 10000,
				PacketsRecv: 20000,
			},
			UptimeSeconds: 86400,
			ProcessCount:  150,
		},
		ExternalIP: "1.2.3.4",
	}

	data, err := json.Marshal(heartbeat)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result["action"] != "heartbeat" {
		t.Error("action should be heartbeat")
	}
	if result["agent_version"] != "1.0.0" {
		t.Error("agent_version should be 1.0.0")
	}

	stats, ok := result["stats"].(map[string]interface{})
	if !ok {
		t.Fatal("stats should be a map")
	}
	if stats["cpu_percent"] != 45.5 {
		t.Errorf("cpu_percent should be 45.5, got %v", stats["cpu_percent"])
	}
}

// TestSupportedActions tests all supported action types.
func TestSupportedActions(t *testing.T) {
	supportedActions := []string{
		// Core actions
		"ping",
		"heartbeat",
		"get_system_stats",
		// osquery
		"run_osquery",
		"osquery",
		// Terminal
		"terminal",
		"terminal_input",
		"terminal_resize",
		"start_terminal",
		"stop_terminal",
		// File operations
		"list_dir",
		"create_folder",
		"delete_entry",
		"rename_entry",
		"download_file",
		// Upload operations
		"start_upload",
		"upload_chunk",
		"finish_upload",
		// Docker operations
		"docker_info",
		"docker_containers",
		"docker_images",
		"docker_volumes",
		"docker_networks",
		// System actions
		"restart",
		"shutdown",
		"update_agent",
	}

	for _, action := range supportedActions {
		t.Run(action, func(t *testing.T) {
			msg := Message{Action: action}
			data, err := json.Marshal(msg)
			if err != nil {
				t.Fatalf("failed to marshal action %s: %v", action, err)
			}

			var parsed Message
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("failed to unmarshal action %s: %v", action, err)
			}
			if parsed.Action != action {
				t.Errorf("action mismatch: got %s, want %s", parsed.Action, action)
			}
		})
	}
}

// TestScanTypes tests all supported scan types.
func TestScanTypes(t *testing.T) {
	scanTypes := []string{
		"software",
		"services",
		"user",
		"cpu",
		"memory",
		"network",
		"os",
	}

	for _, scanType := range scanTypes {
		t.Run(scanType, func(t *testing.T) {
			msg := Message{
				Action:   "run_osquery",
				ScanType: scanType,
				Query:    "SELECT * FROM test",
			}

			data, err := json.Marshal(msg)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			var parsed Message
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if parsed.ScanType != scanType {
				t.Errorf("scan_type mismatch: got %s, want %s", parsed.ScanType, scanType)
			}
		})
	}
}

// TestDockerCommandStructure tests Docker command message structure.
func TestDockerCommandStructure(t *testing.T) {
	dockerActions := []struct {
		action string
		data   map[string]interface{}
	}{
		{"docker_info", nil},
		{"docker_containers", map[string]interface{}{"all": true}},
		{"docker_images", nil},
		{"docker_volumes", nil},
		{"docker_networks", nil},
		{"docker_container_start", map[string]interface{}{"container_id": "abc123"}},
		{"docker_container_stop", map[string]interface{}{"container_id": "abc123"}},
		{"docker_container_restart", map[string]interface{}{"container_id": "abc123"}},
		{"docker_container_logs", map[string]interface{}{"container_id": "abc123", "tail": 100}},
	}

	for _, tc := range dockerActions {
		t.Run(tc.action, func(t *testing.T) {
			msg := map[string]interface{}{
				"action": tc.action,
			}
			if tc.data != nil {
				for k, v := range tc.data {
					msg[k] = v
				}
			}

			data, err := json.Marshal(msg)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			var parsed map[string]interface{}
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if parsed["action"] != tc.action {
				t.Errorf("action mismatch: got %v, want %s", parsed["action"], tc.action)
			}
		})
	}
}

// TestScriptExecutionStructure tests script execution message structure.
func TestScriptExecutionStructure(t *testing.T) {
	scriptTypes := []string{"bash", "powershell", "python"}

	for _, scriptType := range scriptTypes {
		t.Run(scriptType, func(t *testing.T) {
			msg := map[string]interface{}{
				"action":      "run_script",
				"script_type": scriptType,
				"script":      "echo 'hello world'",
				"timeout":     300,
				"request_id":  "script-123",
			}

			data, err := json.Marshal(msg)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			var parsed map[string]interface{}
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if parsed["action"] != "run_script" {
				t.Error("action should be run_script")
			}
			if parsed["script_type"] != scriptType {
				t.Errorf("script_type mismatch: got %v, want %s", parsed["script_type"], scriptType)
			}
		})
	}
}
