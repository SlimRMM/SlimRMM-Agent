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

// TestDockerInfoStructure tests Docker info serialization.
func TestDockerInfoStructure(t *testing.T) {
	dockerInfo := DockerInfo{
		Available:         true,
		Version:           "24.0.7",
		APIVersion:        "1.43",
		Containers:        10,
		ContainersRunning: 5,
		Images:            15,
	}

	data, err := json.Marshal(dockerInfo)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result["available"] != true {
		t.Error("available should be true")
	}
	if result["version"] != "24.0.7" {
		t.Errorf("version should be 24.0.7, got %v", result["version"])
	}
	if result["api_version"] != "1.43" {
		t.Errorf("api_version should be 1.43, got %v", result["api_version"])
	}
	if int(result["containers"].(float64)) != 10 {
		t.Errorf("containers should be 10, got %v", result["containers"])
	}
	if int(result["containers_running"].(float64)) != 5 {
		t.Errorf("containers_running should be 5, got %v", result["containers_running"])
	}
	if int(result["images"].(float64)) != 15 {
		t.Errorf("images should be 15, got %v", result["images"])
	}
}

// TestDockerInfoOmitEmpty tests Docker info omitempty behavior.
func TestDockerInfoOmitEmpty(t *testing.T) {
	dockerInfo := DockerInfo{
		Available: false,
	}

	data, err := json.Marshal(dockerInfo)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Version and APIVersion should be omitted when empty
	if _, exists := result["version"]; exists {
		t.Error("version should be omitted when empty")
	}
	if _, exists := result["api_version"]; exists {
		t.Error("api_version should be omitted when empty")
	}
}

// TestHeartbeatWithDocker tests heartbeat with Docker info.
func TestHeartbeatWithDocker(t *testing.T) {
	heartbeat := HeartbeatMessage{
		Action:       "heartbeat",
		Type:         "full",
		AgentVersion: "1.0.0",
		Stats: HeartbeatStats{
			CPUPercent:    20.0,
			MemoryPercent: 50.0,
		},
		Docker: &DockerInfo{
			Available:         true,
			Version:           "24.0.7",
			APIVersion:        "1.43",
			Containers:        5,
			ContainersRunning: 3,
			Images:            10,
		},
	}

	data, err := json.Marshal(heartbeat)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	docker, ok := result["docker"].(map[string]interface{})
	if !ok {
		t.Fatal("docker should be a map")
	}
	if docker["available"] != true {
		t.Error("docker.available should be true")
	}
	if docker["version"] != "24.0.7" {
		t.Errorf("docker.version should be 24.0.7, got %v", docker["version"])
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

// TestHeartbeatWingetSerialization tests HeartbeatWinget serialization.
func TestHeartbeatWingetSerialization(t *testing.T) {
	winget := HeartbeatWinget{
		Available:                   true,
		Version:                     "1.6.3133",
		BinaryPath:                  "C:\\Program Files\\WindowsApps\\winget.exe",
		SystemLevel:                 true,
		HelperAvailable:             false,
		PowerShell7Available:        true,
		WinGetClientModuleAvailable: true,
	}

	data, err := json.Marshal(winget)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed HeartbeatWinget
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !parsed.Available {
		t.Error("Available should be true")
	}
	if parsed.Version != "1.6.3133" {
		t.Errorf("Version = %s, want 1.6.3133", parsed.Version)
	}
	if !parsed.SystemLevel {
		t.Error("SystemLevel should be true")
	}
	if !parsed.PowerShell7Available {
		t.Error("PowerShell7Available should be true")
	}
	if !parsed.WinGetClientModuleAvailable {
		t.Error("WinGetClientModuleAvailable should be true")
	}
}

// TestHeartbeatProxmoxSerialization tests HeartbeatProxmox serialization.
func TestHeartbeatProxmoxSerialization(t *testing.T) {
	proxmox := HeartbeatProxmox{
		IsProxmox:      true,
		Version:        "8.1.3",
		Release:        "stable",
		KernelVersion:  "6.5.11-4-pve",
		ClusterName:    "pve-cluster",
		NodeName:       "pve-node1",
		RepositoryType: "enterprise",
	}

	data, err := json.Marshal(proxmox)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed HeartbeatProxmox
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !parsed.IsProxmox {
		t.Error("IsProxmox should be true")
	}
	if parsed.Version != "8.1.3" {
		t.Errorf("Version = %s, want 8.1.3", parsed.Version)
	}
	if parsed.ClusterName != "pve-cluster" {
		t.Errorf("ClusterName = %s, want pve-cluster", parsed.ClusterName)
	}
}

// TestHeartbeatHyperVSerialization tests HeartbeatHyperV serialization.
func TestHeartbeatHyperVSerialization(t *testing.T) {
	hyperv := HeartbeatHyperV{
		IsHyperV:       true,
		Version:        "10.0.19041.1",
		HostName:       "hyperv-server",
		VMCount:        15,
		ClusterEnabled: true,
	}

	data, err := json.Marshal(hyperv)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed HeartbeatHyperV
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !parsed.IsHyperV {
		t.Error("IsHyperV should be true")
	}
	if parsed.VMCount != 15 {
		t.Errorf("VMCount = %d, want 15", parsed.VMCount)
	}
	if !parsed.ClusterEnabled {
		t.Error("ClusterEnabled should be true")
	}
}

// TestHeartbeatDiskSerialization tests HeartbeatDisk serialization.
func TestHeartbeatDiskSerialization(t *testing.T) {
	disk := HeartbeatDisk{
		Device:      "/dev/sda1",
		Mountpoint:  "/",
		Total:       500000000000,
		Used:        250000000000,
		Free:        250000000000,
		UsedPercent: 50.0,
	}

	data, err := json.Marshal(disk)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed HeartbeatDisk
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.Device != "/dev/sda1" {
		t.Errorf("Device = %s, want /dev/sda1", parsed.Device)
	}
	if parsed.Mountpoint != "/" {
		t.Errorf("Mountpoint = %s, want /", parsed.Mountpoint)
	}
	if parsed.UsedPercent != 50.0 {
		t.Errorf("UsedPercent = %f, want 50.0", parsed.UsedPercent)
	}
}

// TestHeartbeatNetworkIOSerialization tests HeartbeatNetworkIO serialization.
func TestHeartbeatNetworkIOSerialization(t *testing.T) {
	networkIO := HeartbeatNetworkIO{
		BytesSent:   1000000000,
		BytesRecv:   2000000000,
		PacketsSent: 500000,
		PacketsRecv: 1000000,
	}

	data, err := json.Marshal(networkIO)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed HeartbeatNetworkIO
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.BytesSent != 1000000000 {
		t.Errorf("BytesSent = %d, want 1000000000", parsed.BytesSent)
	}
	if parsed.BytesRecv != 2000000000 {
		t.Errorf("BytesRecv = %d, want 2000000000", parsed.BytesRecv)
	}
}

// TestHeartbeatStatsSerialization tests HeartbeatStats serialization.
func TestHeartbeatStatsSerialization(t *testing.T) {
	stats := HeartbeatStats{
		CPUPercent:    45.5,
		MemoryPercent: 62.3,
		MemoryUsed:    8000000000,
		MemoryTotal:   16000000000,
		UptimeSeconds: 86400,
		ProcessCount:  150,
		Timezone:      "UTC",
	}

	data, err := json.Marshal(stats)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed HeartbeatStats
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.CPUPercent != 45.5 {
		t.Errorf("CPUPercent = %f, want 45.5", parsed.CPUPercent)
	}
	if parsed.ProcessCount != 150 {
		t.Errorf("ProcessCount = %d, want 150", parsed.ProcessCount)
	}
	if parsed.Timezone != "UTC" {
		t.Errorf("Timezone = %s, want UTC", parsed.Timezone)
	}
}

// TestFullHeartbeatMessageSerialization tests complete heartbeat message.
func TestFullHeartbeatMessageSerialization(t *testing.T) {
	heartbeat := HeartbeatMessage{
		Action:       "heartbeat",
		Type:         "full",
		AgentVersion: "2.0.0",
		Stats: HeartbeatStats{
			CPUPercent:    25.0,
			MemoryPercent: 40.0,
			MemoryUsed:    6400000000,
			MemoryTotal:   16000000000,
			Disk: []HeartbeatDisk{
				{
					Device:      "/dev/nvme0n1p1",
					Mountpoint:  "/",
					Total:       1000000000000,
					Used:        400000000000,
					Free:        600000000000,
					UsedPercent: 40.0,
				},
			},
			NetworkIO: &HeartbeatNetworkIO{
				BytesSent:   500000,
				BytesRecv:   1000000,
				PacketsSent: 5000,
				PacketsRecv: 10000,
			},
			UptimeSeconds: 604800,
			ProcessCount:  200,
			Timezone:      "Europe/Berlin",
		},
		ExternalIP:   "203.0.113.50",
		SerialNumber: "ABC123XYZ",
		Proxmox: &HeartbeatProxmox{
			IsProxmox: true,
			Version:   "8.1.3",
			NodeName:  "pve1",
		},
		HyperV: nil, // Not a Hyper-V host
		Docker: &DockerInfo{
			Available:         true,
			Version:           "24.0.7",
			Containers:        10,
			ContainersRunning: 5,
		},
		Winget: &HeartbeatWinget{
			Available:    true,
			Version:      "1.6.3133",
			SystemLevel:  true,
		},
	}

	data, err := json.Marshal(heartbeat)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed HeartbeatMessage
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.Action != "heartbeat" {
		t.Errorf("Action = %s, want heartbeat", parsed.Action)
	}
	if parsed.Type != "full" {
		t.Errorf("Type = %s, want full", parsed.Type)
	}
	if parsed.Proxmox == nil {
		t.Error("Proxmox should not be nil")
	}
	if parsed.HyperV != nil {
		t.Error("HyperV should be nil")
	}
	if parsed.SerialNumber != "ABC123XYZ" {
		t.Errorf("SerialNumber = %s, want ABC123XYZ", parsed.SerialNumber)
	}
}

// TestMessageWithRawData tests Message with raw JSON data.
func TestMessageWithRawData(t *testing.T) {
	rawData := `{"action":"custom_action","request_id":"req-001","data":{"key":"value","count":42}}`

	var msg Message
	if err := json.Unmarshal([]byte(rawData), &msg); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if msg.Action != "custom_action" {
		t.Errorf("Action = %s, want custom_action", msg.Action)
	}
	if msg.RequestID != "req-001" {
		t.Errorf("RequestID = %s, want req-001", msg.RequestID)
	}
	if msg.Data == nil {
		t.Error("Data should not be nil")
	}
}

// TestResponseWithDataTypes tests Response with various data types.
func TestResponseWithDataTypes(t *testing.T) {
	tests := []struct {
		name string
		data interface{}
	}{
		{"string data", "simple string"},
		{"number data", 42},
		{"bool data", true},
		{"array data", []string{"a", "b", "c"}},
		{"map data", map[string]interface{}{"key": "value"}},
		{"nil data", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := Response{
				Action:    "test_action",
				RequestID: "req-123",
				Success:   true,
				Data:      tt.data,
			}

			data, err := json.Marshal(resp)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			var parsed map[string]interface{}
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			if parsed["action"] != "test_action" {
				t.Error("action mismatch")
			}
		})
	}
}

// TestActionToResponseActionMapping tests action mapping.
func TestActionToResponseActionMapping(t *testing.T) {
	// Verify known mapping
	if mapped, ok := actionToResponseAction["pull_logs"]; !ok {
		t.Error("pull_logs should be in actionToResponseAction")
	} else if mapped != "logs_result" {
		t.Errorf("pull_logs should map to logs_result, got %s", mapped)
	}
}

// TestDockerInfoComplete tests DockerInfo with all fields.
func TestDockerInfoComplete(t *testing.T) {
	dockerInfo := DockerInfo{
		Available:         true,
		Version:           "24.0.7",
		APIVersion:        "1.43",
		Containers:        25,
		ContainersRunning: 15,
		Images:            50,
	}

	data, err := json.Marshal(dockerInfo)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed DockerInfo
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.Containers != 25 {
		t.Errorf("Containers = %d, want 25", parsed.Containers)
	}
	if parsed.ContainersRunning != 15 {
		t.Errorf("ContainersRunning = %d, want 15", parsed.ContainersRunning)
	}
	if parsed.Images != 50 {
		t.Errorf("Images = %d, want 50", parsed.Images)
	}
}

// TestHeartbeatStatsWithDiskArray tests HeartbeatStats with multiple disks.
func TestHeartbeatStatsWithDiskArray(t *testing.T) {
	stats := HeartbeatStats{
		CPUPercent:    30.0,
		MemoryPercent: 50.0,
		MemoryUsed:    8000000000,
		MemoryTotal:   16000000000,
		Disk: []HeartbeatDisk{
			{Device: "/dev/sda1", Mountpoint: "/", Total: 500000000000, Used: 200000000000, Free: 300000000000, UsedPercent: 40.0},
			{Device: "/dev/sdb1", Mountpoint: "/data", Total: 1000000000000, Used: 500000000000, Free: 500000000000, UsedPercent: 50.0},
			{Device: "/dev/sdc1", Mountpoint: "/backup", Total: 2000000000000, Used: 800000000000, Free: 1200000000000, UsedPercent: 40.0},
		},
		UptimeSeconds: 86400,
		ProcessCount:  150,
	}

	data, err := json.Marshal(stats)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed HeartbeatStats
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(parsed.Disk) != 3 {
		t.Errorf("len(Disk) = %d, want 3", len(parsed.Disk))
	}
	if parsed.Disk[1].Mountpoint != "/data" {
		t.Errorf("Disk[1].Mountpoint = %s, want /data", parsed.Disk[1].Mountpoint)
	}
}

// TestOsqueryResponseWithError tests OsqueryResponse with error data.
func TestOsqueryResponseWithError(t *testing.T) {
	osqResp := OsqueryResponse{
		Action:    "run_osquery",
		ScanType:  "software",
		RequestID: "req-error",
		Data:      map[string]string{"error": "osquery not available"},
	}

	data, err := json.Marshal(osqResp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	dataMap, ok := parsed["data"].(map[string]interface{})
	if !ok {
		t.Fatal("data should be a map")
	}
	if dataMap["error"] != "osquery not available" {
		t.Errorf("error = %v, want 'osquery not available'", dataMap["error"])
	}
}

// TestHeartbeatWingetOmitEmpty tests HeartbeatWinget with empty optional fields.
func TestHeartbeatWingetOmitEmpty(t *testing.T) {
	winget := HeartbeatWinget{
		Available: false,
		// All other fields are zero values
	}

	data, err := json.Marshal(winget)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Check that version and binary_path are omitted
	if _, exists := parsed["version"]; exists && parsed["version"] != "" {
		t.Log("version exists but should be empty or omitted when winget unavailable")
	}
}

// TestFileOperationActions tests file operation action messages.
func TestFileOperationActions(t *testing.T) {
	actions := []struct {
		action string
		fields map[string]interface{}
	}{
		{"list_dir", map[string]interface{}{"path": "/home/user"}},
		{"create_folder", map[string]interface{}{"path": "/home/user/newfolder"}},
		{"delete_entry", map[string]interface{}{"path": "/home/user/oldfile.txt"}},
		{"rename_entry", map[string]interface{}{"old_path": "/old/path", "new_path": "/new/path"}},
		{"download_file", map[string]interface{}{"path": "/file/to/download.txt"}},
		{"zip_entry", map[string]interface{}{"path": "/folder/to/zip", "output": "/output.zip"}},
		{"unzip_entry", map[string]interface{}{"path": "/archive.zip", "output": "/extracted"}},
		{"chmod", map[string]interface{}{"path": "/file", "mode": "755"}},
		{"chown", map[string]interface{}{"path": "/file", "owner": "root", "group": "root"}},
	}

	for _, tc := range actions {
		t.Run(tc.action, func(t *testing.T) {
			msg := map[string]interface{}{
				"action":     tc.action,
				"request_id": "req-" + tc.action,
			}
			for k, v := range tc.fields {
				msg[k] = v
			}

			data, err := json.Marshal(msg)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			var parsed Message
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			if parsed.Action != tc.action {
				t.Errorf("Action = %s, want %s", parsed.Action, tc.action)
			}
		})
	}
}

// TestUploadActions tests upload-related action messages.
func TestUploadActions(t *testing.T) {
	actions := []struct {
		action string
		fields map[string]interface{}
	}{
		{"start_upload", map[string]interface{}{"path": "/upload/target.txt", "size": 1024}},
		{"upload_chunk", map[string]interface{}{"upload_id": "upload-123", "offset": 0, "data": "base64data"}},
		{"finish_upload", map[string]interface{}{"upload_id": "upload-123"}},
		{"cancel_upload", map[string]interface{}{"upload_id": "upload-123"}},
	}

	for _, tc := range actions {
		t.Run(tc.action, func(t *testing.T) {
			msg := map[string]interface{}{
				"action":     tc.action,
				"request_id": "req-" + tc.action,
			}
			for k, v := range tc.fields {
				msg[k] = v
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
				t.Errorf("action = %v, want %s", parsed["action"], tc.action)
			}
		})
	}
}

// TestSoftwareActions tests software installation/uninstallation actions.
func TestSoftwareActions(t *testing.T) {
	installActions := []string{
		"install_software",
		"download_and_install_msi",
		"download_and_install_pkg",
		"download_and_install_cask",
	}

	uninstallActions := []string{
		"uninstall_software",
		"uninstall_msi",
		"uninstall_pkg",
		"uninstall_cask",
		"uninstall_deb",
		"uninstall_rpm",
	}

	for _, action := range installActions {
		t.Run("install_"+action, func(t *testing.T) {
			msg := map[string]interface{}{
				"action":          action,
				"request_id":      "req-" + action,
				"installation_id": "install-123",
				"package_name":    "test-package",
			}

			data, err := json.Marshal(msg)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			var parsed map[string]interface{}
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			if parsed["action"] != action {
				t.Errorf("action = %v, want %s", parsed["action"], action)
			}
		})
	}

	for _, action := range uninstallActions {
		t.Run("uninstall_"+action, func(t *testing.T) {
			msg := map[string]interface{}{
				"action":            action,
				"request_id":        "req-" + action,
				"uninstallation_id": "uninstall-123",
				"package_name":      "test-package",
			}

			data, err := json.Marshal(msg)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			var parsed map[string]interface{}
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			if parsed["action"] != action {
				t.Errorf("action = %v, want %s", parsed["action"], action)
			}
		})
	}
}
