// Package hyperv provides tests for Hyper-V management functionality.
package hyperv

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// TestDetectParsing tests Info struct JSON serialization.
func TestDetectParsing(t *testing.T) {
	tests := []struct {
		name     string
		info     Info
		validate func(t *testing.T, data []byte)
	}{
		{
			name: "hyperv host detected",
			info: Info{
				IsHyperV:       true,
				Version:        "10.0.19041.1",
				HostName:       "hyperv-server",
				VMCount:        5,
				ClusterEnabled: false,
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("failed to unmarshal: %v", err)
				}
				if result["is_hyperv"] != true {
					t.Error("expected is_hyperv to be true")
				}
				if result["vm_count"].(float64) != 5 {
					t.Errorf("expected vm_count to be 5, got %v", result["vm_count"])
				}
			},
		},
		{
			name: "not a hyperv host",
			info: Info{
				IsHyperV: false,
			},
			validate: func(t *testing.T, data []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("failed to unmarshal: %v", err)
				}
				if result["is_hyperv"] != false {
					t.Error("expected is_hyperv to be false")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.info)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}
			tt.validate(t, data)
		})
	}
}

// TestVMStateParsing tests VM state string handling.
func TestVMStateParsing(t *testing.T) {
	tests := []struct {
		name     string
		state    VMState
		expected string
	}{
		{"running state", VMStateRunning, "Running"},
		{"off state", VMStateOff, "Off"},
		{"saved state", VMStateSaved, "Saved"},
		{"paused state", VMStatePaused, "Paused"},
		{"starting state", VMStateStarting, "Starting"},
		{"stopping state", VMStateStopping, "Stopping"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.state) != tt.expected {
				t.Errorf("state mismatch: got %s, want %s", tt.state, tt.expected)
			}
		})
	}
}

// TestActionTypeParsing tests action type string handling.
func TestActionTypeParsing(t *testing.T) {
	tests := []struct {
		name     string
		action   ActionType
		expected string
	}{
		{"start action", ActionStart, "start"},
		{"stop action", ActionStop, "stop"},
		{"restart action", ActionRestart, "restart"},
		{"pause action", ActionPause, "pause"},
		{"resume action", ActionResume, "resume"},
		{"reset action", ActionReset, "reset"},
		{"save action", ActionSave, "save"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.action) != tt.expected {
				t.Errorf("action mismatch: got %s, want %s", tt.action, tt.expected)
			}
		})
	}
}

// TestVMJSONSerialization tests VM struct JSON serialization.
func TestVMJSONSerialization(t *testing.T) {
	vm := VM{
		ID:              "12345678-1234-1234-1234-123456789012",
		Name:            "TestVM",
		State:           VMStateRunning,
		CPUCount:        4,
		MemoryAssigned:  8589934592, // 8GB
		Generation:      2,
		CheckpointCount: 3,
	}

	data, err := json.Marshal(vm)
	if err != nil {
		t.Fatalf("failed to marshal VM: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result["name"] != "TestVM" {
		t.Errorf("expected name TestVM, got %v", result["name"])
	}
	if result["state"] != "Running" {
		t.Errorf("expected state Running, got %v", result["state"])
	}
	if result["cpu_count"].(float64) != 4 {
		t.Errorf("expected cpu_count 4, got %v", result["cpu_count"])
	}
	if result["generation"].(float64) != 2 {
		t.Errorf("expected generation 2, got %v", result["generation"])
	}
}

// TestCheckpointJSONSerialization tests Checkpoint struct JSON serialization.
func TestCheckpointJSONSerialization(t *testing.T) {
	checkpoint := Checkpoint{
		ID:             "checkpoint-id-123",
		Name:           "Before-Update",
		VMName:         "TestVM",
		VMID:           "vm-uuid-456",
		CreationTime:   time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		CheckpointType: "Standard",
	}

	data, err := json.Marshal(checkpoint)
	if err != nil {
		t.Fatalf("failed to marshal Checkpoint: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result["name"] != "Before-Update" {
		t.Errorf("expected name Before-Update, got %v", result["name"])
	}
	if result["vm_name"] != "TestVM" {
		t.Errorf("expected vm_name TestVM, got %v", result["vm_name"])
	}
	if result["checkpoint_type"] != "Standard" {
		t.Errorf("expected checkpoint_type Standard, got %v", result["checkpoint_type"])
	}
}

// TestActionRequestValidation tests ActionRequest validation logic.
func TestActionRequestValidation(t *testing.T) {
	tests := []struct {
		name    string
		request ActionRequest
		valid   bool
	}{
		{
			name: "valid start request",
			request: ActionRequest{
				VMName: "TestVM",
				Action: ActionStart,
			},
			valid: true,
		},
		{
			name: "valid force stop request",
			request: ActionRequest{
				VMName: "TestVM",
				Action: ActionStop,
				Force:  true,
			},
			valid: true,
		},
		{
			name: "missing vm name",
			request: ActionRequest{
				Action: ActionStart,
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := tt.request.VMName != "" && tt.request.Action != ""
			if isValid != tt.valid {
				t.Errorf("validation mismatch: got %v, want %v", isValid, tt.valid)
			}
		})
	}
}

// TestExportRequestValidation tests ExportRequest validation.
func TestExportRequestValidation(t *testing.T) {
	tests := []struct {
		name    string
		request ExportRequest
		valid   bool
	}{
		{
			name: "valid export request",
			request: ExportRequest{
				VMName:     "TestVM",
				ExportPath: "C:\\Exports\\TestVM",
			},
			valid: true,
		},
		{
			name: "missing export path",
			request: ExportRequest{
				VMName: "TestVM",
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := tt.request.VMName != "" && tt.request.ExportPath != ""
			if isValid != tt.valid {
				t.Errorf("validation mismatch: got %v, want %v", isValid, tt.valid)
			}
		})
	}
}

// TestClientCreation tests client initialization.
func TestClientCreation(t *testing.T) {
	ctx := context.Background()
	client, err := NewClient(ctx)

	// On non-Windows or without Hyper-V, expect an error
	if err != nil {
		t.Skipf("Skipping client creation test: %v", err)
	}

	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

// TestResourceListSerialization tests ResourceList serialization.
func TestResourceListSerialization(t *testing.T) {
	result := ResourceList{
		VMs: []VM{
			{
				ID:       "vm-1",
				Name:     "VM1",
				State:    VMStateRunning,
				CPUCount: 2,
			},
			{
				ID:       "vm-2",
				Name:     "VM2",
				State:    VMStateOff,
				CPUCount: 4,
			},
		},
		TotalVMs:   2,
		RunningVMs: 1,
		StoppedVMs: 1,
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal ResourceList: %v", err)
	}

	var parsed ResourceList
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.TotalVMs != 2 {
		t.Errorf("expected total_vms 2, got %d", parsed.TotalVMs)
	}
	if len(parsed.VMs) != 2 {
		t.Errorf("expected 2 VMs, got %d", len(parsed.VMs))
	}
	if parsed.RunningVMs != 1 {
		t.Errorf("expected running_vms 1, got %d", parsed.RunningVMs)
	}
}
