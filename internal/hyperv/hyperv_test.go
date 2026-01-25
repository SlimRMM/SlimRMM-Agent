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

// TestPSEscape tests PowerShell string escaping.
func TestPSEscape(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"with'quote", "with''quote"},
		{"multiple'single'quotes", "multiple''single''quotes"},
		{"no special chars", "no special chars"},
		{"", ""},
		{"'", "''"},
		{"''", "''''"},
		{"test's test's", "test''s test''s"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := PSEscape(tt.input)
			if result != tt.expected {
				t.Errorf("PSEscape(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestPSString tests PowerShell string wrapping.
func TestPSString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "'simple'"},
		{"with'quote", "'with''quote'"},
		{"", "''"},
		{"TestVM", "'TestVM'"},
		{"VM with spaces", "'VM with spaces'"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := PSString(tt.input)
			if result != tt.expected {
				t.Errorf("PSString(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestParseIntFromString tests integer parsing from strings.
func TestParseIntFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"123", 123},
		{"0", 0},
		{"42", 42},
		{"", 0},
		{"abc", 0},
		{"12abc34", 1234},
		{"  5  ", 5},
		{"999999", 999999},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var result int
			parseIntFromString(tt.input, &result)
			if result != tt.expected {
				t.Errorf("parseIntFromString(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

// TestVMStateConstants tests all VM state constants.
func TestVMStateConstants(t *testing.T) {
	states := []struct {
		state    VMState
		expected string
	}{
		{VMStateRunning, "Running"},
		{VMStateOff, "Off"},
		{VMStateSaved, "Saved"},
		{VMStatePaused, "Paused"},
		{VMStateStarting, "Starting"},
		{VMStateStopping, "Stopping"},
		{VMStateSaving, "Saving"},
		{VMStatePausing, "Pausing"},
		{VMStateResuming, "Resuming"},
		{VMStateReset, "Reset"},
		{VMStateFastSaved, "FastSaved"},
		{VMStateFastSaving, "FastSaving"},
		{VMStateRunningCritical, "RunningCritical"},
		{VMStateOffCritical, "OffCritical"},
		{VMStateOther, "Other"},
	}

	for _, tt := range states {
		t.Run(tt.expected, func(t *testing.T) {
			if string(tt.state) != tt.expected {
				t.Errorf("state = %q, want %q", tt.state, tt.expected)
			}
		})
	}
}

// TestStateMap tests the stateMap conversion.
func TestStateMap(t *testing.T) {
	tests := []struct {
		code     int
		expected VMState
	}{
		{1, VMStateOther},
		{2, VMStateRunning},
		{3, VMStateOff},
		{4, VMStateStopping},
		{5, VMStateSaved},
		{6, VMStatePaused},
		{7, VMStateStarting},
		{8, VMStateReset},
		{9, VMStateSaving},
		{10, VMStatePausing},
		{11, VMStateResuming},
		{12, VMStateFastSaved},
		{13, VMStateFastSaving},
		{32768, VMStateRunningCritical},
		{32769, VMStateOffCritical},
	}

	for _, tt := range tests {
		state := stateMap[tt.code]
		if state != tt.expected {
			t.Errorf("stateMap[%d] = %q, want %q", tt.code, state, tt.expected)
		}
	}
}

// TestCheckpointTypeMap tests checkpoint type conversion.
func TestCheckpointTypeMap(t *testing.T) {
	tests := []struct {
		code     int
		expected string
	}{
		{0, "Disabled"},
		{1, "Production"},
		{2, "ProductionOnly"},
		{3, "Standard"},
	}

	for _, tt := range tests {
		cpType := checkpointTypeMap[tt.code]
		if cpType != tt.expected {
			t.Errorf("checkpointTypeMap[%d] = %q, want %q", tt.code, cpType, tt.expected)
		}
	}
}

// TestActionResultSerialization tests ActionResult serialization.
func TestActionResultSerialization(t *testing.T) {
	result := ActionResult{
		Success:   true,
		Action:    ActionStart,
		VMName:    "TestVM",
		VMID:      "12345678-1234-1234-1234-123456789012",
		Message:   "VM started successfully",
		StartedAt: "2024-01-15T10:30:00Z",
		Duration:  1500,
		NewState:  VMStateRunning,
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal ActionResult: %v", err)
	}

	var parsed ActionResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !parsed.Success {
		t.Error("expected success to be true")
	}
	if parsed.Action != ActionStart {
		t.Errorf("expected action %q, got %q", ActionStart, parsed.Action)
	}
	if parsed.Duration != 1500 {
		t.Errorf("expected duration 1500, got %d", parsed.Duration)
	}
}

// TestExportResultSerialization tests ExportResult serialization.
func TestExportResultSerialization(t *testing.T) {
	result := ExportResult{
		Success:     true,
		VMName:      "TestVM",
		VMID:        "vm-uuid-123",
		ExportPath:  "C:\\Exports\\TestVM",
		VMCXPath:    "C:\\Exports\\TestVM\\Virtual Machines\\vm.vmcx",
		Size:        10737418240, // 10GB
		StartedAt:   "2024-01-15T10:30:00Z",
		CompletedAt: "2024-01-15T10:35:00Z",
		Duration:    300000,
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal ExportResult: %v", err)
	}

	var parsed ExportResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !parsed.Success {
		t.Error("expected success to be true")
	}
	if parsed.Size != 10737418240 {
		t.Errorf("expected size 10737418240, got %d", parsed.Size)
	}
}

// TestImportRequestSerialization tests ImportRequest serialization.
func TestImportRequestSerialization(t *testing.T) {
	request := ImportRequest{
		VMCXPath:        "C:\\Exports\\TestVM\\Virtual Machines\\vm.vmcx",
		DestinationPath: "C:\\VMs",
		GenerateNewID:   true,
		Copy:            true,
		VHDDestination:  "C:\\VMs\\VHDs",
		Timeout:         3600,
	}

	data, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("failed to marshal ImportRequest: %v", err)
	}

	var parsed ImportRequest
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !parsed.GenerateNewID {
		t.Error("expected generate_new_id to be true")
	}
	if !parsed.Copy {
		t.Error("expected copy to be true")
	}
	if parsed.Timeout != 3600 {
		t.Errorf("expected timeout 3600, got %d", parsed.Timeout)
	}
}

// TestBackupRequestSerialization tests BackupRequest serialization.
func TestBackupRequestSerialization(t *testing.T) {
	request := BackupRequest{
		VMName:           "TestVM",
		VMID:             "vm-uuid-123",
		BackupPath:       "C:\\Backups",
		UseVSS:           true,
		CreateCheckpoint: true,
		CheckpointName:   "PreBackup",
		Timeout:          1800,
	}

	data, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("failed to marshal BackupRequest: %v", err)
	}

	var parsed BackupRequest
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !parsed.UseVSS {
		t.Error("expected use_vss to be true")
	}
	if !parsed.CreateCheckpoint {
		t.Error("expected create_checkpoint to be true")
	}
	if parsed.CheckpointName != "PreBackup" {
		t.Errorf("expected checkpoint_name 'PreBackup', got %q", parsed.CheckpointName)
	}
}

// TestBackupResultSerialization tests BackupResult serialization.
func TestBackupResultSerialization(t *testing.T) {
	result := BackupResult{
		Success:        true,
		VMName:         "TestVM",
		VMID:           "vm-uuid-123",
		BackupPath:     "C:\\Backups\\20240115_103000",
		CheckpointName: "PreBackup",
		ExportPath:     "C:\\Backups\\20240115_103000\\TestVM",
		Size:           21474836480, // 20GB
		StartedAt:      "2024-01-15T10:30:00Z",
		CompletedAt:    "2024-01-15T10:45:00Z",
		Duration:       900000,
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal BackupResult: %v", err)
	}

	var parsed BackupResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !parsed.Success {
		t.Error("expected success to be true")
	}
	if parsed.Size != 21474836480 {
		t.Errorf("expected size 21474836480, got %d", parsed.Size)
	}
}

// TestExportInfoSerialization tests ExportInfo serialization.
func TestExportInfoSerialization(t *testing.T) {
	exportInfo := ExportInfo{
		VMName:     "TestVM",
		ExportPath: "C:\\Exports\\TestVM",
		VMCXPath:   "C:\\Exports\\TestVM\\Virtual Machines\\vm.vmcx",
		Size:       10737418240,
		ExportedAt: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
	}

	data, err := json.Marshal(exportInfo)
	if err != nil {
		t.Fatalf("failed to marshal ExportInfo: %v", err)
	}

	var parsed ExportInfo
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.VMName != "TestVM" {
		t.Errorf("expected vm_name 'TestVM', got %q", parsed.VMName)
	}
	if parsed.Size != 10737418240 {
		t.Errorf("expected size 10737418240, got %d", parsed.Size)
	}
}

// TestCheckpointRequestSerialization tests CheckpointRequest serialization.
func TestCheckpointRequestSerialization(t *testing.T) {
	request := CheckpointRequest{
		VMName:         "TestVM",
		VMID:           "vm-uuid-123",
		CheckpointName: "Snapshot1",
		Notes:          "Before update",
	}

	data, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("failed to marshal CheckpointRequest: %v", err)
	}

	var parsed CheckpointRequest
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.VMName != "TestVM" {
		t.Errorf("expected vm_name 'TestVM', got %q", parsed.VMName)
	}
	if parsed.CheckpointName != "Snapshot1" {
		t.Errorf("expected checkpoint_name 'Snapshot1', got %q", parsed.CheckpointName)
	}
}

// TestRestoreCheckpointRequestSerialization tests RestoreCheckpointRequest serialization.
func TestRestoreCheckpointRequestSerialization(t *testing.T) {
	request := RestoreCheckpointRequest{
		VMName:         "TestVM",
		VMID:           "vm-uuid-123",
		CheckpointName: "Snapshot1",
		CheckpointID:   "checkpoint-id-456",
	}

	data, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("failed to marshal RestoreCheckpointRequest: %v", err)
	}

	var parsed RestoreCheckpointRequest
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.CheckpointID != "checkpoint-id-456" {
		t.Errorf("expected checkpoint_id 'checkpoint-id-456', got %q", parsed.CheckpointID)
	}
}

// TestDeleteCheckpointRequestSerialization tests DeleteCheckpointRequest serialization.
func TestDeleteCheckpointRequestSerialization(t *testing.T) {
	request := DeleteCheckpointRequest{
		VMName:             "TestVM",
		VMID:               "vm-uuid-123",
		CheckpointName:     "Snapshot1",
		CheckpointID:       "checkpoint-id-456",
		IncludeAllChildren: true,
	}

	data, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("failed to marshal DeleteCheckpointRequest: %v", err)
	}

	var parsed DeleteCheckpointRequest
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !parsed.IncludeAllChildren {
		t.Error("expected include_all_children to be true")
	}
}

// TestCheckpointResultSerialization tests CheckpointResult serialization.
func TestCheckpointResultSerialization(t *testing.T) {
	checkpoint := &Checkpoint{
		ID:             "checkpoint-id-123",
		Name:           "Snapshot1",
		VMName:         "TestVM",
		VMID:           "vm-uuid-456",
		CreationTime:   time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		CheckpointType: "Standard",
	}

	result := CheckpointResult{
		Success:    true,
		Message:    "Checkpoint created successfully",
		Checkpoint: checkpoint,
		Duration:   500,
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal CheckpointResult: %v", err)
	}

	var parsed CheckpointResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !parsed.Success {
		t.Error("expected success to be true")
	}
	if parsed.Checkpoint == nil {
		t.Fatal("expected checkpoint to not be nil")
	}
	if parsed.Checkpoint.Name != "Snapshot1" {
		t.Errorf("expected checkpoint name 'Snapshot1', got %q", parsed.Checkpoint.Name)
	}
}

// TestVmHostInfoSerialization tests vmHostInfo serialization.
func TestVmHostInfoSerialization(t *testing.T) {
	info := vmHostInfo{
		Name:                           "hyperv-server",
		FullyQualifiedDomainName:       "hyperv-server.domain.local",
		VirtualHardDiskPath:            "C:\\Hyper-V\\Virtual Hard Disks",
		VirtualMachinePath:             "C:\\Hyper-V\\Virtual Machines",
		MacAddressMaximum:              "00155D000F00",
		MacAddressMinimum:              "00155D000000",
		EnableEnhancedSessionMode:      true,
		NumaSpanningEnabled:            true,
		IoVSupport:                     false,
		VirtualMachineMigrationEnabled: true,
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("failed to marshal vmHostInfo: %v", err)
	}

	var parsed vmHostInfo
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.Name != "hyperv-server" {
		t.Errorf("expected name 'hyperv-server', got %q", parsed.Name)
	}
	if !parsed.EnableEnhancedSessionMode {
		t.Error("expected EnableEnhancedSessionMode to be true")
	}
}

// TestVmPSOutputSerialization tests vmPSOutput serialization.
func TestVmPSOutputSerialization(t *testing.T) {
	output := vmPSOutput{
		Id:                   "12345678-1234-1234-1234-123456789012",
		VMId:                 "12345678-1234-1234-1234-123456789012",
		Name:                 "TestVM",
		State:                2, // Running
		ProcessorCount:       4,
		MemoryAssigned:       8589934592,
		MemoryDemand:         4294967296,
		MemoryStartup:        8589934592,
		DynamicMemoryEnabled: true,
		Generation:           2,
		Version:              "9.0",
		Path:                 "C:\\Hyper-V\\Virtual Machines",
		CheckpointCount:      3,
		UptimeSeconds:        86400,
		Status:               "Operating normally",
		ReplicationState:     0,
		Notes:                "Test VM",
		CPUUsage:             15,
	}

	data, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("failed to marshal vmPSOutput: %v", err)
	}

	var parsed vmPSOutput
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.Name != "TestVM" {
		t.Errorf("expected name 'TestVM', got %q", parsed.Name)
	}
	if parsed.ProcessorCount != 4 {
		t.Errorf("expected processor count 4, got %d", parsed.ProcessorCount)
	}
}

// TestCheckpointPSOutputSerialization tests checkpointPSOutput serialization.
func TestCheckpointPSOutputSerialization(t *testing.T) {
	output := checkpointPSOutput{
		Id:                 "checkpoint-id-123",
		Name:               "Snapshot1",
		VMName:             "TestVM",
		VMId:               "vm-uuid-456",
		CreationTime:       "2024-01-15T10:30:00Z",
		ParentCheckpointId: "parent-checkpoint-id",
		CheckpointType:     3, // Standard
		Notes:              "Test checkpoint",
	}

	data, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("failed to marshal checkpointPSOutput: %v", err)
	}

	var parsed checkpointPSOutput
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.Name != "Snapshot1" {
		t.Errorf("expected name 'Snapshot1', got %q", parsed.Name)
	}
	if parsed.CheckpointType != 3 {
		t.Errorf("expected checkpoint type 3, got %d", parsed.CheckpointType)
	}
}

// TestPsOutputToVM tests the psOutputToVM conversion function.
func TestPsOutputToVM(t *testing.T) {
	tests := []struct {
		name        string
		output      vmPSOutput
		expectedID  string
		expectState VMState
	}{
		{
			name: "running VM with Id",
			output: vmPSOutput{
				Id:             "id-123",
				VMId:           "vmid-456",
				Name:           "TestVM",
				State:          2, // Running
				ProcessorCount: 4,
				Generation:     2,
			},
			expectedID:  "id-123",
			expectState: VMStateRunning,
		},
		{
			name: "off VM without Id",
			output: vmPSOutput{
				Id:             "",
				VMId:           "vmid-456",
				Name:           "TestVM2",
				State:          3, // Off
				ProcessorCount: 2,
				Generation:     1,
			},
			expectedID:  "vmid-456",
			expectState: VMStateOff,
		},
		{
			name: "unknown state",
			output: vmPSOutput{
				Id:    "id-789",
				Name:  "TestVM3",
				State: 999, // Unknown
			},
			expectedID:  "id-789",
			expectState: VMStateOther,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vm := psOutputToVM(tt.output)

			if vm.ID != tt.expectedID {
				t.Errorf("expected ID %q, got %q", tt.expectedID, vm.ID)
			}
			if vm.State != tt.expectState {
				t.Errorf("expected state %q, got %q", tt.expectState, vm.State)
			}
			if vm.Name != tt.output.Name {
				t.Errorf("expected name %q, got %q", tt.output.Name, vm.Name)
			}
		})
	}
}

// TestPsOutputToCheckpoint tests the psOutputToCheckpoint conversion function.
func TestPsOutputToCheckpoint(t *testing.T) {
	tests := []struct {
		name       string
		output     checkpointPSOutput
		expectType string
	}{
		{
			name: "standard checkpoint",
			output: checkpointPSOutput{
				Id:             "cp-123",
				Name:           "Snapshot1",
				VMName:         "TestVM",
				VMId:           "vm-456",
				CreationTime:   "2024-01-15T10:30:00Z",
				CheckpointType: 3,
			},
			expectType: "Standard",
		},
		{
			name: "production checkpoint",
			output: checkpointPSOutput{
				Id:             "cp-456",
				Name:           "Snapshot2",
				VMName:         "TestVM",
				VMId:           "vm-456",
				CreationTime:   "2024-01-15T11:00:00Z",
				CheckpointType: 1,
			},
			expectType: "Production",
		},
		{
			name: "unknown checkpoint type",
			output: checkpointPSOutput{
				Id:             "cp-789",
				Name:           "Snapshot3",
				VMName:         "TestVM",
				VMId:           "vm-456",
				CheckpointType: 999,
			},
			expectType: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cp := psOutputToCheckpoint(tt.output)

			if cp.ID != tt.output.Id {
				t.Errorf("expected ID %q, got %q", tt.output.Id, cp.ID)
			}
			if cp.Name != tt.output.Name {
				t.Errorf("expected name %q, got %q", tt.output.Name, cp.Name)
			}
			if cp.CheckpointType != tt.expectType {
				t.Errorf("expected type %q, got %q", tt.expectType, cp.CheckpointType)
			}
		})
	}
}

// TestConstants tests various package constants.
func TestConstants(t *testing.T) {
	// Test defaultActionTimeout
	if defaultActionTimeout != 60*time.Second {
		t.Errorf("defaultActionTimeout = %v, want 60s", defaultActionTimeout)
	}

	// Test defaultBackupTimeout
	if defaultBackupTimeout != 30*time.Minute {
		t.Errorf("defaultBackupTimeout = %v, want 30m", defaultBackupTimeout)
	}

	// Test defaultTimeout
	if defaultTimeout != 30*time.Second {
		t.Errorf("defaultTimeout = %v, want 30s", defaultTimeout)
	}

	// Test detectionTimeout
	if detectionTimeout != 5*time.Second {
		t.Errorf("detectionTimeout = %v, want 5s", detectionTimeout)
	}

	// Test psShell constant
	if psShell != "powershell" {
		t.Errorf("psShell = %q, want 'powershell'", psShell)
	}
}

// TestInfoStruct tests Info struct fields.
func TestInfoStruct(t *testing.T) {
	info := Info{
		IsHyperV:       true,
		Version:        "10.0.19041.1",
		HostName:       "hyperv-server.domain.local",
		VMCount:        10,
		ClusterEnabled: true,
	}

	if !info.IsHyperV {
		t.Error("IsHyperV should be true")
	}
	if info.Version != "10.0.19041.1" {
		t.Errorf("Version = %q, want '10.0.19041.1'", info.Version)
	}
	if info.HostName != "hyperv-server.domain.local" {
		t.Errorf("HostName = %q, want 'hyperv-server.domain.local'", info.HostName)
	}
	if info.VMCount != 10 {
		t.Errorf("VMCount = %d, want 10", info.VMCount)
	}
	if !info.ClusterEnabled {
		t.Error("ClusterEnabled should be true")
	}
}

// TestClientClose tests Client.Close method.
func TestClientClose(t *testing.T) {
	client := &Client{
		hostName: "test-host",
	}

	err := client.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}

// TestClientHostName tests Client.HostName method.
func TestClientHostName(t *testing.T) {
	client := &Client{
		hostName: "test-host",
	}

	name := client.HostName()
	if name != "test-host" {
		t.Errorf("HostName = %q, want 'test-host'", name)
	}
}

// TestVMAllFields tests VM struct with all fields.
func TestVMAllFields(t *testing.T) {
	vm := VM{
		ID:                       "12345678-1234-1234-1234-123456789012",
		Name:                     "TestVM",
		State:                    VMStateRunning,
		CPUCount:                 8,
		MemoryAssigned:           17179869184, // 16GB
		MemoryDemand:             8589934592,  // 8GB
		MemoryStartup:            17179869184, // 16GB
		DynamicMemory:            true,
		Generation:               2,
		Version:                  "9.0",
		Path:                     "C:\\Hyper-V\\Virtual Machines\\TestVM",
		CheckpointCount:          5,
		Uptime:                   604800, // 7 days
		Status:                   "Operating normally",
		ReplicationState:         "Replicating",
		Notes:                    "Production VM",
		CPUUsage:                 25,
		IntegrationServicesState: "Up to date",
	}

	data, err := json.Marshal(vm)
	if err != nil {
		t.Fatalf("failed to marshal VM: %v", err)
	}

	var parsed VM
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.MemoryAssigned != 17179869184 {
		t.Errorf("MemoryAssigned = %d, want 17179869184", parsed.MemoryAssigned)
	}
	if !parsed.DynamicMemory {
		t.Error("DynamicMemory should be true")
	}
	if parsed.IntegrationServicesState != "Up to date" {
		t.Errorf("IntegrationServicesState = %q, want 'Up to date'", parsed.IntegrationServicesState)
	}
}
