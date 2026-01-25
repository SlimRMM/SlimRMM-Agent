package proxmox

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInfo(t *testing.T) {
	info := Info{
		IsProxmox:      true,
		Version:        "8.0.4",
		Release:        "8.0",
		KernelVersion:  "6.2.16-3-pve",
		ClusterName:    "test-cluster",
		NodeName:       "pve1",
		RepositoryType: "no-subscription",
	}

	if !info.IsProxmox {
		t.Error("IsProxmox should be true")
	}
	if info.Version != "8.0.4" {
		t.Errorf("Version = %s, want 8.0.4", info.Version)
	}
	if info.Release != "8.0" {
		t.Errorf("Release = %s, want 8.0", info.Release)
	}
	if info.KernelVersion != "6.2.16-3-pve" {
		t.Errorf("KernelVersion = %s, want 6.2.16-3-pve", info.KernelVersion)
	}
	if info.ClusterName != "test-cluster" {
		t.Errorf("ClusterName = %s, want test-cluster", info.ClusterName)
	}
	if info.NodeName != "pve1" {
		t.Errorf("NodeName = %s, want pve1", info.NodeName)
	}
	if info.RepositoryType != "no-subscription" {
		t.Errorf("RepositoryType = %s, want no-subscription", info.RepositoryType)
	}
}

func TestInfoDefaults(t *testing.T) {
	info := Info{IsProxmox: false}

	if info.IsProxmox {
		t.Error("default IsProxmox should be false")
	}
	if info.Version != "" {
		t.Error("default Version should be empty")
	}
	if info.Release != "" {
		t.Error("default Release should be empty")
	}
}

func TestConstants(t *testing.T) {
	if pveConfigPath != "/etc/pve" {
		t.Errorf("pveConfigPath = %s, want /etc/pve", pveConfigPath)
	}
	if pveVersionCmd != "pveversion" {
		t.Errorf("pveVersionCmd = %s, want pveversion", pveVersionCmd)
	}
	if pveClusterConf != "/etc/pve/corosync.conf" {
		t.Errorf("pveClusterConf = %s, want /etc/pve/corosync.conf", pveClusterConf)
	}
	if detectionTimeout != 5*time.Second {
		t.Errorf("detectionTimeout = %v, want 5s", detectionTimeout)
	}
}

func TestParseVersionOutput(t *testing.T) {
	tests := []struct {
		name           string
		output         string
		wantVersion    string
		wantKernel     string
		wantRelease    string
	}{
		{
			name:           "full version output",
			output:         "pve-manager/8.0.4 (running kernel: 6.2.16-3-pve)\nproxmox-ve: 8.0-2",
			wantVersion:    "8.0.4",
			wantKernel:     "6.2.16-3-pve",
			wantRelease:    "8.0-2",
		},
		{
			name:           "version only",
			output:         "pve-manager/7.4.3 (running kernel: 5.15.102-1-pve)",
			wantVersion:    "7.4.3",
			wantKernel:     "5.15.102-1-pve",
			wantRelease:    "",
		},
		{
			name:           "empty output",
			output:         "",
			wantVersion:    "",
			wantKernel:     "",
			wantRelease:    "",
		},
		{
			name:           "invalid output",
			output:         "some random text",
			wantVersion:    "",
			wantKernel:     "",
			wantRelease:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &Info{}
			parseVersionOutput(tt.output, info)

			if info.Version != tt.wantVersion {
				t.Errorf("Version = %s, want %s", info.Version, tt.wantVersion)
			}
			if info.KernelVersion != tt.wantKernel {
				t.Errorf("KernelVersion = %s, want %s", info.KernelVersion, tt.wantKernel)
			}
			if info.Release != tt.wantRelease {
				t.Errorf("Release = %s, want %s", info.Release, tt.wantRelease)
			}
		})
	}
}

func TestFileContains(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "proxmox_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test file
	testFile := filepath.Join(tmpDir, "test.txt")
	content := "hello world\nthis is a test"
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Test finding existing content
	if !fileContains(testFile, "hello") {
		t.Error("should find 'hello' in file")
	}
	if !fileContains(testFile, "test") {
		t.Error("should find 'test' in file")
	}

	// Test not finding content
	if fileContains(testFile, "notfound") {
		t.Error("should not find 'notfound' in file")
	}

	// Test non-existent file
	if fileContains("/nonexistent/file.txt", "anything") {
		t.Error("should return false for non-existent file")
	}
}

func TestIsProxmoxHost(t *testing.T) {
	// This test depends on whether we're running on Proxmox
	// Just verify the function doesn't panic
	result := IsProxmoxHost()
	// Result can be true or false depending on system
	_ = result
}

func TestDetectRepositoryType(t *testing.T) {
	// This test depends on system state
	// Just verify the function doesn't panic and returns a valid string
	result := detectRepositoryType()
	validTypes := map[string]bool{
		"enterprise":      true,
		"no-subscription": true,
		"test":            true,
		"unknown":         true,
	}
	if !validTypes[result] {
		t.Errorf("detectRepositoryType returned invalid type: %s", result)
	}
}

func TestGetClusterName(t *testing.T) {
	// This test depends on system state
	// Just verify the function doesn't panic
	result := getClusterName()
	// Result can be empty or contain cluster name
	_ = result
}

func TestInfoJSON(t *testing.T) {
	info := Info{
		IsProxmox:      true,
		Version:        "8.0.4",
		Release:        "8.0",
		KernelVersion:  "6.2.16-3-pve",
		ClusterName:    "myCluster",
		NodeName:       "node1",
		RepositoryType: "enterprise",
	}

	// Verify json tags work (struct tags are correct)
	// This is a compile-time check mainly
	if info.IsProxmox != true {
		t.Error("IsProxmox field access failed")
	}
}

func TestRepositoryTypes(t *testing.T) {
	// Test that the three main repository types are recognized
	types := []string{"enterprise", "no-subscription", "test", "unknown"}
	for _, rt := range types {
		info := Info{RepositoryType: rt}
		if info.RepositoryType != rt {
			t.Errorf("RepositoryType assignment failed for %s", rt)
		}
	}
}

func TestParseVersionOutputMultiline(t *testing.T) {
	output := `pve-manager/8.1.3 (running kernel: 6.5.11-4-pve)
proxmox-ve: 8.1-1
pve-kernel-6.5: 8.1-1
pve-kernel-helper: 8.1-1
ceph-fuse: 18.2.0-pve1
corosync: 3.1.7-pve1`

	info := &Info{}
	parseVersionOutput(output, info)

	if info.Version != "8.1.3" {
		t.Errorf("Version = %s, want 8.1.3", info.Version)
	}
	if info.KernelVersion != "6.5.11-4-pve" {
		t.Errorf("KernelVersion = %s, want 6.5.11-4-pve", info.KernelVersion)
	}
	if info.Release != "8.1-1" {
		t.Errorf("Release = %s, want 8.1-1", info.Release)
	}
}

// Token management tests

func TestTokenConfig(t *testing.T) {
	config := TokenConfig{
		TokenID:   "root@pam!slimrmm",
		Secret:    "abc123def456",
		CreatedAt: "2024-01-15T10:00:00Z",
		ExpiresAt: "2025-01-15T10:00:00Z",
	}

	if config.TokenID != "root@pam!slimrmm" {
		t.Errorf("TokenID = %s, want root@pam!slimrmm", config.TokenID)
	}
	if config.Secret != "abc123def456" {
		t.Errorf("Secret = %s, want abc123def456", config.Secret)
	}
	if config.CreatedAt != "2024-01-15T10:00:00Z" {
		t.Errorf("CreatedAt = %s, want 2024-01-15T10:00:00Z", config.CreatedAt)
	}
	if config.ExpiresAt != "2025-01-15T10:00:00Z" {
		t.Errorf("ExpiresAt = %s, want 2025-01-15T10:00:00Z", config.ExpiresAt)
	}
}

func TestTokenConfigDefaults(t *testing.T) {
	config := TokenConfig{}

	if config.TokenID != "" {
		t.Error("default TokenID should be empty")
	}
	if config.Secret != "" {
		t.Error("default Secret should be empty")
	}
	if config.CreatedAt != "" {
		t.Error("default CreatedAt should be empty")
	}
	if config.ExpiresAt != "" {
		t.Error("default ExpiresAt should be empty")
	}
}

func TestTokenConstants(t *testing.T) {
	if tokenConfigFile != ".proxmox_token.json" {
		t.Errorf("tokenConfigFile = %s, want .proxmox_token.json", tokenConfigFile)
	}
	if tokenName != "slimrmm" {
		t.Errorf("tokenName = %s, want slimrmm", tokenName)
	}
	if tokenUser != "root@pam" {
		t.Errorf("tokenUser = %s, want root@pam", tokenUser)
	}
	if tokenComment != "SlimRMM Agent API Token" {
		t.Errorf("tokenComment = %s, want 'SlimRMM Agent API Token'", tokenComment)
	}
	if cmdTimeout != 30*time.Second {
		t.Errorf("cmdTimeout = %v, want 30s", cmdTimeout)
	}
}

func TestGenerateSecureSecret(t *testing.T) {
	secret1, err := generateSecureSecret()
	if err != nil {
		t.Fatalf("generateSecureSecret failed: %v", err)
	}

	// Should be 64 hex characters (32 bytes)
	if len(secret1) != 64 {
		t.Errorf("secret length = %d, want 64", len(secret1))
	}

	// Generate another and verify they're different
	secret2, err := generateSecureSecret()
	if err != nil {
		t.Fatalf("generateSecureSecret failed: %v", err)
	}

	if secret1 == secret2 {
		t.Error("generated secrets should be different")
	}
}

func TestSaveAndLoadTokenFromFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "proxmox_token_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	tokenPath := filepath.Join(tmpDir, "test_token.json")
	originalToken := &TokenConfig{
		TokenID:   "test@pve!testtoken",
		Secret:    "testsecret123",
		CreatedAt: "2024-01-15T10:00:00Z",
	}

	// Save token
	if err := saveTokenToFile(tokenPath, originalToken); err != nil {
		t.Fatalf("saveTokenToFile failed: %v", err)
	}

	// Check file permissions
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatalf("failed to stat token file: %v", err)
	}
	// On Unix-like systems, verify permissions are 0600
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}

	// Load token
	loadedToken, err := loadTokenFromFile(tokenPath)
	if err != nil {
		t.Fatalf("loadTokenFromFile failed: %v", err)
	}

	if loadedToken.TokenID != originalToken.TokenID {
		t.Errorf("TokenID = %s, want %s", loadedToken.TokenID, originalToken.TokenID)
	}
	if loadedToken.Secret != originalToken.Secret {
		t.Errorf("Secret = %s, want %s", loadedToken.Secret, originalToken.Secret)
	}
	if loadedToken.CreatedAt != originalToken.CreatedAt {
		t.Errorf("CreatedAt = %s, want %s", loadedToken.CreatedAt, originalToken.CreatedAt)
	}
}

func TestLoadTokenFromFileErrors(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "proxmox_token_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Non-existent file
	_, err = loadTokenFromFile(filepath.Join(tmpDir, "nonexistent.json"))
	if err == nil {
		t.Error("loadTokenFromFile should fail for non-existent file")
	}

	// Invalid JSON
	invalidJSONPath := filepath.Join(tmpDir, "invalid.json")
	if err := os.WriteFile(invalidJSONPath, []byte("not json"), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	_, err = loadTokenFromFile(invalidJSONPath)
	if err == nil {
		t.Error("loadTokenFromFile should fail for invalid JSON")
	}

	// Valid JSON but missing required fields
	emptyTokenPath := filepath.Join(tmpDir, "empty.json")
	if err := os.WriteFile(emptyTokenPath, []byte(`{"token_id":"","secret":""}`), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	_, err = loadTokenFromFile(emptyTokenPath)
	if err == nil {
		t.Error("loadTokenFromFile should fail for empty token fields")
	}
}

func TestHasToken(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "proxmox_token_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// No token file
	if HasToken(tmpDir) {
		t.Error("HasToken should return false when no token file exists")
	}

	// Create token file
	tokenPath := filepath.Join(tmpDir, tokenConfigFile)
	if err := os.WriteFile(tokenPath, []byte(`{"token_id":"test","secret":"secret"}`), 0600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	if !HasToken(tmpDir) {
		t.Error("HasToken should return true when token file exists")
	}
}

func TestClearCachedToken(t *testing.T) {
	// Just verify it doesn't panic
	ClearCachedToken()
	ClearCachedToken() // Call twice to ensure idempotent
}

func TestLoadToken(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "proxmox_token_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Clear any cached token
	ClearCachedToken()

	// No token file should return nil
	if token := LoadToken(tmpDir); token != nil {
		t.Error("LoadToken should return nil when no token file exists")
	}

	// Create token file
	tokenPath := filepath.Join(tmpDir, tokenConfigFile)
	tokenData := `{"token_id":"root@pam!test","secret":"testsecret","created_at":"2024-01-15T10:00:00Z"}`
	if err := os.WriteFile(tokenPath, []byte(tokenData), 0600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	// Clear cache again
	ClearCachedToken()

	// Now LoadToken should return the token
	token := LoadToken(tmpDir)
	if token == nil {
		t.Fatal("LoadToken should return token when file exists")
	}
	if token.TokenID != "root@pam!test" {
		t.Errorf("TokenID = %s, want root@pam!test", token.TokenID)
	}
}

// Policy types tests

func TestPolicyActionTypeConstants(t *testing.T) {
	tests := []struct {
		action   PolicyActionType
		expected string
	}{
		{PolicyActionBackup, "backup"},
		{PolicyActionSnapshot, "snapshot"},
		{PolicyActionPruneBackups, "prune_backups"},
		{PolicyActionCleanStorage, "clean_storage"},
		{PolicyActionHACheck, "ha_check"},
		{PolicyActionReplication, "replication_check"},
	}

	for _, tt := range tests {
		if string(tt.action) != tt.expected {
			t.Errorf("PolicyActionType %v = %s, want %s", tt.action, string(tt.action), tt.expected)
		}
	}
}

func TestBackupModeConstants(t *testing.T) {
	if string(BackupModeSnapshot) != "snapshot" {
		t.Errorf("BackupModeSnapshot = %s, want snapshot", string(BackupModeSnapshot))
	}
	if string(BackupModeStop) != "stop" {
		t.Errorf("BackupModeStop = %s, want stop", string(BackupModeStop))
	}
	if string(BackupModeSuspend) != "suspend" {
		t.Errorf("BackupModeSuspend = %s, want suspend", string(BackupModeSuspend))
	}
}

func TestCompressionTypeConstants(t *testing.T) {
	if string(CompressionNone) != "none" {
		t.Errorf("CompressionNone = %s, want none", string(CompressionNone))
	}
	if string(CompressionLZO) != "lzo" {
		t.Errorf("CompressionLZO = %s, want lzo", string(CompressionLZO))
	}
	if string(CompressionGZIP) != "gzip" {
		t.Errorf("CompressionGZIP = %s, want gzip", string(CompressionGZIP))
	}
	if string(CompressionZSTD) != "zstd" {
		t.Errorf("CompressionZSTD = %s, want zstd", string(CompressionZSTD))
	}
}

func TestDefaultPolicyTimeout(t *testing.T) {
	if defaultPolicyTimeout != 10*time.Minute {
		t.Errorf("defaultPolicyTimeout = %v, want 10m", defaultPolicyTimeout)
	}
}

func TestBackupRequest(t *testing.T) {
	req := BackupRequest{
		VMIDs:       []uint64{100, 101, 102},
		Storage:     "local-zfs",
		Mode:        BackupModeSnapshot,
		Compress:    CompressionZSTD,
		MaxFiles:    5,
		MailTo:      "admin@example.com",
		Notes:       "Daily backup",
		All:         false,
		ExcludeVMID: []uint64{999},
		Timeout:     3600,
	}

	if len(req.VMIDs) != 3 {
		t.Errorf("len(VMIDs) = %d, want 3", len(req.VMIDs))
	}
	if req.Storage != "local-zfs" {
		t.Errorf("Storage = %s, want local-zfs", req.Storage)
	}
	if req.Mode != BackupModeSnapshot {
		t.Errorf("Mode = %s, want snapshot", req.Mode)
	}
	if req.Compress != CompressionZSTD {
		t.Errorf("Compress = %s, want zstd", req.Compress)
	}
	if req.MaxFiles != 5 {
		t.Errorf("MaxFiles = %d, want 5", req.MaxFiles)
	}
	if req.Timeout != 3600 {
		t.Errorf("Timeout = %d, want 3600", req.Timeout)
	}
}

func TestBackupResult(t *testing.T) {
	result := BackupResult{
		Success:     true,
		VMID:        100,
		Type:        ResourceTypeVM,
		TaskID:      "UPID:node1:00001234:12345678:12345678:vzdump:100:root@pam:",
		Storage:     "local-zfs",
		BackupFile:  "vzdump-qemu-100-2024_01_15-10_00_00.vma.zst",
		Size:        10737418240,
		StartedAt:   "2024-01-15T10:00:00Z",
		CompletedAt: "2024-01-15T10:15:00Z",
		Duration:    900000,
	}

	if !result.Success {
		t.Error("Success should be true")
	}
	if result.VMID != 100 {
		t.Errorf("VMID = %d, want 100", result.VMID)
	}
	if result.Type != ResourceTypeVM {
		t.Errorf("Type = %s, want vm", result.Type)
	}
	if result.Size != 10737418240 {
		t.Errorf("Size = %d, want 10737418240", result.Size)
	}
	if result.Duration != 900000 {
		t.Errorf("Duration = %d, want 900000", result.Duration)
	}
}

func TestSnapshotRequest(t *testing.T) {
	req := SnapshotRequest{
		VMID:        100,
		Type:        ResourceTypeVM,
		Name:        "before-upgrade",
		Description: "Snapshot before system upgrade",
		IncludeRAM:  true,
	}

	if req.VMID != 100 {
		t.Errorf("VMID = %d, want 100", req.VMID)
	}
	if req.Type != ResourceTypeVM {
		t.Errorf("Type = %s, want vm", req.Type)
	}
	if req.Name != "before-upgrade" {
		t.Errorf("Name = %s, want before-upgrade", req.Name)
	}
	if !req.IncludeRAM {
		t.Error("IncludeRAM should be true")
	}
}

func TestSnapshotResult(t *testing.T) {
	result := SnapshotResult{
		Success:   true,
		VMID:      100,
		Type:      ResourceTypeVM,
		Name:      "before-upgrade",
		TaskID:    "UPID:node1:00001234:12345678:12345678:qmsnapshot:100:root@pam:",
		StartedAt: "2024-01-15T10:00:00Z",
		Duration:  5000,
	}

	if !result.Success {
		t.Error("Success should be true")
	}
	if result.Name != "before-upgrade" {
		t.Errorf("Name = %s, want before-upgrade", result.Name)
	}
	if result.Duration != 5000 {
		t.Errorf("Duration = %d, want 5000", result.Duration)
	}
}

func TestPruneRequest(t *testing.T) {
	req := PruneRequest{
		Storage:     "local-zfs",
		VMIDs:       []uint64{100, 101},
		KeepLast:    5,
		KeepHourly:  24,
		KeepDaily:   7,
		KeepWeekly:  4,
		KeepMonthly: 6,
		KeepYearly:  2,
		DryRun:      true,
	}

	if req.Storage != "local-zfs" {
		t.Errorf("Storage = %s, want local-zfs", req.Storage)
	}
	if req.KeepLast != 5 {
		t.Errorf("KeepLast = %d, want 5", req.KeepLast)
	}
	if req.KeepDaily != 7 {
		t.Errorf("KeepDaily = %d, want 7", req.KeepDaily)
	}
	if !req.DryRun {
		t.Error("DryRun should be true")
	}
}

func TestPruneResult(t *testing.T) {
	result := PruneResult{
		Success:       true,
		Storage:       "local-zfs",
		DeletedCount:  3,
		DeletedFiles:  []string{"backup1.vma", "backup2.vma", "backup3.vma"},
		ReclaimedSize: 32212254720,
		DryRun:        false,
	}

	if !result.Success {
		t.Error("Success should be true")
	}
	if result.DeletedCount != 3 {
		t.Errorf("DeletedCount = %d, want 3", result.DeletedCount)
	}
	if len(result.DeletedFiles) != 3 {
		t.Errorf("len(DeletedFiles) = %d, want 3", len(result.DeletedFiles))
	}
	if result.ReclaimedSize != 32212254720 {
		t.Errorf("ReclaimedSize = %d, want 32212254720", result.ReclaimedSize)
	}
}

func TestHAStatusResult(t *testing.T) {
	result := HAStatusResult{
		Success:   true,
		Enabled:   true,
		Quorum:    true,
		NodeCount: 3,
		Nodes: []HANodeStatus{
			{Name: "pve1", Status: "online", Online: true},
			{Name: "pve2", Status: "online", Online: true},
			{Name: "pve3", Status: "online", Online: true},
		},
		Resources: []HAResourceStatus{
			{SID: "vm:100", Type: "vm", VMID: 100, Node: "pve1", State: "started", Status: ""},
		},
	}

	if !result.Success {
		t.Error("Success should be true")
	}
	if !result.Enabled {
		t.Error("Enabled should be true")
	}
	if !result.Quorum {
		t.Error("Quorum should be true")
	}
	if result.NodeCount != 3 {
		t.Errorf("NodeCount = %d, want 3", result.NodeCount)
	}
	if len(result.Nodes) != 3 {
		t.Errorf("len(Nodes) = %d, want 3", len(result.Nodes))
	}
}

func TestHANodeStatus(t *testing.T) {
	node := HANodeStatus{
		Name:   "pve1",
		Status: "online",
		Online: true,
	}

	if node.Name != "pve1" {
		t.Errorf("Name = %s, want pve1", node.Name)
	}
	if node.Status != "online" {
		t.Errorf("Status = %s, want online", node.Status)
	}
	if !node.Online {
		t.Error("Online should be true")
	}
}

func TestHAResourceStatus(t *testing.T) {
	res := HAResourceStatus{
		SID:    "vm:100",
		Type:   "vm",
		VMID:   100,
		Node:   "pve1",
		State:  "started",
		Status: "active",
	}

	if res.SID != "vm:100" {
		t.Errorf("SID = %s, want vm:100", res.SID)
	}
	if res.VMID != 100 {
		t.Errorf("VMID = %d, want 100", res.VMID)
	}
	if res.Node != "pve1" {
		t.Errorf("Node = %s, want pve1", res.Node)
	}
}

func TestReplicationStatusResult(t *testing.T) {
	result := ReplicationStatusResult{
		Success: true,
		Jobs: []ReplicationJob{
			{
				ID:       "100-0",
				VMID:     100,
				Target:   "pve2",
				Schedule: "*/15 * * * *",
				LastSync: "2024-01-15T10:00:00Z",
				NextSync: "2024-01-15T10:15:00Z",
				Status:   "OK",
				Duration: 30000,
			},
		},
	}

	if !result.Success {
		t.Error("Success should be true")
	}
	if len(result.Jobs) != 1 {
		t.Errorf("len(Jobs) = %d, want 1", len(result.Jobs))
	}
	if result.Jobs[0].ID != "100-0" {
		t.Errorf("Jobs[0].ID = %s, want 100-0", result.Jobs[0].ID)
	}
}

func TestReplicationJob(t *testing.T) {
	job := ReplicationJob{
		ID:       "100-0",
		VMID:     100,
		Target:   "pve2",
		Schedule: "*/15 * * * *",
		LastSync: "2024-01-15T10:00:00Z",
		NextSync: "2024-01-15T10:15:00Z",
		Status:   "OK",
		Duration: 30000,
	}

	if job.ID != "100-0" {
		t.Errorf("ID = %s, want 100-0", job.ID)
	}
	if job.VMID != 100 {
		t.Errorf("VMID = %d, want 100", job.VMID)
	}
	if job.Target != "pve2" {
		t.Errorf("Target = %s, want pve2", job.Target)
	}
	if job.Schedule != "*/15 * * * *" {
		t.Errorf("Schedule = %s, want */15 * * * *", job.Schedule)
	}
	if job.Status != "OK" {
		t.Errorf("Status = %s, want OK", job.Status)
	}
}

func TestStorageCleanRequest(t *testing.T) {
	req := StorageCleanRequest{
		Storage:       "local-zfs",
		CleanOrphaned: true,
		CleanUnused:   true,
		DryRun:        true,
	}

	if req.Storage != "local-zfs" {
		t.Errorf("Storage = %s, want local-zfs", req.Storage)
	}
	if !req.CleanOrphaned {
		t.Error("CleanOrphaned should be true")
	}
	if !req.CleanUnused {
		t.Error("CleanUnused should be true")
	}
	if !req.DryRun {
		t.Error("DryRun should be true")
	}
}

func TestStorageCleanResult(t *testing.T) {
	result := StorageCleanResult{
		Success:       true,
		Storage:       "local-zfs",
		CleanedCount:  5,
		CleanedItems:  []string{"vm-100-disk-0", "vm-101-disk-1"},
		ReclaimedSize: 53687091200,
		DryRun:        false,
	}

	if !result.Success {
		t.Error("Success should be true")
	}
	if result.CleanedCount != 5 {
		t.Errorf("CleanedCount = %d, want 5", result.CleanedCount)
	}
	if result.ReclaimedSize != 53687091200 {
		t.Errorf("ReclaimedSize = %d, want 53687091200", result.ReclaimedSize)
	}
}

func TestPolicyConfig(t *testing.T) {
	config := PolicyConfig{
		Action:         PolicyActionBackup,
		BackupStorage:  "local-zfs",
		BackupMode:     BackupModeSnapshot,
		BackupCompress: CompressionZSTD,
		BackupMaxFiles: 5,
		SnapshotName:   "test-snapshot",
		SnapshotDesc:   "Test snapshot description",
		VMIDs:          []uint64{100, 101},
		All:            false,
		ExcludeVMIDs:   []uint64{999},
		ResourceType:   ResourceTypeVM,
		KeepLast:       5,
		KeepDaily:      7,
		KeepWeekly:     4,
		KeepMonthly:    6,
		Storage:        "local-zfs",
		CleanOrphaned:  true,
		DryRun:         false,
		Timeout:        3600,
	}

	if config.Action != PolicyActionBackup {
		t.Errorf("Action = %s, want backup", config.Action)
	}
	if config.BackupStorage != "local-zfs" {
		t.Errorf("BackupStorage = %s, want local-zfs", config.BackupStorage)
	}
	if config.BackupMode != BackupModeSnapshot {
		t.Errorf("BackupMode = %s, want snapshot", config.BackupMode)
	}
	if len(config.VMIDs) != 2 {
		t.Errorf("len(VMIDs) = %d, want 2", len(config.VMIDs))
	}
	if config.Timeout != 3600 {
		t.Errorf("Timeout = %d, want 3600", config.Timeout)
	}
}

func TestPolicyResult(t *testing.T) {
	result := PolicyResult{
		Action:    PolicyActionBackup,
		Success:   true,
		Results:   []BackupResult{{Success: true, VMID: 100}},
		StartedAt: "2024-01-15T10:00:00Z",
		Duration:  900000,
	}

	if result.Action != PolicyActionBackup {
		t.Errorf("Action = %s, want backup", result.Action)
	}
	if !result.Success {
		t.Error("Success should be true")
	}
	if result.Duration != 900000 {
		t.Errorf("Duration = %d, want 900000", result.Duration)
	}
}

func TestBackupInfoStruct(t *testing.T) {
	info := BackupInfo{
		Volid: "local-zfs:backup/vzdump-qemu-100-2024_01_15-10_00_00.vma.zst",
		VMID:  100,
		CTime: 1705312800,
		Size:  10737418240,
	}

	if info.Volid == "" {
		t.Error("Volid should not be empty")
	}
	if info.VMID != 100 {
		t.Errorf("VMID = %d, want 100", info.VMID)
	}
	if info.CTime != 1705312800 {
		t.Errorf("CTime = %d, want 1705312800", info.CTime)
	}
	if info.Size != 10737418240 {
		t.Errorf("Size = %d, want 10737418240", info.Size)
	}
}
