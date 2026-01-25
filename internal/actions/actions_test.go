package actions

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCommandResult(t *testing.T) {
	result := CommandResult{
		Command:     "ls -la",
		ExitCode:    0,
		Stdout:      "file1\nfile2\n",
		Stderr:      "",
		Duration:    100,
		IsSensitive: false,
	}

	if result.Command != "ls -la" {
		t.Error("Command not set correctly")
	}
	if result.ExitCode != 0 {
		t.Error("ExitCode not set correctly")
	}
	if result.Duration != 100 {
		t.Error("Duration not set correctly")
	}
}

func TestScriptResult(t *testing.T) {
	result := ScriptResult{
		ScriptType: "bash",
		ExitCode:   0,
		Stdout:     "output",
		Stderr:     "",
		Duration:   50,
	}

	if result.ScriptType != "bash" {
		t.Error("ScriptType not set correctly")
	}
	if result.ExitCode != 0 {
		t.Error("ExitCode not set correctly")
	}
}

func TestContainsDangerousScriptPattern(t *testing.T) {
	tests := []struct {
		name      string
		script    string
		dangerous bool
	}{
		{"safe script", "echo hello", false},
		{"safe rm", "rm file.txt", false},
		{"rm rf root", "rm -rf /", true},
		{"rm fr root", "rm -fr /", true},
		{"fork bomb", ":(){:|:&};:", true},
		{"dd overwrite", "dd if=/dev/zero of=/dev/sda", true},
		{"mkfs", "mkfs.ext4 /dev/sda1", true},
		{"overwrite disk", "> /dev/sda", true},
		{"chmod 777 root", "chmod -R 777 /", true},
		{"case insensitive", "RM -RF /", true},
		{"nested in command", "echo 'rm -rf /' | bash", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsDangerousScriptPattern(tt.script)
			if got != tt.dangerous {
				t.Errorf("containsDangerousScriptPattern(%q) = %v, want %v", tt.script, got, tt.dangerous)
			}
		})
	}
}

func TestTruncateOutput(t *testing.T) {
	// Short output
	short := "short output"
	if truncateOutput(short) != short {
		t.Error("short output should not be truncated")
	}

	// Exactly max size
	exact := strings.Repeat("a", MaxOutputSize)
	if truncateOutput(exact) != exact {
		t.Error("exact size output should not be truncated")
	}

	// Longer than max
	long := strings.Repeat("b", MaxOutputSize+100)
	result := truncateOutput(long)
	if len(result) >= len(long) {
		t.Error("long output should be truncated")
	}
	if !strings.Contains(result, "[output truncated") {
		t.Error("truncated output should contain truncation message")
	}
}

func TestExtractBaseCommand(t *testing.T) {
	tests := []struct {
		command string
		base    string
	}{
		{"ls -la /tmp", "ls"},
		{"echo hello world", "echo"},
		{"grep", "grep"},
		{"", ""},
		{"   ", ""},
		{"/usr/bin/ls -la", "/usr/bin/ls"},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got := extractBaseCommand(tt.command)
			if got != tt.base {
				t.Errorf("extractBaseCommand(%q) = %q, want %q", tt.command, got, tt.base)
			}
		})
	}
}

func TestGetShell(t *testing.T) {
	shell := GetShell()
	if shell == "" {
		t.Error("GetShell should return a shell")
	}

	if runtime.GOOS == "windows" {
		if shell != "cmd" {
			t.Errorf("on Windows, GetShell = %s, want cmd", shell)
		}
	} else {
		if !strings.HasPrefix(shell, "/") {
			t.Errorf("on Unix, GetShell should return absolute path: %s", shell)
		}
	}
}

func TestGetShellArgs(t *testing.T) {
	args := GetShellArgs()
	if len(args) == 0 {
		t.Error("GetShellArgs should return arguments")
	}

	if runtime.GOOS == "windows" {
		if args[0] != "/C" {
			t.Errorf("on Windows, GetShellArgs = %v, want [/C]", args)
		}
	} else {
		if args[0] != "-c" {
			t.Errorf("on Unix, GetShellArgs = %v, want [-c]", args)
		}
	}
}

func TestConstants(t *testing.T) {
	if DefaultCommandTimeout <= 0 {
		t.Error("DefaultCommandTimeout should be positive")
	}
	if MaxOutputSize <= 0 {
		t.Error("MaxOutputSize should be positive")
	}
	if MaxOutputSize != 1024*1024 {
		t.Errorf("MaxOutputSize = %d, want %d", MaxOutputSize, 1024*1024)
	}
}

// Log buffer tests

func TestNewLogBuffer(t *testing.T) {
	buffer := NewLogBuffer(100)
	if buffer == nil {
		t.Fatal("NewLogBuffer should return non-nil buffer")
	}
	if buffer.size != 100 {
		t.Errorf("size = %d, want 100", buffer.size)
	}
	if buffer.count != 0 {
		t.Errorf("count = %d, want 0", buffer.count)
	}
}

func TestLogBufferAdd(t *testing.T) {
	buffer := NewLogBuffer(10)
	entry := LogEntry{
		Time:    "2026-01-25T10:00:00Z",
		Level:   "info",
		Message: "test message",
	}

	buffer.Add(entry)
	if buffer.count != 1 {
		t.Errorf("count = %d, want 1", buffer.count)
	}

	// Add more entries than buffer size to test circular behavior
	for i := 0; i < 15; i++ {
		buffer.Add(entry)
	}
	if buffer.count != 10 {
		t.Errorf("count = %d, want 10 (buffer size)", buffer.count)
	}
}

func TestLogBufferGetRecent(t *testing.T) {
	buffer := NewLogBuffer(100)

	// Add some entries
	for i := 0; i < 5; i++ {
		buffer.Add(LogEntry{
			Time:    "2026-01-25T10:00:00Z",
			Level:   "info",
			Message: "message " + string(rune('0'+i)),
		})
	}

	// Get recent with no time filter
	entries := buffer.GetRecent(time.Time{}, 10)
	if len(entries) != 5 {
		t.Errorf("len(entries) = %d, want 5", len(entries))
	}

	// Get with limit
	entries = buffer.GetRecent(time.Time{}, 3)
	if len(entries) != 3 {
		t.Errorf("len(entries) = %d, want 3", len(entries))
	}
}

func TestLogBufferCount(t *testing.T) {
	buffer := NewLogBuffer(50)
	if buffer.Count() != 0 {
		t.Errorf("Count = %d, want 0", buffer.Count())
	}

	buffer.Add(LogEntry{Level: "info", Message: "test"})
	if buffer.Count() != 1 {
		t.Errorf("Count = %d, want 1", buffer.Count())
	}
}

func TestLogBufferSetPushCallback(t *testing.T) {
	buffer := NewLogBuffer(10)
	called := false
	buffer.SetPushCallback(func(logs []LogEntry) {
		called = true
	})

	if buffer.pushCallback == nil {
		t.Error("pushCallback should be set")
	}
	// Note: callback is only called when threshold is reached
	_ = called
}

func TestLogBufferSetPushThreshold(t *testing.T) {
	buffer := NewLogBuffer(10)
	buffer.SetPushThreshold(100)
	if buffer.pushThreshold != 100 {
		t.Errorf("pushThreshold = %d, want 100", buffer.pushThreshold)
	}
}

func TestGetLogBuffer(t *testing.T) {
	buffer := GetLogBuffer()
	if buffer == nil {
		t.Fatal("GetLogBuffer should return non-nil buffer")
	}

	// Verify singleton
	buffer2 := GetLogBuffer()
	if buffer != buffer2 {
		t.Error("GetLogBuffer should return same instance")
	}
}

func TestAddLogEntry(t *testing.T) {
	// AddLogEntry should not panic
	AddLogEntry(LogEntry{
		Time:    "2026-01-25T10:00:00Z",
		Level:   "info",
		Message: "test",
	})
}

func TestLogEntry(t *testing.T) {
	entry := LogEntry{
		Time:    "2026-01-25T10:00:00Z",
		Level:   "error",
		Source:  "test-source",
		Message: "test message",
		Details: map[string]interface{}{
			"key": "value",
		},
	}

	if entry.Time != "2026-01-25T10:00:00Z" {
		t.Errorf("Time = %s, want 2026-01-25T10:00:00Z", entry.Time)
	}
	if entry.Level != "error" {
		t.Errorf("Level = %s, want error", entry.Level)
	}
	if entry.Source != "test-source" {
		t.Errorf("Source = %s, want test-source", entry.Source)
	}
	if entry.Message != "test message" {
		t.Errorf("Message = %s, want 'test message'", entry.Message)
	}
	if entry.Details["key"] != "value" {
		t.Error("Details key not set correctly")
	}
}

// Docker struct tests

func TestDockerContainerStruct(t *testing.T) {
	container := DockerContainer{
		ID:        "abc123",
		Name:      "test-container",
		Image:     "nginx:latest",
		ImageID:   "sha256:abc123",
		Command:   "nginx -g 'daemon off;'",
		Created:   1706000000,
		CreatedAt: "2024-01-23T10:00:00Z",
		State:     "running",
		Status:    "Up 2 days",
		Networks:  []string{"bridge", "custom"},
	}

	if container.ID != "abc123" {
		t.Errorf("ID = %s, want abc123", container.ID)
	}
	if container.Name != "test-container" {
		t.Errorf("Name = %s, want test-container", container.Name)
	}
	if container.State != "running" {
		t.Errorf("State = %s, want running", container.State)
	}
	if len(container.Networks) != 2 {
		t.Errorf("len(Networks) = %d, want 2", len(container.Networks))
	}
}

func TestDockerPortStruct(t *testing.T) {
	port := DockerPort{
		IP:          "0.0.0.0",
		PrivatePort: 80,
		PublicPort:  8080,
		Type:        "tcp",
	}

	if port.IP != "0.0.0.0" {
		t.Errorf("IP = %s, want 0.0.0.0", port.IP)
	}
	if port.PrivatePort != 80 {
		t.Errorf("PrivatePort = %d, want 80", port.PrivatePort)
	}
	if port.PublicPort != 8080 {
		t.Errorf("PublicPort = %d, want 8080", port.PublicPort)
	}
	if port.Type != "tcp" {
		t.Errorf("Type = %s, want tcp", port.Type)
	}
}

func TestDockerImageStruct(t *testing.T) {
	image := DockerImage{
		ID:          "sha256:abc123",
		RepoTags:    []string{"nginx:latest", "nginx:1.25"},
		RepoDigests: []string{"nginx@sha256:def456"},
		Created:     1706000000,
		Size:        187000000,
		VirtualSize: 187000000,
	}

	if image.ID != "sha256:abc123" {
		t.Errorf("ID = %s, want sha256:abc123", image.ID)
	}
	if len(image.RepoTags) != 2 {
		t.Errorf("len(RepoTags) = %d, want 2", len(image.RepoTags))
	}
	if image.Size != 187000000 {
		t.Errorf("Size = %d, want 187000000", image.Size)
	}
}

func TestDockerVolumeStruct(t *testing.T) {
	volume := DockerVolume{
		Name:       "my-volume",
		Driver:     "local",
		Mountpoint: "/var/lib/docker/volumes/my-volume/_data",
		CreatedAt:  "2024-01-23T10:00:00Z",
		Scope:      "local",
	}

	if volume.Name != "my-volume" {
		t.Errorf("Name = %s, want my-volume", volume.Name)
	}
	if volume.Driver != "local" {
		t.Errorf("Driver = %s, want local", volume.Driver)
	}
	if volume.Scope != "local" {
		t.Errorf("Scope = %s, want local", volume.Scope)
	}
}

func TestDockerNetworkStruct(t *testing.T) {
	network := DockerNetwork{
		ID:         "abc123",
		Name:       "my-network",
		Driver:     "bridge",
		Scope:      "local",
		EnableIPv6: false,
		Internal:   false,
		Attachable: true,
	}

	if network.ID != "abc123" {
		t.Errorf("ID = %s, want abc123", network.ID)
	}
	if network.Name != "my-network" {
		t.Errorf("Name = %s, want my-network", network.Name)
	}
	if network.Driver != "bridge" {
		t.Errorf("Driver = %s, want bridge", network.Driver)
	}
}

func TestDockerInfoStruct(t *testing.T) {
	info := DockerInfo{
		Available:         true,
		Version:           "24.0.7",
		APIVersion:        "1.44",
		OS:                "Docker Desktop",
		Arch:              "aarch64",
		KernelVersion:     "6.4.16-linuxkit",
		Containers:        10,
		ContainersRunning: 5,
		ContainersPaused:  1,
		ContainersStopped: 4,
		Images:            25,
	}

	if !info.Available {
		t.Error("Available should be true")
	}
	if info.Version != "24.0.7" {
		t.Errorf("Version = %s, want 24.0.7", info.Version)
	}
	if info.Containers != 10 {
		t.Errorf("Containers = %d, want 10", info.Containers)
	}
	if info.ContainersRunning != 5 {
		t.Errorf("ContainersRunning = %d, want 5", info.ContainersRunning)
	}
}

func TestDockerContainerStatsStruct(t *testing.T) {
	stats := DockerContainerStats{
		ContainerID:   "abc123",
		Name:          "test",
		CPUPercent:    15.5,
		MemoryUsage:   1073741824,
		MemoryLimit:   4294967296,
		MemoryPercent: 25.0,
		NetworkRx:     1000000,
		NetworkTx:     500000,
		BlockRead:     50000000,
		BlockWrite:    25000000,
		PIDs:          15,
	}

	if stats.ContainerID != "abc123" {
		t.Errorf("ContainerID = %s, want abc123", stats.ContainerID)
	}
	if stats.CPUPercent != 15.5 {
		t.Errorf("CPUPercent = %f, want 15.5", stats.CPUPercent)
	}
	if stats.MemoryPercent != 25.0 {
		t.Errorf("MemoryPercent = %f, want 25.0", stats.MemoryPercent)
	}
	if stats.PIDs != 15 {
		t.Errorf("PIDs = %d, want 15", stats.PIDs)
	}
}

func TestDockerContainerLogsStruct(t *testing.T) {
	logs := DockerContainerLogs{
		ContainerID: "abc123",
		Logs:        []string{"line 1", "line 2", "line 3"},
		Timestamps:  true,
		Tail:        100,
	}

	if logs.ContainerID != "abc123" {
		t.Errorf("ContainerID = %s, want abc123", logs.ContainerID)
	}
	if len(logs.Logs) != 3 {
		t.Errorf("len(Logs) = %d, want 3", len(logs.Logs))
	}
	if !logs.Timestamps {
		t.Error("Timestamps should be true")
	}
	if logs.Tail != 100 {
		t.Errorf("Tail = %d, want 100", logs.Tail)
	}
}

func TestDockerPruneResultStruct(t *testing.T) {
	result := DockerPruneResult{
		Type:           "images",
		ReclaimedSpace: 1073741824,
		DeletedItems:   []string{"sha256:abc", "sha256:def"},
	}

	if result.Type != "images" {
		t.Errorf("Type = %s, want images", result.Type)
	}
	if result.ReclaimedSpace != 1073741824 {
		t.Errorf("ReclaimedSpace = %d, want 1073741824", result.ReclaimedSpace)
	}
	if len(result.DeletedItems) != 2 {
		t.Errorf("len(DeletedItems) = %d, want 2", len(result.DeletedItems))
	}
}

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"empty", "", 0},
		{"single port", "80/tcp", 1},
		{"mapped port", "0.0.0.0:8080->80/tcp", 1},
		{"multiple ports", "0.0.0.0:8080->80/tcp, 443/tcp", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports := parsePorts(tt.input)
			if len(ports) != tt.expected {
				t.Errorf("parsePorts(%q) returned %d ports, want %d", tt.input, len(ports), tt.expected)
			}
		})
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"", 0},
		{"100B", 100},
		{"1KB", 1024},
		{"1MB", 1024 * 1024},
		{"1GB", 1024 * 1024 * 1024},
		{"1.5GB", int64(1.5 * 1024 * 1024 * 1024)},
		{"invalid", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseSize(tt.input)
			if result != tt.expected {
				t.Errorf("parseSize(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseDeletedItems(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"empty", "", 0},
		{"total only", "Total reclaimed space: 0B", 0},
		{"single hash", "abc123def456", 1},
		{"multiple hashes", "abc123def456\n789ghi012jkl", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items := parseDeletedItems(tt.input)
			if len(items) != tt.expected {
				t.Errorf("parseDeletedItems returned %d items, want %d", len(items), tt.expected)
			}
		})
	}
}

func TestGetString(t *testing.T) {
	m := map[string]interface{}{
		"str":    "value",
		"number": 42,
		"bool":   true,
	}

	if getString(m, "str") != "value" {
		t.Error("getString for 'str' failed")
	}
	if getString(m, "number") != "" {
		t.Error("getString for non-string should return empty")
	}
	if getString(m, "missing") != "" {
		t.Error("getString for missing key should return empty")
	}
}

func TestGetInt(t *testing.T) {
	m := map[string]interface{}{
		"float":  42.0,
		"int":    42,
		"string": "42",
	}

	if getInt(m, "float") != 42 {
		t.Error("getInt for float64 failed")
	}
	if getInt(m, "int") != 42 {
		t.Error("getInt for int failed")
	}
	if getInt(m, "string") != 0 {
		t.Error("getInt for string should return 0")
	}
	if getInt(m, "missing") != 0 {
		t.Error("getInt for missing key should return 0")
	}
}

func TestGetLogDirectory(t *testing.T) {
	dir := getLogDirectory()
	if dir == "" {
		t.Error("getLogDirectory should return non-empty string")
	}
	// Platform-specific paths
	switch runtime.GOOS {
	case "windows":
		if !strings.Contains(dir, "SlimRMM") {
			t.Errorf("Windows log dir should contain SlimRMM: %s", dir)
		}
	case "darwin":
		if dir != "/Library/Logs/SlimRMM" {
			t.Errorf("macOS log dir = %s, want /Library/Logs/SlimRMM", dir)
		}
	default:
		if dir != "/var/log/slimrmm" {
			t.Errorf("Linux log dir = %s, want /var/log/slimrmm", dir)
		}
	}
}

func TestIsDockerAvailable(t *testing.T) {
	// Just verify function doesn't panic
	_ = IsDockerAvailable()
}

// File operation struct tests

func TestFileInfoStruct(t *testing.T) {
	fi := FileInfo{
		Name:          "test.txt",
		Path:          "/home/user/test.txt",
		Type:          "file",
		Size:          1024,
		Modified:      "2024-01-25T10:00:00Z",
		Permissions:   "-rw-r--r--",
		Owner:         "user",
		Group:         "staff",
		IsSymlink:     false,
		SymlinkTarget: "",
	}

	if fi.Name != "test.txt" {
		t.Errorf("Name = %s, want test.txt", fi.Name)
	}
	if fi.Path != "/home/user/test.txt" {
		t.Errorf("Path = %s, want /home/user/test.txt", fi.Path)
	}
	if fi.Type != "file" {
		t.Errorf("Type = %s, want file", fi.Type)
	}
	if fi.Size != 1024 {
		t.Errorf("Size = %d, want 1024", fi.Size)
	}
	if fi.Owner != "user" {
		t.Errorf("Owner = %s, want user", fi.Owner)
	}
	if fi.IsSymlink {
		t.Error("IsSymlink should be false")
	}
}

func TestFileInfoSymlink(t *testing.T) {
	fi := FileInfo{
		Name:          "link",
		Path:          "/home/user/link",
		Type:          "file",
		IsSymlink:     true,
		SymlinkTarget: "/home/user/target",
	}

	if !fi.IsSymlink {
		t.Error("IsSymlink should be true")
	}
	if fi.SymlinkTarget != "/home/user/target" {
		t.Errorf("SymlinkTarget = %s, want /home/user/target", fi.SymlinkTarget)
	}
}

func TestFileInfoDirectory(t *testing.T) {
	fi := FileInfo{
		Name: "mydir",
		Path: "/home/user/mydir",
		Type: "directory",
	}

	if fi.Type != "directory" {
		t.Errorf("Type = %s, want directory", fi.Type)
	}
}

func TestListDirResultStruct(t *testing.T) {
	result := ListDirResult{
		CurrentPath: "/home/user",
		Entries: []FileInfo{
			{Name: "file1.txt", Type: "file"},
			{Name: "file2.txt", Type: "file"},
			{Name: "subdir", Type: "directory"},
		},
		Count: 3,
	}

	if result.CurrentPath != "/home/user" {
		t.Errorf("CurrentPath = %s, want /home/user", result.CurrentPath)
	}
	if result.Count != 3 {
		t.Errorf("Count = %d, want 3", result.Count)
	}
	if len(result.Entries) != 3 {
		t.Errorf("len(Entries) = %d, want 3", len(result.Entries))
	}
}

// Transfer struct and constant tests

func TestTransferConstants(t *testing.T) {
	if DefaultChunkSize != 64*1024 {
		t.Errorf("DefaultChunkSize = %d, want %d", DefaultChunkSize, 64*1024)
	}
	if DownloadChunkSize != 1024*1024 {
		t.Errorf("DownloadChunkSize = %d, want %d", DownloadChunkSize, 1024*1024)
	}
	if DirectDownloadLimit != 50*1024*1024 {
		t.Errorf("DirectDownloadLimit = %d, want %d", DirectDownloadLimit, 50*1024*1024)
	}
	if MaxFileSize != 100*1024*1024 {
		t.Errorf("MaxFileSize = %d, want %d", MaxFileSize, 100*1024*1024)
	}
	if SessionTimeout != 30*time.Minute {
		t.Errorf("SessionTimeout = %v, want 30m", SessionTimeout)
	}
	if CleanupInterval != 5*time.Minute {
		t.Errorf("CleanupInterval = %v, want 5m", CleanupInterval)
	}
}

func TestUploadResultStruct(t *testing.T) {
	result := UploadResult{
		Path:     "/uploads/file.zip",
		Size:     1048576,
		Hash:     "abc123def456",
		Duration: 5000,
	}

	if result.Path != "/uploads/file.zip" {
		t.Errorf("Path = %s, want /uploads/file.zip", result.Path)
	}
	if result.Size != 1048576 {
		t.Errorf("Size = %d, want 1048576", result.Size)
	}
	if result.Hash != "abc123def456" {
		t.Errorf("Hash = %s, want abc123def456", result.Hash)
	}
	if result.Duration != 5000 {
		t.Errorf("Duration = %d, want 5000", result.Duration)
	}
}

func TestDownloadResultStruct(t *testing.T) {
	result := DownloadResult{
		Path:       "/files/document.pdf",
		Size:       2097152,
		Hash:       "fedcba987654",
		Content:    "base64content...",
		ChunkCount: 0,
	}

	if result.Path != "/files/document.pdf" {
		t.Errorf("Path = %s, want /files/document.pdf", result.Path)
	}
	if result.Size != 2097152 {
		t.Errorf("Size = %d, want 2097152", result.Size)
	}
	if result.Hash != "fedcba987654" {
		t.Errorf("Hash = %s, want fedcba987654", result.Hash)
	}
	if result.Content != "base64content..." {
		t.Errorf("Content = %s, want base64content...", result.Content)
	}
}

func TestDownloadResultWithChunks(t *testing.T) {
	result := DownloadResult{
		Path:       "/files/large.iso",
		Size:       104857600, // 100 MB
		Hash:       "hash123",
		ChunkCount: 100,
	}

	if result.ChunkCount != 100 {
		t.Errorf("ChunkCount = %d, want 100", result.ChunkCount)
	}
	if result.Content != "" {
		t.Error("Content should be empty for chunked downloads")
	}
}

func TestUploadSessionStruct(t *testing.T) {
	now := time.Now()
	session := UploadSession{
		ID:           "session-123",
		Path:         "/uploads/test.bin",
		TotalSize:    10485760,
		Received:     5242880,
		ChunkCount:   5,
		Hash:         "hash123",
		StartTime:    now,
		LastActivity: now,
	}

	if session.ID != "session-123" {
		t.Errorf("ID = %s, want session-123", session.ID)
	}
	if session.Path != "/uploads/test.bin" {
		t.Errorf("Path = %s, want /uploads/test.bin", session.Path)
	}
	if session.TotalSize != 10485760 {
		t.Errorf("TotalSize = %d, want 10485760", session.TotalSize)
	}
	if session.Received != 5242880 {
		t.Errorf("Received = %d, want 5242880", session.Received)
	}
	if session.ChunkCount != 5 {
		t.Errorf("ChunkCount = %d, want 5", session.ChunkCount)
	}
}

func TestNewUploadManager(t *testing.T) {
	mgr := NewUploadManager()
	if mgr == nil {
		t.Fatal("NewUploadManager should return non-nil")
	}
	if mgr.sessions == nil {
		t.Error("sessions map should be initialized")
	}
	if mgr.stopChan == nil {
		t.Error("stopChan should be initialized")
	}
}

func TestUploadManagerStop(t *testing.T) {
	mgr := NewUploadManager()
	// Should not panic when called multiple times
	mgr.Stop()
	mgr.Stop()
}

func TestUploadManagerStartCleanup(t *testing.T) {
	mgr := NewUploadManager()
	// Start cleanup and immediately stop to avoid goroutine leak
	mgr.StartCleanup()
	mgr.Stop()
}

// Command result default values

func TestCommandResultDefaults(t *testing.T) {
	result := CommandResult{}

	if result.Command != "" {
		t.Error("default Command should be empty")
	}
	if result.ExitCode != 0 {
		t.Errorf("default ExitCode = %d, want 0", result.ExitCode)
	}
	if result.Stdout != "" {
		t.Error("default Stdout should be empty")
	}
	if result.IsSensitive {
		t.Error("default IsSensitive should be false")
	}
}

func TestScriptResultDefaults(t *testing.T) {
	result := ScriptResult{}

	if result.ScriptType != "" {
		t.Error("default ScriptType should be empty")
	}
	if result.ExitCode != 0 {
		t.Errorf("default ExitCode = %d, want 0", result.ExitCode)
	}
}

// Additional Docker struct tests

func TestDockerContainerDefaults(t *testing.T) {
	container := DockerContainer{}

	if container.ID != "" {
		t.Error("default ID should be empty")
	}
	if container.State != "" {
		t.Error("default State should be empty")
	}
	if container.Networks != nil {
		t.Error("default Networks should be nil")
	}
}

func TestDockerImageDefaults(t *testing.T) {
	image := DockerImage{}

	if image.ID != "" {
		t.Error("default ID should be empty")
	}
	if image.RepoTags != nil {
		t.Error("default RepoTags should be nil")
	}
	if image.Size != 0 {
		t.Errorf("default Size = %d, want 0", image.Size)
	}
}

func TestDockerVolumeDefaults(t *testing.T) {
	volume := DockerVolume{}

	if volume.Name != "" {
		t.Error("default Name should be empty")
	}
	if volume.Driver != "" {
		t.Error("default Driver should be empty")
	}
}

func TestDockerNetworkDefaults(t *testing.T) {
	network := DockerNetwork{}

	if network.ID != "" {
		t.Error("default ID should be empty")
	}
	if network.EnableIPv6 {
		t.Error("default EnableIPv6 should be false")
	}
	if network.Internal {
		t.Error("default Internal should be false")
	}
}

func TestDockerContainerStatsDefaults(t *testing.T) {
	stats := DockerContainerStats{}

	if stats.ContainerID != "" {
		t.Error("default ContainerID should be empty")
	}
	if stats.CPUPercent != 0 {
		t.Errorf("default CPUPercent = %f, want 0", stats.CPUPercent)
	}
	if stats.PIDs != 0 {
		t.Errorf("default PIDs = %d, want 0", stats.PIDs)
	}
}

func TestDockerPruneResultDefaults(t *testing.T) {
	result := DockerPruneResult{}

	if result.Type != "" {
		t.Error("default Type should be empty")
	}
	if result.ReclaimedSpace != 0 {
		t.Errorf("default ReclaimedSpace = %d, want 0", result.ReclaimedSpace)
	}
	if result.DeletedItems != nil {
		t.Error("default DeletedItems should be nil")
	}
}

// Log entry tests

func TestLogEntryDefaults(t *testing.T) {
	entry := LogEntry{}

	if entry.Time != "" {
		t.Error("default Time should be empty")
	}
	if entry.Level != "" {
		t.Error("default Level should be empty")
	}
	if entry.Source != "" {
		t.Error("default Source should be empty")
	}
	if entry.Message != "" {
		t.Error("default Message should be empty")
	}
	if entry.Details != nil {
		t.Error("default Details should be nil")
	}
}

func TestLogBufferSize(t *testing.T) {
	sizes := []int{10, 100, 1000, 10000}
	for _, size := range sizes {
		buffer := NewLogBuffer(size)
		if buffer.size != size {
			t.Errorf("NewLogBuffer(%d) size = %d, want %d", size, buffer.size, size)
		}
	}
}

func TestLogBufferCircular(t *testing.T) {
	buffer := NewLogBuffer(5)

	// Add 10 entries to a buffer of size 5
	for i := 0; i < 10; i++ {
		buffer.Add(LogEntry{
			Time:    time.Now().Format(time.RFC3339),
			Level:   "info",
			Message: fmt.Sprintf("message %d", i),
		})
	}

	// Count should be at most 5
	if buffer.Count() > 5 {
		t.Errorf("Count = %d, should be <= 5", buffer.Count())
	}
}

func TestFileInfoDefaults(t *testing.T) {
	fi := FileInfo{}

	if fi.Name != "" {
		t.Error("default Name should be empty")
	}
	if fi.Path != "" {
		t.Error("default Path should be empty")
	}
	if fi.Type != "" {
		t.Error("default Type should be empty")
	}
	if fi.Size != 0 {
		t.Errorf("default Size = %d, want 0", fi.Size)
	}
	if fi.IsSymlink {
		t.Error("default IsSymlink should be false")
	}
}

func TestListDirResultDefaults(t *testing.T) {
	result := ListDirResult{}

	if result.CurrentPath != "" {
		t.Error("default CurrentPath should be empty")
	}
	if result.Entries != nil {
		t.Error("default Entries should be nil")
	}
	if result.Count != 0 {
		t.Errorf("default Count = %d, want 0", result.Count)
	}
}

func TestUploadResultDefaults(t *testing.T) {
	result := UploadResult{}

	if result.Path != "" {
		t.Error("default Path should be empty")
	}
	if result.Size != 0 {
		t.Errorf("default Size = %d, want 0", result.Size)
	}
	if result.Hash != "" {
		t.Error("default Hash should be empty")
	}
	if result.Duration != 0 {
		t.Errorf("default Duration = %d, want 0", result.Duration)
	}
}

func TestDownloadResultDefaults(t *testing.T) {
	result := DownloadResult{}

	if result.Path != "" {
		t.Error("default Path should be empty")
	}
	if result.Size != 0 {
		t.Errorf("default Size = %d, want 0", result.Size)
	}
	if result.Hash != "" {
		t.Error("default Hash should be empty")
	}
	if result.Content != "" {
		t.Error("default Content should be empty")
	}
	if result.ChunkCount != 0 {
		t.Errorf("default ChunkCount = %d, want 0", result.ChunkCount)
	}
}
