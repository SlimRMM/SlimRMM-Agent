package monitor

import (
	"runtime"
	"testing"
	"time"
)

func TestDefaultThresholdConfig(t *testing.T) {
	cfg := DefaultThresholdConfig()

	if cfg.CPUWarning != 80.0 {
		t.Errorf("CPUWarning = %f, want 80.0", cfg.CPUWarning)
	}
	if cfg.CPUCritical != 95.0 {
		t.Errorf("CPUCritical = %f, want 95.0", cfg.CPUCritical)
	}
	if cfg.MemoryWarning != 85.0 {
		t.Errorf("MemoryWarning = %f, want 85.0", cfg.MemoryWarning)
	}
	if cfg.MemoryCritical != 95.0 {
		t.Errorf("MemoryCritical = %f, want 95.0", cfg.MemoryCritical)
	}
	if cfg.DiskWarning != 85.0 {
		t.Errorf("DiskWarning = %f, want 85.0", cfg.DiskWarning)
	}
	if cfg.DiskCritical != 95.0 {
		t.Errorf("DiskCritical = %f, want 95.0", cfg.DiskCritical)
	}
	if cfg.SustainedMinutes != 2 {
		t.Errorf("SustainedMinutes = %d, want 2", cfg.SustainedMinutes)
	}
	if cfg.CooldownMinutes != 5 {
		t.Errorf("CooldownMinutes = %d, want 5", cfg.CooldownMinutes)
	}
}

func TestNewThresholdMonitor(t *testing.T) {
	cfg := DefaultThresholdConfig()
	m := NewThresholdMonitor(cfg)

	if m == nil {
		t.Fatal("NewThresholdMonitor returned nil")
	}
	if !m.enabled {
		t.Error("monitor should be enabled by default")
	}
	if m.states == nil {
		t.Error("states map should be initialized")
	}
}

func TestSetAlertCallback(t *testing.T) {
	cfg := DefaultThresholdConfig()
	m := NewThresholdMonitor(cfg)

	m.SetAlertCallback(func(alert ThresholdAlert) {
		_ = alert // callback is set
	})

	if m.alertCallback == nil {
		t.Error("alertCallback should be set")
	}
}

func TestSetEnabled(t *testing.T) {
	cfg := DefaultThresholdConfig()
	m := NewThresholdMonitor(cfg)

	m.SetEnabled(false)
	if m.enabled {
		t.Error("monitor should be disabled")
	}

	m.SetEnabled(true)
	if !m.enabled {
		t.Error("monitor should be enabled")
	}
}

func TestUpdateDisabled(t *testing.T) {
	cfg := DefaultThresholdConfig()
	m := NewThresholdMonitor(cfg)
	m.SetEnabled(false)

	stats := &Stats{
		CPU: CPUStats{UsagePercent: 99.0},
	}

	alerts := m.Update(stats)
	if len(alerts) != 0 {
		t.Error("disabled monitor should not generate alerts")
	}
}

func TestUpdateNormal(t *testing.T) {
	cfg := DefaultThresholdConfig()
	cfg.SustainedMinutes = 0 // Immediate alerts for testing
	m := NewThresholdMonitor(cfg)

	// Normal values - no alerts
	stats := &Stats{
		CPU:    CPUStats{UsagePercent: 50.0},
		Memory: MemStats{UsedPercent: 60.0},
		Disk:   []DiskStats{{Mountpoint: "/", UsedPercent: 50.0}},
	}

	alerts := m.Update(stats)
	if len(alerts) != 0 {
		t.Errorf("normal values should not generate alerts, got %d", len(alerts))
	}
}

func TestUpdateWarning(t *testing.T) {
	cfg := DefaultThresholdConfig()
	cfg.SustainedMinutes = 0 // Immediate alerts for testing
	m := NewThresholdMonitor(cfg)

	// Warning values
	stats := &Stats{
		CPU:    CPUStats{UsagePercent: 85.0},
		Memory: MemStats{UsedPercent: 50.0},
		Disk:   []DiskStats{{Mountpoint: "/", UsedPercent: 50.0}},
	}

	alerts := m.Update(stats)
	if len(alerts) != 1 {
		t.Errorf("warning value should generate 1 alert, got %d", len(alerts))
		return
	}
	if alerts[0].Severity != SeverityWarning {
		t.Errorf("severity = %s, want warning", alerts[0].Severity)
	}
	if alerts[0].Metric != MetricCPU {
		t.Errorf("metric = %s, want cpu", alerts[0].Metric)
	}
}

func TestUpdateCritical(t *testing.T) {
	cfg := DefaultThresholdConfig()
	cfg.SustainedMinutes = 0 // Immediate alerts for testing
	m := NewThresholdMonitor(cfg)

	// Critical values
	stats := &Stats{
		CPU:    CPUStats{UsagePercent: 98.0},
		Memory: MemStats{UsedPercent: 50.0},
		Disk:   []DiskStats{{Mountpoint: "/", UsedPercent: 50.0}},
	}

	alerts := m.Update(stats)
	if len(alerts) != 1 {
		t.Errorf("critical value should generate 1 alert, got %d", len(alerts))
		return
	}
	if alerts[0].Severity != SeverityCritical {
		t.Errorf("severity = %s, want critical", alerts[0].Severity)
	}
}

func TestUpdateWithCallback(t *testing.T) {
	cfg := DefaultThresholdConfig()
	cfg.SustainedMinutes = 0
	m := NewThresholdMonitor(cfg)

	var receivedAlerts []ThresholdAlert
	m.SetAlertCallback(func(alert ThresholdAlert) {
		receivedAlerts = append(receivedAlerts, alert)
	})

	stats := &Stats{
		CPU:    CPUStats{UsagePercent: 98.0},
		Memory: MemStats{UsedPercent: 50.0},
		Disk:   []DiskStats{},
	}

	m.Update(stats)
	if len(receivedAlerts) != 1 {
		t.Errorf("callback should receive 1 alert, got %d", len(receivedAlerts))
	}
}

func TestCooldown(t *testing.T) {
	cfg := DefaultThresholdConfig()
	cfg.SustainedMinutes = 0
	cfg.CooldownMinutes = 1000 // Long cooldown
	m := NewThresholdMonitor(cfg)

	stats := &Stats{
		CPU:    CPUStats{UsagePercent: 98.0},
		Memory: MemStats{UsedPercent: 50.0},
		Disk:   []DiskStats{},
	}

	// First alert
	alerts1 := m.Update(stats)
	if len(alerts1) != 1 {
		t.Errorf("first update should generate 1 alert, got %d", len(alerts1))
	}

	// Second update - should be in cooldown
	alerts2 := m.Update(stats)
	if len(alerts2) != 0 {
		t.Errorf("second update should be in cooldown, got %d alerts", len(alerts2))
	}
}

func TestReset(t *testing.T) {
	cfg := DefaultThresholdConfig()
	cfg.SustainedMinutes = 0
	m := NewThresholdMonitor(cfg)

	// Generate some state
	stats := &Stats{
		CPU:    CPUStats{UsagePercent: 98.0},
		Memory: MemStats{UsedPercent: 50.0},
		Disk:   []DiskStats{},
	}
	m.Update(stats)

	// Reset
	m.Reset()

	// States should be empty
	state := m.GetCurrentState()
	if len(state) != 0 {
		t.Errorf("states should be empty after reset, got %d", len(state))
	}
}

func TestGetCurrentState(t *testing.T) {
	cfg := DefaultThresholdConfig()
	m := NewThresholdMonitor(cfg)

	stats := &Stats{
		CPU:    CPUStats{UsagePercent: 98.0},
		Memory: MemStats{UsedPercent: 50.0},
		Disk:   []DiskStats{},
	}
	m.Update(stats)

	state := m.GetCurrentState()
	if _, ok := state[MetricCPU]; !ok {
		t.Error("CPU state should be tracked")
	}
	if state[MetricCPU].Value != 98.0 {
		t.Errorf("CPU value = %f, want 98.0", state[MetricCPU].Value)
	}
}

func TestGetAlertMessage(t *testing.T) {
	cfg := DefaultThresholdConfig()
	m := NewThresholdMonitor(cfg)

	tests := []struct {
		metric   MetricType
		severity AlertSeverity
		contains string
	}{
		{MetricCPU, SeverityCritical, "CPU usage"},
		{MetricCPU, SeverityWarning, "CPU usage"},
		{MetricMemory, SeverityCritical, "Memory usage"},
		{MetricDisk, SeverityWarning, "Disk usage"},
	}

	for _, tt := range tests {
		msg := m.getAlertMessage(tt.metric, tt.severity, 90.0)
		if msg == "" {
			t.Errorf("message for %s %s should not be empty", tt.metric, tt.severity)
		}
	}
}

func TestGetSystemDiskUsage(t *testing.T) {
	// Test with no disks
	if usage := getSystemDiskUsage(nil); usage != 0 {
		t.Errorf("empty disks should return 0, got %f", usage)
	}

	// Test with system drive
	var mountpoint string
	if runtime.GOOS == "windows" {
		mountpoint = "C:"
	} else {
		mountpoint = "/"
	}

	disks := []DiskStats{
		{Mountpoint: mountpoint, UsedPercent: 75.5, Total: 500 * 1024 * 1024 * 1024},
	}

	usage := getSystemDiskUsage(disks)
	if usage != 75.5 {
		t.Errorf("system disk usage = %f, want 75.5", usage)
	}
}

func TestGetSystemDiskUsageFallback(t *testing.T) {
	// Test fallback to large disk
	disks := []DiskStats{
		{Mountpoint: "/mnt/usb", UsedPercent: 50.0, Total: 1 * 1024 * 1024}, // Small, skip
		{Mountpoint: "/mnt/data", UsedPercent: 80.0, Total: 100 * 1024 * 1024 * 1024}, // Large, use
	}

	usage := getSystemDiskUsage(disks)
	if usage != 80.0 {
		t.Errorf("fallback disk usage = %f, want 80.0", usage)
	}
}

func TestThresholdAlert(t *testing.T) {
	alert := ThresholdAlert{
		Metric:          MetricCPU,
		CurrentValue:    95.5,
		Threshold:       90.0,
		Severity:        SeverityCritical,
		DurationSeconds: 120,
		Timestamp:       time.Now(),
		Message:         "CPU usage is critically high",
	}

	if alert.Metric != MetricCPU {
		t.Error("Metric not set correctly")
	}
	if alert.CurrentValue != 95.5 {
		t.Error("CurrentValue not set correctly")
	}
	if alert.Severity != SeverityCritical {
		t.Error("Severity not set correctly")
	}
}

func TestSeverityConstants(t *testing.T) {
	if SeverityWarning != "warning" {
		t.Errorf("SeverityWarning = %s, want warning", SeverityWarning)
	}
	if SeverityCritical != "critical" {
		t.Errorf("SeverityCritical = %s, want critical", SeverityCritical)
	}
}

func TestMetricTypeConstants(t *testing.T) {
	if MetricCPU != "cpu" {
		t.Errorf("MetricCPU = %s, want cpu", MetricCPU)
	}
	if MetricMemory != "memory" {
		t.Errorf("MetricMemory = %s, want memory", MetricMemory)
	}
	if MetricDisk != "disk" {
		t.Errorf("MetricDisk = %s, want disk", MetricDisk)
	}
}

// Stats struct tests

func TestStatsStruct(t *testing.T) {
	now := time.Now()
	stats := Stats{
		Hostname:     "server1",
		OS:           "linux",
		Platform:     "ubuntu",
		Kernel:       "5.15.0",
		Uptime:       86400,
		BootTime:     1705000000,
		ExternalIP:   "8.8.8.8",
		Timezone:     "UTC",
		ProcessCount: 150,
		Timestamp:    now,
	}

	if stats.Hostname != "server1" {
		t.Errorf("Hostname = %s, want server1", stats.Hostname)
	}
	if stats.OS != "linux" {
		t.Errorf("OS = %s, want linux", stats.OS)
	}
	if stats.Uptime != 86400 {
		t.Errorf("Uptime = %d, want 86400", stats.Uptime)
	}
	if stats.ProcessCount != 150 {
		t.Errorf("ProcessCount = %d, want 150", stats.ProcessCount)
	}
}

func TestCPUStatsStruct(t *testing.T) {
	cpuStats := CPUStats{
		Cores:        8,
		ModelName:    "Intel Core i7",
		UsagePercent: 45.5,
		LoadAvg:      []float64{1.5, 2.0, 1.8},
	}

	if cpuStats.Cores != 8 {
		t.Errorf("Cores = %d, want 8", cpuStats.Cores)
	}
	if cpuStats.ModelName != "Intel Core i7" {
		t.Errorf("ModelName = %s, want Intel Core i7", cpuStats.ModelName)
	}
	if cpuStats.UsagePercent != 45.5 {
		t.Errorf("UsagePercent = %f, want 45.5", cpuStats.UsagePercent)
	}
	if len(cpuStats.LoadAvg) != 3 {
		t.Errorf("len(LoadAvg) = %d, want 3", len(cpuStats.LoadAvg))
	}
}

func TestMemStatsStruct(t *testing.T) {
	memStats := MemStats{
		Total:       16 * 1024 * 1024 * 1024,
		Available:   8 * 1024 * 1024 * 1024,
		Used:        8 * 1024 * 1024 * 1024,
		UsedPercent: 50.0,
		SwapTotal:   4 * 1024 * 1024 * 1024,
		SwapUsed:    1 * 1024 * 1024 * 1024,
	}

	if memStats.Total != 16*1024*1024*1024 {
		t.Errorf("Total = %d, want 16GB", memStats.Total)
	}
	if memStats.UsedPercent != 50.0 {
		t.Errorf("UsedPercent = %f, want 50.0", memStats.UsedPercent)
	}
}

func TestDiskStatsStruct(t *testing.T) {
	diskStats := DiskStats{
		Device:      "/dev/sda1",
		Mountpoint:  "/",
		Fstype:      "ext4",
		Total:       500 * 1024 * 1024 * 1024,
		Used:        250 * 1024 * 1024 * 1024,
		Free:        250 * 1024 * 1024 * 1024,
		UsedPercent: 50.0,
	}

	if diskStats.Device != "/dev/sda1" {
		t.Errorf("Device = %s, want /dev/sda1", diskStats.Device)
	}
	if diskStats.Mountpoint != "/" {
		t.Errorf("Mountpoint = %s, want /", diskStats.Mountpoint)
	}
	if diskStats.Fstype != "ext4" {
		t.Errorf("Fstype = %s, want ext4", diskStats.Fstype)
	}
	if diskStats.UsedPercent != 50.0 {
		t.Errorf("UsedPercent = %f, want 50.0", diskStats.UsedPercent)
	}
}

func TestNetStatsStruct(t *testing.T) {
	netStats := NetStats{
		Name:        "eth0",
		BytesSent:   1000000000,
		BytesRecv:   2000000000,
		PacketsSent: 1000000,
		PacketsRecv: 2000000,
		IPv4:        "192.168.1.100",
		IPv6:        "fe80::1",
	}

	if netStats.Name != "eth0" {
		t.Errorf("Name = %s, want eth0", netStats.Name)
	}
	if netStats.BytesSent != 1000000000 {
		t.Errorf("BytesSent = %d, want 1000000000", netStats.BytesSent)
	}
	if netStats.IPv4 != "192.168.1.100" {
		t.Errorf("IPv4 = %s, want 192.168.1.100", netStats.IPv4)
	}
}

func TestNewMonitor(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New should return non-nil Monitor")
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    uint64
		expected string
	}{
		{0, "0 B"},
		{100, "100 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1024 * 1024, "1.0 MiB"},
		{1024 * 1024 * 1024, "1.0 GiB"},
		{1024 * 1024 * 1024 * 1024, "1.0 TiB"},
	}

	for _, tt := range tests {
		result := FormatBytes(tt.bytes)
		if result != tt.expected {
			t.Errorf("FormatBytes(%d) = %s, want %s", tt.bytes, result, tt.expected)
		}
	}
}

func TestIsVirtualFilesystem(t *testing.T) {
	tests := []struct {
		fstype     string
		mountpoint string
		isVirtual  bool
	}{
		{"ext4", "/", false},
		{"xfs", "/home", false},
		{"apfs", "/System/Volumes/Data", false},
		{"sysfs", "/sys", true},
		{"proc", "/proc", true},
		{"cgroup", "/sys/fs/cgroup", true},
		{"cgroup2", "/sys/fs/cgroup", true},
		{"debugfs", "/sys/kernel/debug", true},
		{"overlay", "/var/lib/docker/overlay2", true},
		{"ext4", "/sys/something", true},
		{"ext4", "/proc/something", true},
		{"ext4", "/run/user/1000", true},
	}

	for _, tt := range tests {
		result := isVirtualFilesystem(tt.fstype, tt.mountpoint)
		if result != tt.isVirtual {
			t.Errorf("isVirtualFilesystem(%s, %s) = %v, want %v", tt.fstype, tt.mountpoint, result, tt.isVirtual)
		}
	}
}

func TestGetHostname(t *testing.T) {
	hostname := GetHostname()
	if hostname == "" {
		t.Error("GetHostname should return non-empty string")
	}
	if hostname == "unknown" {
		t.Log("GetHostname returned 'unknown' - this may be a test environment issue")
	}
}

// Aggregator tests

func TestDefaultAggregatorConfig(t *testing.T) {
	cfg := DefaultAggregatorConfig()

	if cfg.MaxSamples != 6 {
		t.Errorf("MaxSamples = %d, want 6", cfg.MaxSamples)
	}
	if cfg.FlushPeriod != 3*time.Minute {
		t.Errorf("FlushPeriod = %v, want 3m", cfg.FlushPeriod)
	}
}

func TestNewStatsAggregator(t *testing.T) {
	cfg := DefaultAggregatorConfig()
	agg := NewStatsAggregator(cfg)

	if agg == nil {
		t.Fatal("NewStatsAggregator should return non-nil")
	}
	if agg.maxSamples != cfg.MaxSamples {
		t.Errorf("maxSamples = %d, want %d", agg.maxSamples, cfg.MaxSamples)
	}
	if agg.samples == nil {
		t.Error("samples should be initialized")
	}
}

func TestStatsAggregatorAddSample(t *testing.T) {
	cfg := AggregatorConfig{MaxSamples: 10, FlushPeriod: time.Minute}
	agg := NewStatsAggregator(cfg)

	agg.AddSample(50.0, 60.0, 8*1024*1024*1024, 16*1024*1024*1024)

	if agg.GetSampleCount() != 1 {
		t.Errorf("sample count = %d, want 1", agg.GetSampleCount())
	}

	agg.AddSample(55.0, 65.0, 9*1024*1024*1024, 16*1024*1024*1024)

	if agg.GetSampleCount() != 2 {
		t.Errorf("sample count = %d, want 2", agg.GetSampleCount())
	}
}

func TestStatsAggregatorFlush(t *testing.T) {
	cfg := AggregatorConfig{MaxSamples: 10, FlushPeriod: time.Minute}
	agg := NewStatsAggregator(cfg)

	var receivedStats *AggregatedStats
	agg.SetFlushCallback(func(stats AggregatedStats) {
		receivedStats = &stats
	})

	// Add some samples
	agg.AddSample(50.0, 60.0, 8*1024*1024*1024, 16*1024*1024*1024)
	agg.AddSample(70.0, 80.0, 10*1024*1024*1024, 16*1024*1024*1024)
	agg.AddSample(60.0, 70.0, 9*1024*1024*1024, 16*1024*1024*1024)

	agg.Flush()

	if receivedStats == nil {
		t.Fatal("callback should have been called")
	}

	if receivedStats.SampleCount != 3 {
		t.Errorf("SampleCount = %d, want 3", receivedStats.SampleCount)
	}

	// Check average
	expectedCPUAvg := (50.0 + 70.0 + 60.0) / 3.0
	if receivedStats.CPUAvg != expectedCPUAvg {
		t.Errorf("CPUAvg = %f, want %f", receivedStats.CPUAvg, expectedCPUAvg)
	}

	// Check min/max
	if receivedStats.CPUMin != 50.0 {
		t.Errorf("CPUMin = %f, want 50.0", receivedStats.CPUMin)
	}
	if receivedStats.CPUMax != 70.0 {
		t.Errorf("CPUMax = %f, want 70.0", receivedStats.CPUMax)
	}

	// Sample count should be 0 after flush
	if agg.GetSampleCount() != 0 {
		t.Errorf("sample count after flush = %d, want 0", agg.GetSampleCount())
	}
}

func TestStatsAggregatorAutoFlush(t *testing.T) {
	cfg := AggregatorConfig{MaxSamples: 3, FlushPeriod: time.Minute}
	agg := NewStatsAggregator(cfg)

	flushed := false
	agg.SetFlushCallback(func(stats AggregatedStats) {
		flushed = true
	})

	// Add maxSamples to trigger auto flush
	agg.AddSample(50.0, 60.0, 8*1024*1024*1024, 16*1024*1024*1024)
	agg.AddSample(55.0, 65.0, 8*1024*1024*1024, 16*1024*1024*1024)
	agg.AddSample(60.0, 70.0, 8*1024*1024*1024, 16*1024*1024*1024)

	if !flushed {
		t.Error("auto flush should have triggered at maxSamples")
	}
}

func TestStatsAggregatorEmptyFlush(t *testing.T) {
	cfg := DefaultAggregatorConfig()
	agg := NewStatsAggregator(cfg)

	called := false
	agg.SetFlushCallback(func(stats AggregatedStats) {
		called = true
	})

	// Flush with no samples should not call callback
	agg.Flush()

	if called {
		t.Error("callback should not be called for empty flush")
	}
}

func TestAggregatedStatsStruct(t *testing.T) {
	stats := AggregatedStats{
		PeriodStart:   time.Now(),
		PeriodSeconds: 180,
		CPUAvg:        55.5,
		CPUMax:        70.0,
		CPUMin:        40.0,
		MemoryAvg:     65.0,
		MemoryMax:     75.0,
		MemoryMin:     55.0,
		MemoryUsed:    8 * 1024 * 1024 * 1024,
		MemoryTotal:   16 * 1024 * 1024 * 1024,
		SampleCount:   6,
	}

	if stats.PeriodSeconds != 180 {
		t.Errorf("PeriodSeconds = %d, want 180", stats.PeriodSeconds)
	}
	if stats.CPUAvg != 55.5 {
		t.Errorf("CPUAvg = %f, want 55.5", stats.CPUAvg)
	}
	if stats.SampleCount != 6 {
		t.Errorf("SampleCount = %d, want 6", stats.SampleCount)
	}
}

func TestStatsDefaults(t *testing.T) {
	stats := Stats{}

	if stats.Hostname != "" {
		t.Error("default Hostname should be empty")
	}
	if stats.CPU.Cores != 0 {
		t.Errorf("default CPU.Cores = %d, want 0", stats.CPU.Cores)
	}
	if stats.Memory.Total != 0 {
		t.Errorf("default Memory.Total = %d, want 0", stats.Memory.Total)
	}
	if stats.Disk != nil {
		t.Error("default Disk should be nil")
	}
	if stats.Network != nil {
		t.Error("default Network should be nil")
	}
	if stats.ProcessCount != 0 {
		t.Errorf("default ProcessCount = %d, want 0", stats.ProcessCount)
	}
}

func TestStatsWithAllFields(t *testing.T) {
	now := time.Now()
	stats := Stats{
		Hostname:     "webserver",
		OS:           "darwin",
		Platform:     "darwin",
		Kernel:       "23.1.0",
		Uptime:       172800,
		BootTime:     uint64(now.Unix() - 172800),
		CPU: CPUStats{
			Cores:        10,
			ModelName:    "Apple M1 Pro",
			UsagePercent: 25.0,
			LoadAvg:      []float64{1.0, 1.5, 1.2},
		},
		Memory: MemStats{
			Total:       32 * 1024 * 1024 * 1024,
			Available:   20 * 1024 * 1024 * 1024,
			Used:        12 * 1024 * 1024 * 1024,
			UsedPercent: 37.5,
			SwapTotal:   0,
			SwapUsed:    0,
		},
		Disk: []DiskStats{
			{Device: "disk1s1", Mountpoint: "/", Fstype: "apfs", Total: 1 * 1024 * 1024 * 1024 * 1024, UsedPercent: 75.0},
		},
		Network: []NetStats{
			{Name: "en0", BytesSent: 1000000, BytesRecv: 2000000, IPv4: "192.168.1.10"},
		},
		ExternalIP:   "1.2.3.4",
		Timezone:     "America/New_York",
		ProcessCount: 400,
		Timestamp:    now,
	}

	if stats.Hostname != "webserver" {
		t.Errorf("Hostname = %s, want webserver", stats.Hostname)
	}
	if stats.CPU.ModelName != "Apple M1 Pro" {
		t.Errorf("CPU.ModelName = %s, want Apple M1 Pro", stats.CPU.ModelName)
	}
	if len(stats.Disk) != 1 {
		t.Errorf("len(Disk) = %d, want 1", len(stats.Disk))
	}
	if len(stats.Network) != 1 {
		t.Errorf("len(Network) = %d, want 1", len(stats.Network))
	}
}
