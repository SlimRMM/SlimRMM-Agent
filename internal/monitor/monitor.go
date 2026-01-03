// Package monitor provides system monitoring capabilities.
// It collects CPU, memory, disk, and network statistics.
package monitor

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	gopsnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// Stats contains system statistics.
type Stats struct {
	Hostname     string     `json:"hostname"`
	OS           string     `json:"os"`
	Platform     string     `json:"platform"`
	Kernel       string     `json:"kernel"`
	Uptime       uint64     `json:"uptime"`
	BootTime     uint64     `json:"boot_time"`
	CPU          CPUStats   `json:"cpu"`
	Memory       MemStats   `json:"memory"`
	Disk         []DiskStats `json:"disk"`
	Network      []NetStats `json:"network"`
	ExternalIP   string     `json:"external_ip,omitempty"`
	ProcessCount int        `json:"process_count"`
	Timestamp    time.Time  `json:"timestamp"`
}

// CPUStats contains CPU statistics.
type CPUStats struct {
	Cores       int       `json:"cores"`
	ModelName   string    `json:"model_name"`
	UsagePercent float64  `json:"usage_percent"`
	LoadAvg     []float64 `json:"load_avg,omitempty"`
}

// MemStats contains memory statistics.
type MemStats struct {
	Total       uint64  `json:"total"`
	Available   uint64  `json:"available"`
	Used        uint64  `json:"used"`
	UsedPercent float64 `json:"used_percent"`
	SwapTotal   uint64  `json:"swap_total"`
	SwapUsed    uint64  `json:"swap_used"`
}

// DiskStats contains disk statistics.
type DiskStats struct {
	Device      string  `json:"device"`
	Mountpoint  string  `json:"mountpoint"`
	Fstype      string  `json:"fstype"`
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"used_percent"`
}

// NetStats contains network interface statistics.
type NetStats struct {
	Name        string `json:"name"`
	BytesSent   uint64 `json:"bytes_sent"`
	BytesRecv   uint64 `json:"bytes_recv"`
	PacketsSent uint64 `json:"packets_sent"`
	PacketsRecv uint64 `json:"packets_recv"`
	IPv4        string `json:"ipv4,omitempty"`
	IPv6        string `json:"ipv6,omitempty"`
}

// Monitor provides system monitoring functionality.
type Monitor struct {
	externalIP     string
	externalIPTime time.Time
	mu             sync.RWMutex
}

// New creates a new Monitor.
func New() *Monitor {
	return &Monitor{}
}

// GetStats collects and returns current system statistics.
func (m *Monitor) GetStats(ctx context.Context) (*Stats, error) {
	stats := &Stats{
		Timestamp: time.Now(),
	}

	// Host info
	hostInfo, err := host.InfoWithContext(ctx)
	if err == nil {
		stats.Hostname = hostInfo.Hostname
		stats.OS = hostInfo.OS
		stats.Platform = hostInfo.Platform
		stats.Kernel = hostInfo.KernelVersion
		stats.Uptime = hostInfo.Uptime
		stats.BootTime = hostInfo.BootTime
	}

	// CPU info
	cpuInfo, err := cpu.InfoWithContext(ctx)
	if err == nil && len(cpuInfo) > 0 {
		stats.CPU.ModelName = cpuInfo[0].ModelName
		stats.CPU.Cores = runtime.NumCPU()
	}

	cpuPercent, err := cpu.PercentWithContext(ctx, 0, false)
	if err == nil && len(cpuPercent) > 0 {
		stats.CPU.UsagePercent = cpuPercent[0]
	}

	// Memory info
	memInfo, err := mem.VirtualMemoryWithContext(ctx)
	if err == nil {
		stats.Memory.Total = memInfo.Total
		stats.Memory.Available = memInfo.Available
		stats.Memory.Used = memInfo.Used
		stats.Memory.UsedPercent = memInfo.UsedPercent
	}

	swapInfo, err := mem.SwapMemoryWithContext(ctx)
	if err == nil {
		stats.Memory.SwapTotal = swapInfo.Total
		stats.Memory.SwapUsed = swapInfo.Used
	}

	// Disk info
	partitions, err := disk.PartitionsWithContext(ctx, false)
	if err == nil {
		for _, p := range partitions {
			usage, err := disk.UsageWithContext(ctx, p.Mountpoint)
			if err != nil {
				continue
			}
			stats.Disk = append(stats.Disk, DiskStats{
				Device:      p.Device,
				Mountpoint:  p.Mountpoint,
				Fstype:      p.Fstype,
				Total:       usage.Total,
				Used:        usage.Used,
				Free:        usage.Free,
				UsedPercent: usage.UsedPercent,
			})
		}
	}

	// Network info
	netIO, err := gopsnet.IOCountersWithContext(ctx, true)
	if err == nil {
		interfaces, _ := net.Interfaces()
		ifAddrs := make(map[string][]string)
		for _, iface := range interfaces {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				ifAddrs[iface.Name] = append(ifAddrs[iface.Name], addr.String())
			}
		}

		for _, io := range netIO {
			ns := NetStats{
				Name:        io.Name,
				BytesSent:   io.BytesSent,
				BytesRecv:   io.BytesRecv,
				PacketsSent: io.PacketsSent,
				PacketsRecv: io.PacketsRecv,
			}
			// Add IP addresses
			for _, addr := range ifAddrs[io.Name] {
				if ip, _, err := net.ParseCIDR(addr); err == nil {
					if ip.To4() != nil {
						ns.IPv4 = ip.String()
					} else {
						ns.IPv6 = ip.String()
					}
				}
			}
			stats.Network = append(stats.Network, ns)
		}
	}

	// Process count
	procs, err := process.ProcessesWithContext(ctx)
	if err == nil {
		stats.ProcessCount = len(procs)
	}

	// External IP (cached for 15 minutes)
	stats.ExternalIP = m.getExternalIP()

	return stats, nil
}

// getExternalIP returns the cached external IP or fetches a new one.
func (m *Monitor) getExternalIP() string {
	m.mu.RLock()
	if time.Since(m.externalIPTime) < 15*time.Minute && m.externalIP != "" {
		ip := m.externalIP
		m.mu.RUnlock()
		return ip
	}
	m.mu.RUnlock()

	// Fetch new IP
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if time.Since(m.externalIPTime) < 15*time.Minute && m.externalIP != "" {
		return m.externalIP
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://ifconfig.io/ip")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	ip := strings.TrimSpace(string(buf[:n]))

	// Validate IP
	if parsed := net.ParseIP(ip); parsed != nil {
		m.externalIP = parsed.String()
		m.externalIPTime = time.Now()
	}

	return m.externalIP
}

// GetHostname returns the system hostname.
func GetHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// FormatBytes formats bytes to human-readable format.
func FormatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
