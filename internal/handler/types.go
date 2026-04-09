package handler

import (
	"context"
	"encoding/json"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/services/backup"
)

const (
	// WebSocket timing constants
	writeWait       = 10 * time.Second
	pongWait        = 60 * time.Second
	pingPeriod      = (pongWait * 9) / 10
	heartbeatPeriod = 30 * time.Second
	// SECURITY: Reduced from 10MB to 1MB to prevent memory exhaustion DoS attacks.
	// Large file transfers should use streaming endpoints, not WebSocket messages.
	maxMessageSize    = 1 * 1024 * 1024 // 1 MB
	certCheckInterval = 24 * time.Hour  // Check certificates every 24 hours

	// Connection constants
	connectionTimeout = 30 * time.Second
	tcpKeepAlive      = 30 * time.Second
	handshakeTimeout  = 15 * time.Second
	wsEndpoint        = "/api/v1/ws/agent"
	httpClientTimeout = 30 * time.Second

	// Heartbeat configuration
	fullHeartbeatInterval = 10  // Full heartbeat every N heartbeats (~5 minutes)
	configSaveInterval    = 10  // Save config every N heartbeats (~5 minutes)
	wingetUpdateInterval  = 120 // Winget update check every N heartbeats (~60 minutes)

	// Concurrency controls
	// MaxConcurrentHandlers caps in-flight message handler goroutines to provide
	// natural backpressure against message floods / DoS from a compromised server.
	MaxConcurrentHandlers = 64
	// defaultHandlerTimeout is applied to every dispatched handler unless it is listed
	// in longRunningActions, which receive longHandlerTimeout instead.
	defaultHandlerTimeout = 30 * time.Second
	longHandlerTimeout    = 10 * time.Minute
)

// longRunningActions lists handler actions that may legitimately run longer than
// defaultHandlerTimeout (updates, script execution, file transfers, patching, etc.).
var longRunningActions = map[string]bool{
	"update_agent":                  true,
	"execute_script":                true,
	"custom_command":                true,
	"start_transfer":                true,
	"start_upload":                  true,
	"upload_chunk":                  true,
	"finish_upload":                 true,
	"download_file":                 true,
	"download_chunk":                true,
	"download_url":                  true,
	"execute_patches":               true,
	"run_patches":                   true,
	"update_osquery":                true,
	"install_software":              true,
	"download_and_install_msi":      true,
	"download_and_install_pkg":      true,
	"download_and_install_cask":     true,
	"uninstall_software":            true,
	"create_agent_backup":           true,
	"restore_agent_backup":          true,
	"docker_pull_image":             true,
	"docker_update_images":          true,
	"execute_winget_policy":         true,
	"execute_winget_update":         true,
	"execute_winget_updates":        true,
	"execute_winget_install_policy": true,
	"install_winget":                true,
	"zip_entry":                     true,
	"unzip_entry":                   true,
	"run_compliance_check":          true,
	"install_remote_desktop":        true,
	"uninstall_remote_desktop":      true,
}

// actionToResponseAction maps request action names to their response action names.
// This is needed because the backend expects specific action names for certain responses.
var actionToResponseAction = map[string]string{
	"pull_logs":                  "logs_result",
	"create_agent_backup":        "backup_result",
	"install_remote_desktop":     "install_remote_desktop_result",
	"uninstall_remote_desktop":   "uninstall_remote_desktop_result",
}

// Message represents a WebSocket message from the backend.
// The backend sends all fields at root level, not inside a "data" object.
type Message struct {
	Action    string          `json:"action"`
	RequestID string          `json:"request_id,omitempty"`
	ScanType  string          `json:"scan_type,omitempty"`
	Query     string          `json:"query,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	// Additional fields used by various actions
	// We store the raw message to extract action-specific fields
	Raw json.RawMessage `json:"-"`
}

// Response represents a WebSocket response.
type Response struct {
	Action    string      `json:"action"`
	RequestID string      `json:"request_id,omitempty"`
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
}

// HeartbeatMessage is the format expected by the backend (Python-compatible).
type HeartbeatMessage struct {
	Action             string                     `json:"action"`
	Type               string                     `json:"type,omitempty"`
	AgentVersion       string                     `json:"agent_version"`
	Stats              HeartbeatStats             `json:"stats"`
	ExternalIP         string                     `json:"external_ip,omitempty"`
	SerialNumber       string                     `json:"serial_number,omitempty"`
	Proxmox            *HeartbeatProxmox          `json:"proxmox,omitempty"`
	HyperV             *HeartbeatHyperV           `json:"hyperv,omitempty"`
	Docker             *DockerInfo                `json:"docker,omitempty"`
	Winget             *HeartbeatWinget           `json:"winget,omitempty"`
	BackupCapabilities *backup.BackupCapabilities `json:"backup_capabilities,omitempty"`
	RustDesk           *HeartbeatRustDesk         `json:"rustdesk,omitempty"`
	DroppedMessages    int64                      `json:"dropped_messages,omitempty"`
}

// HeartbeatRustDesk contains RustDesk remote desktop information.
type HeartbeatRustDesk struct {
	Installed bool   `json:"installed"`
	ID        string `json:"id,omitempty"`
	Version   string `json:"version,omitempty"`
}

// HeartbeatWinget contains Windows Package Manager (winget) information.
type HeartbeatWinget struct {
	Available                   bool   `json:"available"`
	Version                     string `json:"version,omitempty"`
	BinaryPath                  string `json:"binary_path,omitempty"`
	SystemLevel                 bool   `json:"system_level"`
	HelperAvailable             bool   `json:"helper_available"`               // Available via helper in user context
	PowerShell7Available        bool   `json:"powershell7_available"`          // PowerShell 7 is installed
	WinGetClientModuleAvailable bool   `json:"winget_client_module_available"` // Microsoft.WinGet.Client module is available
}

// HeartbeatProxmox contains Proxmox host information.
type HeartbeatProxmox struct {
	IsProxmox      bool   `json:"is_proxmox"`
	Version        string `json:"version,omitempty"`
	Release        string `json:"release,omitempty"`
	KernelVersion  string `json:"kernel_version,omitempty"`
	ClusterName    string `json:"cluster_name,omitempty"`
	NodeName       string `json:"node_name,omitempty"`
	RepositoryType string `json:"repository_type,omitempty"`
}

// HeartbeatHyperV contains Hyper-V host information.
type HeartbeatHyperV struct {
	IsHyperV       bool   `json:"is_hyperv"`
	Version        string `json:"version,omitempty"`
	HostName       string `json:"host_name,omitempty"`
	VMCount        int    `json:"vm_count,omitempty"`
	ClusterEnabled bool   `json:"cluster_enabled,omitempty"`
}

// HeartbeatStats contains the stats in the format expected by the backend.
// Matches Python agent format for API compatibility.
type HeartbeatStats struct {
	CPUPercent    float64             `json:"cpu_percent"`
	MemoryPercent float64             `json:"memory_percent"`
	MemoryUsed    int64               `json:"memory_used"`
	MemoryTotal   int64               `json:"memory_total"`
	Disk          []HeartbeatDisk     `json:"disk,omitempty"`
	NetworkIO     *HeartbeatNetworkIO `json:"network_io,omitempty"`
	UptimeSeconds int64               `json:"uptime_seconds,omitempty"`
	ProcessCount  int                 `json:"process_count,omitempty"`
	Timezone      string              `json:"timezone,omitempty"`
}

// HeartbeatDisk contains disk statistics for heartbeat.
type HeartbeatDisk struct {
	Device      string  `json:"device"`
	Mountpoint  string  `json:"mountpoint"`
	Total       int64   `json:"total"`
	Used        int64   `json:"used"`
	Free        int64   `json:"free"`
	UsedPercent float64 `json:"used_percent"`
}

// HeartbeatNetworkIO contains network I/O statistics.
type HeartbeatNetworkIO struct {
	BytesSent   int64 `json:"bytes_sent"`
	BytesRecv   int64 `json:"bytes_recv"`
	PacketsSent int64 `json:"packets_sent"`
	PacketsRecv int64 `json:"packets_recv"`
}

// OsqueryResponse is the format expected by the backend for osquery results.
type OsqueryResponse struct {
	Action    string      `json:"action"`
	ScanType  string      `json:"scan_type"`
	Data      interface{} `json:"data"`
	RequestID string      `json:"request_id,omitempty"`
}

// ActionHandler is a function that handles a specific action.
type ActionHandler func(ctx context.Context, data json.RawMessage) (interface{}, error)

// SelfHealingWatchdog is the interface for the self-healing watchdog.
type SelfHealingWatchdog interface {
	RecordConnectionSuccess()
	RecordConnectionFailure()
	GetRestartCount() int
}
