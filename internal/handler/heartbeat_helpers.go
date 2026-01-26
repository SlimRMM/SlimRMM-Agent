package handler

import (
	"context"
	"runtime"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/monitor"
	"github.com/slimrmm/slimrmm-agent/internal/winget"
	"github.com/slimrmm/slimrmm-agent/pkg/version"
)

// buildDiskStats converts monitor disk stats to heartbeat format.
func buildDiskStats(stats *monitor.Stats) []HeartbeatDisk {
	diskStats := make([]HeartbeatDisk, 0, len(stats.Disk))
	for _, d := range stats.Disk {
		diskStats = append(diskStats, HeartbeatDisk{
			Device:      d.Device,
			Mountpoint:  d.Mountpoint,
			Total:       d.Total,
			Used:        d.Used,
			Free:        d.Free,
			UsedPercent: d.UsedPercent,
		})
	}
	return diskStats
}

// aggregateNetworkIO aggregates network I/O stats from all interfaces.
func aggregateNetworkIO(stats *monitor.Stats) *HeartbeatNetworkIO {
	var totalBytesSent, totalBytesRecv, totalPacketsSent, totalPacketsRecv uint64
	for _, n := range stats.Network {
		totalBytesSent += n.BytesSent
		totalBytesRecv += n.BytesRecv
		totalPacketsSent += n.PacketsSent
		totalPacketsRecv += n.PacketsRecv
	}
	return &HeartbeatNetworkIO{
		BytesSent:   totalBytesSent,
		BytesRecv:   totalBytesRecv,
		PacketsSent: totalPacketsSent,
		PacketsRecv: totalPacketsRecv,
	}
}

// buildBaseHeartbeat creates the base heartbeat message structure.
func (h *Handler) buildBaseHeartbeat(ctx context.Context, stats *monitor.Stats) HeartbeatMessage {
	return HeartbeatMessage{
		Action:       "heartbeat",
		Type:         "full",
		AgentVersion: version.Version,
		Stats: HeartbeatStats{
			CPUPercent:    stats.CPU.UsagePercent,
			MemoryPercent: stats.Memory.UsedPercent,
			MemoryUsed:    stats.Memory.Used,
			MemoryTotal:   stats.Memory.Total,
			Disk:          buildDiskStats(stats),
			NetworkIO:     aggregateNetworkIO(stats),
			UptimeSeconds: stats.Uptime,
			ProcessCount:  stats.ProcessCount,
			Timezone:      stats.Timezone,
		},
		ExternalIP:   stats.ExternalIP,
		SerialNumber: h.getSerialNumber(ctx),
	}
}

// addProxmoxInfo adds Proxmox info to heartbeat if available and changed.
func (h *Handler) addProxmoxInfo(ctx context.Context, heartbeat *HeartbeatMessage) {
	proxmoxInfo := GetProxmoxInfo(ctx)
	if proxmoxInfo == nil {
		return
	}

	proxmoxData := &HeartbeatProxmox{
		IsProxmox:      proxmoxInfo.IsProxmox,
		Version:        proxmoxInfo.Version,
		Release:        proxmoxInfo.Release,
		KernelVersion:  proxmoxInfo.KernelVersion,
		ClusterName:    proxmoxInfo.ClusterName,
		NodeName:       proxmoxInfo.NodeName,
		RepositoryType: proxmoxInfo.RepositoryType,
	}

	currentHash := hashStruct(proxmoxData)
	h.mu.Lock()
	defer h.mu.Unlock()

	if currentHash != h.lastProxmoxHash {
		heartbeat.Proxmox = proxmoxData
		h.lastProxmoxHash = currentHash
		h.logger.Debug("proxmox info changed, including in heartbeat")
	}
}

// addHyperVInfo adds Hyper-V info to heartbeat if available and changed.
func (h *Handler) addHyperVInfo(ctx context.Context, heartbeat *HeartbeatMessage) {
	hypervInfo := GetHyperVInfo(ctx)
	if hypervInfo == nil {
		return
	}

	hypervData := &HeartbeatHyperV{
		IsHyperV:       hypervInfo.IsHyperV,
		Version:        hypervInfo.Version,
		HostName:       hypervInfo.HostName,
		VMCount:        hypervInfo.VMCount,
		ClusterEnabled: hypervInfo.ClusterEnabled,
	}

	currentHash := hashStruct(hypervData)
	h.mu.Lock()
	defer h.mu.Unlock()

	if currentHash != h.lastHyperVHash {
		heartbeat.HyperV = hypervData
		h.lastHyperVHash = currentHash
		h.logger.Debug("hyperv info changed, including in heartbeat")
	}
}

// addDockerInfo adds Docker info to heartbeat if available and changed.
func (h *Handler) addDockerInfo(ctx context.Context, heartbeat *HeartbeatMessage) {
	dockerInfo := GetDockerInfo(ctx)
	if dockerInfo == nil {
		return
	}

	currentHash := hashStruct(dockerInfo)
	h.mu.Lock()
	defer h.mu.Unlock()

	if currentHash != h.lastDockerHash {
		heartbeat.Docker = dockerInfo
		h.lastDockerHash = currentHash
		h.logger.Debug("docker info changed, including in heartbeat")
	}
}

// addBackupCapabilities adds backup capabilities to heartbeat if changed.
func (h *Handler) addBackupCapabilities(ctx context.Context, heartbeat *HeartbeatMessage) {
	if h.capabilityDetector == nil {
		return
	}

	// Detect capabilities (cached if already detected)
	h.mu.RLock()
	cachedCaps := h.cachedBackupCaps
	h.mu.RUnlock()

	// Refresh capabilities periodically or if not cached
	if cachedCaps == nil {
		caps := h.capabilityDetector.DetectCapabilities(ctx)

		h.mu.Lock()
		h.cachedBackupCaps = caps
		h.mu.Unlock()

		cachedCaps = caps
	}

	// Check if capabilities have changed
	currentHash := hashStruct(cachedCaps)
	h.mu.Lock()
	defer h.mu.Unlock()

	if currentHash != h.lastBackupCapsHash {
		heartbeat.BackupCapabilities = cachedCaps
		h.lastBackupCapsHash = currentHash
		h.logger.Debug("backup capabilities changed, including in heartbeat",
			"available_types", len(cachedCaps.AvailableTypes),
		)
	}
}

// addWingetInfo adds Winget info to heartbeat on Windows.
func (h *Handler) addWingetInfo(ctx context.Context, heartbeat *HeartbeatMessage) {
	if runtime.GOOS != "windows" {
		return
	}

	wingetClient := winget.GetDefault()

	// Check if should refresh
	h.mu.RLock()
	shouldRefresh := h.heartbeatCount%fullHeartbeatInterval == 0
	helperAvailable := h.wingetHelperAvailable
	h.mu.RUnlock()

	if shouldRefresh {
		wingetClient.Refresh()
	}

	status := wingetClient.GetStatus()

	// Handle winget maintenance tasks
	h.handleWingetMaintenance(ctx, status, shouldRefresh)

	// Build winget data
	wingetData := &HeartbeatWinget{
		Available:                   status.Available,
		Version:                     status.Version,
		BinaryPath:                  status.BinaryPath,
		SystemLevel:                 status.SystemLevel,
		HelperAvailable:             helperAvailable,
		PowerShell7Available:        status.PowerShell7Available,
		WinGetClientModuleAvailable: status.WinGetClientModuleAvailable,
	}

	heartbeat.Winget = wingetData

	// Update hash for tracking changes
	currentHash := hashStruct(wingetData)
	h.mu.Lock()
	if currentHash != h.lastWingetHash {
		h.lastWingetHash = currentHash
		h.logger.Debug("winget status changed",
			"available", status.Available,
			"version", status.Version,
			"binary_path", status.BinaryPath,
			"system_level", status.SystemLevel,
		)
	}
	h.mu.Unlock()
}

// handleWingetMaintenance handles winget auto-install, cleanup, and updates.
func (h *Handler) handleWingetMaintenance(ctx context.Context, status winget.Status, shouldRefresh bool) {
	// Auto-install winget if not available
	if !status.Available && shouldRefresh {
		go h.autoInstallWinget(ctx)
	}

	// Periodically clean up per-user winget installations
	if status.Available && shouldRefresh {
		go h.cleanupWingetInstallations(ctx)
	}

	// Check for winget updates
	shouldCheckWingetUpdate := h.heartbeatCount%wingetUpdateInterval == 0
	if status.Available && shouldCheckWingetUpdate {
		go h.checkWingetUpdates(ctx)
	}

	// Bootstrap PowerShell 7 and WinGet.Client module
	if shouldCheckWingetUpdate {
		go h.bootstrapWingetEnvironment(ctx)
	}
}

// autoInstallWinget attempts to auto-install winget.
func (h *Handler) autoInstallWinget(parentCtx context.Context) {
	installCtx, cancel := context.WithTimeout(parentCtx, 10*time.Minute)
	defer cancel()

	h.logger.Info("winget not available, attempting auto-installation")
	if err := winget.EnsureInstalled(installCtx, h.logger); err != nil {
		if parentCtx.Err() != nil {
			h.logger.Debug("winget auto-installation cancelled due to shutdown")
			return
		}
		h.logger.Warn("winget auto-installation failed during heartbeat", "error", err)
	} else {
		h.logger.Info("cleaning up any per-user winget installations")
		_ = winget.EnsureSystemOnly(installCtx, h.logger)
	}
}

// cleanupWingetInstallations cleans up per-user winget installations.
func (h *Handler) cleanupWingetInstallations(parentCtx context.Context) {
	cleanupCtx, cancel := context.WithTimeout(parentCtx, 2*time.Minute)
	defer cancel()
	_ = winget.EnsureSystemOnly(cleanupCtx, h.logger)
}

// checkWingetUpdates checks for and installs winget updates.
func (h *Handler) checkWingetUpdates(parentCtx context.Context) {
	updateCtx, cancel := context.WithTimeout(parentCtx, 10*time.Minute)
	defer cancel()

	h.logger.Info("checking for winget updates (60-minute cycle)")
	updated, err := winget.CheckAndUpdate(updateCtx, h.logger)
	if err != nil {
		if parentCtx.Err() != nil {
			h.logger.Debug("winget update check cancelled due to shutdown")
			return
		}
		h.logger.Warn("winget auto-update check failed", "error", err)
	} else if updated {
		h.logger.Info("winget was auto-updated to latest version")
	}
}

// bootstrapWingetEnvironment bootstraps PowerShell 7 and WinGet.Client module.
func (h *Handler) bootstrapWingetEnvironment(parentCtx context.Context) {
	bootstrapCtx, cancel := context.WithTimeout(parentCtx, 15*time.Minute)
	defer cancel()

	h.logger.Info("bootstrapping WinGet environment (PS7 + WinGet.Client module)")
	changed, err := winget.BootstrapWinGetEnvironment(bootstrapCtx, h.logger)
	if err != nil {
		if parentCtx.Err() != nil {
			h.logger.Debug("WinGet environment bootstrap cancelled due to shutdown")
			return
		}
		h.logger.Warn("WinGet environment bootstrap failed", "error", err)
	} else if changed {
		h.logger.Info("WinGet environment was updated (PS7 or WinGet.Client module installed/updated)")
		winget.GetDefault().Refresh()
	}
}

// incrementHeartbeatCount increments the heartbeat counter and returns whether config should be saved.
func (h *Handler) incrementHeartbeatCount() bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.heartbeatCount++
	shouldSave := h.heartbeatCount >= configSaveInterval
	if shouldSave {
		h.heartbeatCount = 0
	}
	return shouldSave
}
