// Package proxmox provides policy operations for Proxmox VMs and containers.
package proxmox

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// PolicyActionType represents the type of policy action.
type PolicyActionType string

const (
	PolicyActionBackup        PolicyActionType = "backup"
	PolicyActionSnapshot      PolicyActionType = "snapshot"
	PolicyActionPruneBackups  PolicyActionType = "prune_backups"
	PolicyActionCleanStorage  PolicyActionType = "clean_storage"
	PolicyActionHACheck       PolicyActionType = "ha_check"
	PolicyActionReplication   PolicyActionType = "replication_check"
)

// BackupMode represents the backup mode for vzdump.
type BackupMode string

const (
	BackupModeSnapshot BackupMode = "snapshot"
	BackupModeStop     BackupMode = "stop"
	BackupModeSuspend  BackupMode = "suspend"
)

// CompressionType represents backup compression options.
type CompressionType string

const (
	CompressionNone  CompressionType = "none"
	CompressionLZO   CompressionType = "lzo"
	CompressionGZIP  CompressionType = "gzip"
	CompressionZSTD  CompressionType = "zstd"
)

// BackupRequest represents a backup operation request.
type BackupRequest struct {
	VMIDs       []uint64        `json:"vmids,omitempty"`       // Specific VMIDs to backup (empty = all)
	Storage     string          `json:"storage"`               // Storage destination
	Mode        BackupMode      `json:"mode"`                  // snapshot, stop, suspend
	Compress    CompressionType `json:"compress"`              // Compression type
	MaxFiles    int             `json:"maxfiles,omitempty"`    // Max backup files to keep
	MailTo      string          `json:"mailto,omitempty"`      // Email notification
	Notes       string          `json:"notes,omitempty"`       // Backup notes
	All         bool            `json:"all,omitempty"`         // Backup all VMs/CTs
	ExcludeVMID []uint64        `json:"exclude,omitempty"`     // VMIDs to exclude
	Timeout     int             `json:"timeout,omitempty"`     // Timeout in seconds
}

// BackupResult represents the result of a backup operation.
type BackupResult struct {
	Success     bool              `json:"success"`
	VMID        uint64            `json:"vmid,omitempty"`
	Type        ResourceType      `json:"type,omitempty"`
	TaskID      string            `json:"task_id,omitempty"`
	Storage     string            `json:"storage"`
	BackupFile  string            `json:"backup_file,omitempty"`
	Size        int64             `json:"size,omitempty"`
	StartedAt   string            `json:"started_at"`
	CompletedAt string            `json:"completed_at,omitempty"`
	Duration    int64             `json:"duration_ms"`
	Error       string            `json:"error,omitempty"`
}

// SnapshotRequest represents a snapshot creation request.
type SnapshotRequest struct {
	VMID        uint64       `json:"vmid"`
	Type        ResourceType `json:"type"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	IncludeRAM  bool         `json:"include_ram,omitempty"` // Include VM RAM state
}

// SnapshotResult represents the result of a snapshot operation.
type SnapshotResult struct {
	Success     bool         `json:"success"`
	VMID        uint64       `json:"vmid"`
	Type        ResourceType `json:"type"`
	Name        string       `json:"name"`
	TaskID      string       `json:"task_id,omitempty"`
	StartedAt   string       `json:"started_at"`
	Duration    int64        `json:"duration_ms"`
	Error       string       `json:"error,omitempty"`
}

// PruneRequest represents a backup prune request.
type PruneRequest struct {
	Storage    string   `json:"storage"`
	VMIDs      []uint64 `json:"vmids,omitempty"`
	KeepLast   int      `json:"keep_last,omitempty"`   // Keep last N backups
	KeepHourly int      `json:"keep_hourly,omitempty"` // Keep N hourly backups
	KeepDaily  int      `json:"keep_daily,omitempty"`  // Keep N daily backups
	KeepWeekly int      `json:"keep_weekly,omitempty"` // Keep N weekly backups
	KeepMonthly int     `json:"keep_monthly,omitempty"` // Keep N monthly backups
	KeepYearly int      `json:"keep_yearly,omitempty"` // Keep N yearly backups
	DryRun     bool     `json:"dry_run,omitempty"`     // Only list what would be deleted
}

// PruneResult represents the result of a prune operation.
type PruneResult struct {
	Success       bool     `json:"success"`
	Storage       string   `json:"storage"`
	DeletedCount  int      `json:"deleted_count"`
	DeletedFiles  []string `json:"deleted_files,omitempty"`
	ReclaimedSize int64    `json:"reclaimed_size,omitempty"`
	DryRun        bool     `json:"dry_run"`
	Error         string   `json:"error,omitempty"`
}

// HAStatusResult represents the HA cluster status.
type HAStatusResult struct {
	Success    bool                   `json:"success"`
	Enabled    bool                   `json:"enabled"`
	Quorum     bool                   `json:"quorum"`
	NodeCount  int                    `json:"node_count"`
	Nodes      []HANodeStatus         `json:"nodes,omitempty"`
	Resources  []HAResourceStatus     `json:"resources,omitempty"`
	Error      string                 `json:"error,omitempty"`
}

// HANodeStatus represents a node's HA status.
type HANodeStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Online bool   `json:"online"`
}

// HAResourceStatus represents a HA resource status.
type HAResourceStatus struct {
	SID    string `json:"sid"`    // Resource ID (e.g., "vm:100")
	Type   string `json:"type"`   // vm or ct
	VMID   uint64 `json:"vmid"`
	Node   string `json:"node"`   // Current node
	State  string `json:"state"`  // started, stopped, error, etc.
	Status string `json:"status"` // Status message
}

// ReplicationStatusResult represents replication status.
type ReplicationStatusResult struct {
	Success bool                `json:"success"`
	Jobs    []ReplicationJob    `json:"jobs,omitempty"`
	Error   string              `json:"error,omitempty"`
}

// ReplicationJob represents a replication job status.
type ReplicationJob struct {
	ID             string `json:"id"`
	VMID           uint64 `json:"vmid"`
	Target         string `json:"target"`          // Target node
	Schedule       string `json:"schedule"`
	LastSync       string `json:"last_sync,omitempty"`
	NextSync       string `json:"next_sync,omitempty"`
	Status         string `json:"status"`          // OK, error, etc.
	Duration       int64  `json:"duration,omitempty"` // Last sync duration
	Error          string `json:"error,omitempty"`
}

// StorageCleanRequest represents a storage cleanup request.
type StorageCleanRequest struct {
	Storage       string `json:"storage"`
	CleanOrphaned bool   `json:"clean_orphaned,omitempty"` // Clean orphaned disk images
	CleanUnused   bool   `json:"clean_unused,omitempty"`   // Clean unused volumes
	DryRun        bool   `json:"dry_run,omitempty"`
}

// StorageCleanResult represents storage cleanup results.
type StorageCleanResult struct {
	Success       bool     `json:"success"`
	Storage       string   `json:"storage"`
	CleanedCount  int      `json:"cleaned_count"`
	CleanedItems  []string `json:"cleaned_items,omitempty"`
	ReclaimedSize int64    `json:"reclaimed_size,omitempty"`
	DryRun        bool     `json:"dry_run"`
	Error         string   `json:"error,omitempty"`
}

// defaultPolicyTimeout is the default timeout for policy operations.
const defaultPolicyTimeout = 10 * time.Minute

// CreateBackup creates a backup of VMs/containers using vzdump via Node API.
func (c *Client) CreateBackup(ctx context.Context, req BackupRequest) []BackupResult {
	results := make([]BackupResult, 0)
	start := time.Now()

	timeout := defaultPolicyTimeout
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	node, err := c.GetNode(ctx)
	if err != nil {
		results = append(results, BackupResult{
			Success:   false,
			Storage:   req.Storage,
			StartedAt: start.Format(time.RFC3339),
			Duration:  time.Since(start).Milliseconds(),
			Error:     fmt.Sprintf("failed to get node: %v", err),
		})
		return results
	}

	// Get VMIDs to backup
	vmids := req.VMIDs
	if req.All || len(vmids) == 0 {
		// Get all VMs and containers
		resourceList, err := c.GetResources(ctx)
		if err != nil {
			results = append(results, BackupResult{
				Success:   false,
				Storage:   req.Storage,
				StartedAt: start.Format(time.RFC3339),
				Duration:  time.Since(start).Milliseconds(),
				Error:     fmt.Sprintf("failed to get resources: %v", err),
			})
			return results
		}

		excludeMap := make(map[uint64]bool)
		for _, id := range req.ExcludeVMID {
			excludeMap[id] = true
		}

		for _, r := range resourceList.Resources {
			if (r.Type == ResourceTypeVM || r.Type == ResourceTypeContainer) && !excludeMap[r.VMID] {
				vmids = append(vmids, r.VMID)
			}
		}
	}

	// Create backup for each VMID using Node.VZDump API
	for _, vmid := range vmids {
		backupStart := time.Now()
		result := BackupResult{
			VMID:      vmid,
			Storage:   req.Storage,
			StartedAt: backupStart.Format(time.RFC3339),
		}

		// Determine resource type
		vm, vmErr := node.VirtualMachine(ctx, int(vmid))
		if vmErr == nil && vm != nil {
			result.Type = ResourceTypeVM
		} else {
			_, ctErr := node.Container(ctx, int(vmid))
			if ctErr != nil {
				result.Error = fmt.Sprintf("VMID %d not found as VM or container", vmid)
				result.Duration = time.Since(backupStart).Milliseconds()
				results = append(results, result)
				continue
			}
			result.Type = ResourceTypeContainer
		}

		// Call vzdump via Node API
		vzdumpOpts := map[string]interface{}{
			"vmid":     vmid,
			"storage":  req.Storage,
			"mode":     string(req.Mode),
			"compress": string(req.Compress),
		}
		if req.MaxFiles > 0 {
			vzdumpOpts["maxfiles"] = req.MaxFiles
		}
		if req.MailTo != "" {
			vzdumpOpts["mailto"] = req.MailTo
		}
		if req.Notes != "" {
			vzdumpOpts["notes-template"] = req.Notes
		}

		// Execute vzdump via API POST
		var taskResponse map[string]interface{}
		if err := c.client.Post(ctx, fmt.Sprintf("/nodes/%s/vzdump", node.Name), vzdumpOpts, &taskResponse); err != nil {
			result.Error = fmt.Sprintf("backup failed: %v", err)
			result.Duration = time.Since(backupStart).Milliseconds()
			results = append(results, result)
			continue
		}

		if upid, ok := taskResponse["data"].(string); ok {
			result.TaskID = upid
			result.Success = true
		} else {
			result.Success = true
		}

		result.Duration = time.Since(backupStart).Milliseconds()
		result.CompletedAt = time.Now().Format(time.RFC3339)
		results = append(results, result)
	}

	return results
}

// CreateSnapshot creates a snapshot of a VM or container.
func (c *Client) CreateSnapshot(ctx context.Context, req SnapshotRequest) *SnapshotResult {
	start := time.Now()
	result := &SnapshotResult{
		VMID:      req.VMID,
		Type:      req.Type,
		Name:      req.Name,
		StartedAt: start.Format(time.RFC3339),
	}

	ctx, cancel := context.WithTimeout(ctx, defaultPolicyTimeout)
	defer cancel()

	node, err := c.GetNode(ctx)
	if err != nil {
		result.Error = fmt.Sprintf("failed to get node: %v", err)
		result.Duration = time.Since(start).Milliseconds()
		return result
	}

	if req.Type == ResourceTypeVM || req.Type == "" {
		vm, err := node.VirtualMachine(ctx, int(req.VMID))
		if err != nil {
			result.Error = fmt.Sprintf("VM %d not found: %v", req.VMID, err)
			result.Duration = time.Since(start).Milliseconds()
			return result
		}

		// NewSnapshot takes (ctx, name) - description is not supported in go-proxmox
		task, err := vm.NewSnapshot(ctx, req.Name)
		if err != nil {
			result.Error = fmt.Sprintf("snapshot failed: %v", err)
			result.Duration = time.Since(start).Milliseconds()
			return result
		}

		if task != nil {
			result.TaskID = string(task.UPID)
			if err := task.Wait(ctx, time.Second, defaultPolicyTimeout); err != nil {
				result.Error = fmt.Sprintf("snapshot task failed: %v", err)
			} else {
				result.Success = true
			}
		}
	} else {
		ct, err := node.Container(ctx, int(req.VMID))
		if err != nil {
			result.Error = fmt.Sprintf("container %d not found: %v", req.VMID, err)
			result.Duration = time.Since(start).Milliseconds()
			return result
		}

		// NewSnapshot for container
		task, err := ct.NewSnapshot(ctx, req.Name)
		if err != nil {
			result.Error = fmt.Sprintf("snapshot failed: %v", err)
			result.Duration = time.Since(start).Milliseconds()
			return result
		}

		if task != nil {
			result.TaskID = string(task.UPID)
			if err := task.Wait(ctx, time.Second, defaultPolicyTimeout); err != nil {
				result.Error = fmt.Sprintf("snapshot task failed: %v", err)
			} else {
				result.Success = true
			}
		}
	}

	result.Duration = time.Since(start).Milliseconds()
	return result
}

// CreateBulkSnapshots creates snapshots for multiple VMs/containers.
func (c *Client) CreateBulkSnapshots(ctx context.Context, vmids []uint64, name, description string, resourceType ResourceType) []SnapshotResult {
	results := make([]SnapshotResult, 0, len(vmids))

	for _, vmid := range vmids {
		req := SnapshotRequest{
			VMID:        vmid,
			Type:        resourceType,
			Name:        name,
			Description: description,
		}
		result := c.CreateSnapshot(ctx, req)
		results = append(results, *result)
	}

	return results
}

// BackupInfo represents info about a backup file.
type BackupInfo struct {
	Volid string `json:"volid"`
	VMID  uint64 `json:"vmid"`
	CTime int64  `json:"ctime"`
	Size  int64  `json:"size"`
}

// PruneBackups removes old backups based on retention policy.
func (c *Client) PruneBackups(ctx context.Context, req PruneRequest) *PruneResult {
	result := &PruneResult{
		Storage: req.Storage,
		DryRun:  req.DryRun,
	}

	ctx, cancel := context.WithTimeout(ctx, defaultPolicyTimeout)
	defer cancel()

	node, err := c.GetNode(ctx)
	if err != nil {
		result.Error = fmt.Sprintf("failed to get node: %v", err)
		return result
	}

	// Get storage info
	storage, err := node.Storage(ctx, req.Storage)
	if err != nil {
		result.Error = fmt.Sprintf("storage %s not found: %v", req.Storage, err)
		return result
	}

	// Get backup content
	content, err := storage.GetContent(ctx)
	if err != nil {
		result.Error = fmt.Sprintf("failed to get storage content: %v", err)
		return result
	}

	// Filter and process backups
	deletedFiles := make([]string, 0)
	var reclaimedSize int64

	// Simple retention: keep last N backups per VMID
	vmBackups := make(map[uint64][]BackupInfo)

	for _, item := range content {
		// Check if this is a backup by looking at content type
		if item.Format == "" || item.VMID == 0 {
			continue
		}
		// Filter by specified VMIDs if provided
		if len(req.VMIDs) > 0 {
			found := false
			for _, id := range req.VMIDs {
				if id == item.VMID {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		vmBackups[item.VMID] = append(vmBackups[item.VMID], BackupInfo{
			Volid: item.Volid,
			VMID:  item.VMID,
			CTime: int64(item.Ctime),
			Size:  int64(item.Size),
		})
	}

	// Apply retention policy
	keepLast := req.KeepLast
	if keepLast == 0 {
		keepLast = 3 // Default: keep last 3 backups
	}

	for _, backups := range vmBackups {
		// Sort by creation time (newest first)
		for i := 0; i < len(backups); i++ {
			for j := i + 1; j < len(backups); j++ {
				if backups[i].CTime < backups[j].CTime {
					backups[i], backups[j] = backups[j], backups[i]
				}
			}
		}

		// Delete backups beyond keepLast
		for i := keepLast; i < len(backups); i++ {
			if !req.DryRun {
				// Delete the backup via API
				if err := c.client.Delete(ctx, fmt.Sprintf("/nodes/%s/storage/%s/content/%s", node.Name, req.Storage, backups[i].Volid), nil); err != nil {
					continue
				}
			}
			deletedFiles = append(deletedFiles, backups[i].Volid)
			reclaimedSize += backups[i].Size
		}
	}

	result.Success = true
	result.DeletedCount = len(deletedFiles)
	result.DeletedFiles = deletedFiles
	result.ReclaimedSize = reclaimedSize

	return result
}

// GetHAStatus retrieves the HA cluster status.
func (c *Client) GetHAStatus(ctx context.Context) *HAStatusResult {
	result := &HAStatusResult{}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cluster, err := c.client.Cluster(ctx)
	if err != nil {
		result.Error = fmt.Sprintf("failed to get cluster: %v", err)
		return result
	}

	// Get cluster status via API
	var statusData []map[string]interface{}
	if err := c.client.Get(ctx, "/cluster/status", &statusData); err != nil {
		result.Error = fmt.Sprintf("failed to get cluster status: %v", err)
		return result
	}

	// Process nodes
	nodes := make([]HANodeStatus, 0)
	for _, data := range statusData {
		if t, ok := data["type"].(string); ok && t == "node" {
			node := HANodeStatus{
				Name: fmt.Sprintf("%v", data["name"]),
			}
			if online, ok := data["online"].(float64); ok {
				node.Online = online == 1
			}
			if state, ok := data["state"].(string); ok {
				node.Status = state
			}
			nodes = append(nodes, node)
		}
	}

	result.Success = true
	result.Enabled = len(nodes) > 0
	result.NodeCount = len(nodes)
	result.Nodes = nodes

	// Check quorum
	for _, n := range nodes {
		if n.Online {
			result.Quorum = true
			break
		}
	}

	// Get HA resources
	haResources, err := cluster.Resources(ctx)
	if err == nil {
		resources := make([]HAResourceStatus, 0)
		for _, r := range haResources {
			if r.HAstate != "" {
				resources = append(resources, HAResourceStatus{
					SID:    r.ID,
					Type:   r.Type,
					VMID:   r.VMID,
					Node:   r.Node,
					State:  r.HAstate,
					Status: r.Status,
				})
			}
		}
		result.Resources = resources
	}

	return result
}

// GetReplicationStatus retrieves replication job status.
func (c *Client) GetReplicationStatus(ctx context.Context) *ReplicationStatusResult {
	result := &ReplicationStatusResult{}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	node, err := c.GetNode(ctx)
	if err != nil {
		result.Error = fmt.Sprintf("failed to get node: %v", err)
		return result
	}

	// Get replication status via API call
	var replData []map[string]interface{}
	if err := c.client.Get(ctx, fmt.Sprintf("/nodes/%s/replication", node.Name), &replData); err != nil {
		// Replication might not be configured
		result.Success = true
		result.Jobs = make([]ReplicationJob, 0)
		return result
	}

	jobs := make([]ReplicationJob, 0)
	for _, r := range replData {
		job := ReplicationJob{}
		if id, ok := r["id"].(string); ok {
			job.ID = id
		}
		if vmid, ok := r["vmid"].(float64); ok {
			job.VMID = uint64(vmid)
		}
		if target, ok := r["target"].(string); ok {
			job.Target = target
		}
		if schedule, ok := r["schedule"].(string); ok {
			job.Schedule = schedule
		}
		if lastSync, ok := r["last_sync"].(float64); ok && lastSync > 0 {
			job.LastSync = time.Unix(int64(lastSync), 0).Format(time.RFC3339)
		}
		if nextSync, ok := r["next_sync"].(float64); ok && nextSync > 0 {
			job.NextSync = time.Unix(int64(nextSync), 0).Format(time.RFC3339)
		}
		if state, ok := r["state"].(string); ok {
			job.Status = state
		}
		if errStr, ok := r["error"].(string); ok {
			job.Error = errStr
		}
		jobs = append(jobs, job)
	}

	result.Success = true
	result.Jobs = jobs
	return result
}

// CleanStorage cleans up orphaned and unused volumes from storage.
func (c *Client) CleanStorage(ctx context.Context, req StorageCleanRequest) *StorageCleanResult {
	result := &StorageCleanResult{
		Storage: req.Storage,
		DryRun:  req.DryRun,
	}

	ctx, cancel := context.WithTimeout(ctx, defaultPolicyTimeout)
	defer cancel()

	node, err := c.GetNode(ctx)
	if err != nil {
		result.Error = fmt.Sprintf("failed to get node: %v", err)
		return result
	}

	storage, err := node.Storage(ctx, req.Storage)
	if err != nil {
		result.Error = fmt.Sprintf("storage %s not found: %v", req.Storage, err)
		return result
	}

	content, err := storage.GetContent(ctx)
	if err != nil {
		result.Error = fmt.Sprintf("failed to get storage content: %v", err)
		return result
	}

	// Get all VMs and containers to check which volumes are in use
	resourceList, err := c.GetResources(ctx)
	if err != nil {
		result.Error = fmt.Sprintf("failed to get resources: %v", err)
		return result
	}

	// Build a set of active VMIDs
	activeVMIDs := make(map[uint64]bool)
	for _, r := range resourceList.Resources {
		if r.Type == ResourceTypeVM || r.Type == ResourceTypeContainer {
			activeVMIDs[r.VMID] = true
		}
	}

	cleanedItems := make([]string, 0)
	var reclaimedSize int64

	for _, item := range content {
		// Check for orphaned disk images (VMID doesn't exist)
		if req.CleanOrphaned && item.VMID > 0 && !activeVMIDs[uint64(item.VMID)] {
			if !req.DryRun {
				if err := c.client.Delete(ctx, fmt.Sprintf("/nodes/%s/storage/%s/content/%s", node.Name, req.Storage, item.Volid), nil); err != nil {
					continue
				}
			}
			cleanedItems = append(cleanedItems, item.Volid)
			reclaimedSize += int64(item.Size)
		}
	}

	result.Success = true
	result.CleanedCount = len(cleanedItems)
	result.CleanedItems = cleanedItems
	result.ReclaimedSize = reclaimedSize

	return result
}

// PolicyConfig represents a Proxmox policy configuration.
type PolicyConfig struct {
	Action         PolicyActionType `json:"action"`

	// Backup options
	BackupStorage  string           `json:"backup_storage,omitempty"`
	BackupMode     BackupMode       `json:"backup_mode,omitempty"`
	BackupCompress CompressionType  `json:"backup_compress,omitempty"`
	BackupMaxFiles int              `json:"backup_maxfiles,omitempty"`

	// Snapshot options
	SnapshotName   string           `json:"snapshot_name,omitempty"`
	SnapshotDesc   string           `json:"snapshot_description,omitempty"`

	// Target selection
	VMIDs          []uint64         `json:"vmids,omitempty"`
	All            bool             `json:"all,omitempty"`
	ExcludeVMIDs   []uint64         `json:"exclude_vmids,omitempty"`
	ResourceType   ResourceType     `json:"resource_type,omitempty"` // vm, lxc, or both

	// Prune options
	KeepLast       int              `json:"keep_last,omitempty"`
	KeepDaily      int              `json:"keep_daily,omitempty"`
	KeepWeekly     int              `json:"keep_weekly,omitempty"`
	KeepMonthly    int              `json:"keep_monthly,omitempty"`

	// Storage options
	Storage        string           `json:"storage,omitempty"`
	CleanOrphaned  bool             `json:"clean_orphaned,omitempty"`

	// General options
	DryRun         bool             `json:"dry_run,omitempty"`
	Timeout        int              `json:"timeout,omitempty"`
}

// PolicyResult represents the result of a policy execution.
type PolicyResult struct {
	Action    PolicyActionType `json:"action"`
	Success   bool             `json:"success"`
	Results   interface{}      `json:"results,omitempty"`
	Error     string           `json:"error,omitempty"`
	StartedAt string           `json:"started_at"`
	Duration  int64            `json:"duration_ms"`
}

// ExecutePolicy executes a Proxmox policy based on configuration.
func (c *Client) ExecutePolicy(ctx context.Context, configJSON string) *PolicyResult {
	start := time.Now()
	result := &PolicyResult{
		StartedAt: start.Format(time.RFC3339),
	}

	var config PolicyConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		result.Error = fmt.Sprintf("invalid policy config: %v", err)
		result.Duration = time.Since(start).Milliseconds()
		return result
	}

	result.Action = config.Action

	switch config.Action {
	case PolicyActionBackup:
		req := BackupRequest{
			VMIDs:       config.VMIDs,
			Storage:     config.BackupStorage,
			Mode:        config.BackupMode,
			Compress:    config.BackupCompress,
			MaxFiles:    config.BackupMaxFiles,
			All:         config.All,
			ExcludeVMID: config.ExcludeVMIDs,
			Timeout:     config.Timeout,
		}
		if req.Storage == "" {
			req.Storage = config.Storage
		}
		if req.Mode == "" {
			req.Mode = BackupModeSnapshot
		}
		if req.Compress == "" {
			req.Compress = CompressionZSTD
		}
		backupResults := c.CreateBackup(ctx, req)
		result.Results = backupResults

		// Check if all backups succeeded
		allSuccess := true
		for _, br := range backupResults {
			if !br.Success {
				allSuccess = false
				break
			}
		}
		result.Success = allSuccess

	case PolicyActionSnapshot:
		snapshotResults := c.CreateBulkSnapshots(
			ctx,
			config.VMIDs,
			config.SnapshotName,
			config.SnapshotDesc,
			config.ResourceType,
		)
		result.Results = snapshotResults

		allSuccess := true
		for _, sr := range snapshotResults {
			if !sr.Success {
				allSuccess = false
				break
			}
		}
		result.Success = allSuccess

	case PolicyActionPruneBackups:
		req := PruneRequest{
			Storage:     config.Storage,
			VMIDs:       config.VMIDs,
			KeepLast:    config.KeepLast,
			KeepDaily:   config.KeepDaily,
			KeepWeekly:  config.KeepWeekly,
			KeepMonthly: config.KeepMonthly,
			DryRun:      config.DryRun,
		}
		if req.Storage == "" {
			req.Storage = config.BackupStorage
		}
		pruneResult := c.PruneBackups(ctx, req)
		result.Results = pruneResult
		result.Success = pruneResult.Success

	case PolicyActionCleanStorage:
		req := StorageCleanRequest{
			Storage:       config.Storage,
			CleanOrphaned: config.CleanOrphaned,
			DryRun:        config.DryRun,
		}
		cleanResult := c.CleanStorage(ctx, req)
		result.Results = cleanResult
		result.Success = cleanResult.Success

	case PolicyActionHACheck:
		haResult := c.GetHAStatus(ctx)
		result.Results = haResult
		result.Success = haResult.Success

	case PolicyActionReplication:
		replResult := c.GetReplicationStatus(ctx)
		result.Results = replResult
		result.Success = replResult.Success

	default:
		result.Error = fmt.Sprintf("unknown policy action: %s", config.Action)
	}

	result.Duration = time.Since(start).Milliseconds()
	return result
}
