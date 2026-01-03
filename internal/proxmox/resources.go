// Package proxmox provides resource types and listing functions.
package proxmox

import (
	"context"
	"sort"

	"github.com/luthermonson/go-proxmox"
)

// ResourceType represents the type of Proxmox resource.
type ResourceType string

const (
	ResourceTypeVM        ResourceType = "qemu"
	ResourceTypeContainer ResourceType = "lxc"
)

// Resource represents a VM or container resource.
type Resource struct {
	VMID        uint64       `json:"vmid"`
	Name        string       `json:"name"`
	Type        ResourceType `json:"type"`
	Status      string       `json:"status"` // running, stopped, paused
	Node        string       `json:"node"`
	CPUs        int          `json:"cpus"`
	MaxMem      uint64       `json:"maxmem"`      // bytes
	MaxDisk     uint64       `json:"maxdisk"`     // bytes
	Uptime      uint64       `json:"uptime"`      // seconds
	NetIn       uint64       `json:"netin"`       // bytes
	NetOut      uint64       `json:"netout"`      // bytes
	DiskRead    uint64       `json:"diskread"`    // bytes
	DiskWrite   uint64       `json:"diskwrite"`   // bytes
	Mem         uint64       `json:"mem"`         // current memory usage
	CPU         float64      `json:"cpu"`         // current CPU usage (0-1)
	Template    bool         `json:"template"`
	Lock        string       `json:"lock,omitempty"` // backup, clone, migrate, etc.
	Tags        string       `json:"tags,omitempty"`
	Description string       `json:"description,omitempty"`
	// Container-specific
	Hostname string `json:"hostname,omitempty"`
	// VM-specific
	QemuAgent bool `json:"qemu_agent,omitempty"`
}

// ResourceList contains a list of resources with summary information.
type ResourceList struct {
	Resources    []Resource `json:"resources"`
	TotalVMs     int        `json:"total_vms"`
	TotalLXC     int        `json:"total_lxc"`
	RunningVMs   int        `json:"running_vms"`
	RunningLXC   int        `json:"running_lxc"`
	TotalCPUs    int        `json:"total_cpus"`
	TotalMemory  uint64     `json:"total_memory"`
	UsedMemory   uint64     `json:"used_memory"`
	ClusterMode  bool       `json:"cluster_mode"`
	NodeName     string     `json:"node_name"`
	ClusterName  string     `json:"cluster_name,omitempty"`
}

// GetResources returns all VMs and containers from the local node or cluster.
func (c *Client) GetResources(ctx context.Context) (*ResourceList, error) {
	result := &ResourceList{
		Resources: make([]Resource, 0),
		NodeName:  c.nodeName,
	}

	// Get all nodes (local or cluster)
	nodes, err := c.GetNodes(ctx)
	if err != nil {
		return nil, err
	}

	result.ClusterMode = len(nodes) > 1

	// Collect resources from all nodes
	for _, node := range nodes {
		// Get VMs
		vms, err := node.VirtualMachines(ctx)
		if err == nil {
			for _, vm := range vms {
				res := vmToResource(vm, node.Name)
				result.Resources = append(result.Resources, res)
				result.TotalVMs++
				if res.Status == "running" {
					result.RunningVMs++
				}
				result.TotalCPUs += res.CPUs
				result.TotalMemory += res.MaxMem
				result.UsedMemory += res.Mem
			}
		}

		// Get Containers
		containers, err := node.Containers(ctx)
		if err == nil {
			for _, ct := range containers {
				res := containerToResource(ct, node.Name)
				result.Resources = append(result.Resources, res)
				result.TotalLXC++
				if res.Status == "running" {
					result.RunningLXC++
				}
				result.TotalCPUs += res.CPUs
				result.TotalMemory += res.MaxMem
				result.UsedMemory += res.Mem
			}
		}
	}

	// Sort by VMID
	sort.Slice(result.Resources, func(i, j int) bool {
		return result.Resources[i].VMID < result.Resources[j].VMID
	})

	// Get cluster name if in cluster mode
	if result.ClusterMode {
		info := Detect(ctx)
		result.ClusterName = info.ClusterName
	}

	return result, nil
}

// GetResource returns a specific resource by VMID.
func (c *Client) GetResource(ctx context.Context, vmid uint64, resourceType ResourceType) (*Resource, error) {
	node, err := c.GetNode(ctx)
	if err != nil {
		return nil, err
	}

	switch resourceType {
	case ResourceTypeVM:
		vm, err := node.VirtualMachine(ctx, int(vmid))
		if err != nil {
			return nil, err
		}
		res := vmToResource(vm, node.Name)
		return &res, nil

	case ResourceTypeContainer:
		ct, err := node.Container(ctx, int(vmid))
		if err != nil {
			return nil, err
		}
		res := containerToResource(ct, node.Name)
		return &res, nil

	default:
		// Try VM first, then container
		if vm, err := node.VirtualMachine(ctx, int(vmid)); err == nil {
			res := vmToResource(vm, node.Name)
			return &res, nil
		}
		if ct, err := node.Container(ctx, int(vmid)); err == nil {
			res := containerToResource(ct, node.Name)
			return &res, nil
		}
		return nil, err
	}
}

// vmToResource converts a Proxmox VM to our Resource type.
func vmToResource(vm *proxmox.VirtualMachine, nodeName string) Resource {
	return Resource{
		VMID:      uint64(vm.VMID),
		Name:      vm.Name,
		Type:      ResourceTypeVM,
		Status:    vm.Status,
		Node:      nodeName,
		CPUs:      vm.CPUs,
		MaxMem:    vm.MaxMem,
		MaxDisk:   vm.MaxDisk,
		Uptime:    vm.Uptime,
		NetIn:     vm.NetIn,
		NetOut:    vm.Netout, // Note: library uses Netout (lowercase 'o')
		DiskRead:  vm.DiskRead,
		DiskWrite: vm.DiskWrite,
		Mem:       vm.Mem,
		CPU:       vm.CPU,
		Template:  bool(vm.Template),
		Lock:      vm.Lock,
		Tags:      vm.Tags,
	}
}

// containerToResource converts a Proxmox container to our Resource type.
// Note: Container has fewer fields than VM in the go-proxmox library
func containerToResource(ct *proxmox.Container, nodeName string) Resource {
	return Resource{
		VMID:    uint64(ct.VMID),
		Name:    ct.Name,
		Type:    ResourceTypeContainer,
		Status:  ct.Status,
		Node:    nodeName,
		CPUs:    ct.CPUs,
		MaxMem:  ct.MaxMem,
		MaxDisk: ct.MaxDisk,
		Uptime:  ct.Uptime,
		Tags:    ct.Tags,
		// Note: Container type doesn't expose NetIn, NetOut, Mem, CPU, etc.
		// These would require additional API calls to get
	}
}

// GetVMs returns only VMs from the local node.
func (c *Client) GetVMs(ctx context.Context) ([]Resource, error) {
	node, err := c.GetNode(ctx)
	if err != nil {
		return nil, err
	}

	vms, err := node.VirtualMachines(ctx)
	if err != nil {
		return nil, err
	}

	resources := make([]Resource, 0, len(vms))
	for _, vm := range vms {
		resources = append(resources, vmToResource(vm, node.Name))
	}

	return resources, nil
}

// GetContainers returns only containers from the local node.
func (c *Client) GetContainers(ctx context.Context) ([]Resource, error) {
	node, err := c.GetNode(ctx)
	if err != nil {
		return nil, err
	}

	containers, err := node.Containers(ctx)
	if err != nil {
		return nil, err
	}

	resources := make([]Resource, 0, len(containers))
	for _, ct := range containers {
		resources = append(resources, containerToResource(ct, node.Name))
	}

	return resources, nil
}
