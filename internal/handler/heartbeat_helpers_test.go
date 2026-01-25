package handler

import (
	"testing"

	"github.com/slimrmm/slimrmm-agent/internal/monitor"
)

func TestBuildDiskStats(t *testing.T) {
	stats := &monitor.Stats{
		Disk: []monitor.DiskStats{
			{
				Device:      "/dev/sda1",
				Mountpoint:  "/",
				Total:       100000000,
				Used:        50000000,
				Free:        50000000,
				UsedPercent: 50.0,
			},
			{
				Device:      "/dev/sda2",
				Mountpoint:  "/home",
				Total:       200000000,
				Used:        100000000,
				Free:        100000000,
				UsedPercent: 50.0,
			},
		},
	}

	diskStats := buildDiskStats(stats)

	if len(diskStats) != 2 {
		t.Errorf("len(diskStats) = %d, want 2", len(diskStats))
	}

	if diskStats[0].Device != "/dev/sda1" {
		t.Errorf("diskStats[0].Device = %s, want /dev/sda1", diskStats[0].Device)
	}

	if diskStats[1].Mountpoint != "/home" {
		t.Errorf("diskStats[1].Mountpoint = %s, want /home", diskStats[1].Mountpoint)
	}
}

func TestBuildDiskStatsEmpty(t *testing.T) {
	stats := &monitor.Stats{
		Disk: []monitor.DiskStats{},
	}

	diskStats := buildDiskStats(stats)

	if len(diskStats) != 0 {
		t.Errorf("len(diskStats) = %d, want 0", len(diskStats))
	}
}

func TestAggregateNetworkIO(t *testing.T) {
	stats := &monitor.Stats{
		Network: []monitor.NetStats{
			{
				BytesSent:   1000,
				BytesRecv:   2000,
				PacketsSent: 10,
				PacketsRecv: 20,
			},
			{
				BytesSent:   3000,
				BytesRecv:   4000,
				PacketsSent: 30,
				PacketsRecv: 40,
			},
		},
	}

	networkIO := aggregateNetworkIO(stats)

	if networkIO.BytesSent != 4000 {
		t.Errorf("BytesSent = %d, want 4000", networkIO.BytesSent)
	}

	if networkIO.BytesRecv != 6000 {
		t.Errorf("BytesRecv = %d, want 6000", networkIO.BytesRecv)
	}

	if networkIO.PacketsSent != 40 {
		t.Errorf("PacketsSent = %d, want 40", networkIO.PacketsSent)
	}

	if networkIO.PacketsRecv != 60 {
		t.Errorf("PacketsRecv = %d, want 60", networkIO.PacketsRecv)
	}
}

func TestAggregateNetworkIOEmpty(t *testing.T) {
	stats := &monitor.Stats{
		Network: []monitor.NetStats{},
	}

	networkIO := aggregateNetworkIO(stats)

	if networkIO.BytesSent != 0 {
		t.Errorf("BytesSent = %d, want 0", networkIO.BytesSent)
	}
}

func TestAggregateNetworkIOSingleInterface(t *testing.T) {
	stats := &monitor.Stats{
		Network: []monitor.NetStats{
			{
				BytesSent:   1000,
				BytesRecv:   2000,
				PacketsSent: 10,
				PacketsRecv: 20,
			},
		},
	}

	networkIO := aggregateNetworkIO(stats)

	if networkIO.BytesSent != 1000 {
		t.Errorf("BytesSent = %d, want 1000", networkIO.BytesSent)
	}

	if networkIO.BytesRecv != 2000 {
		t.Errorf("BytesRecv = %d, want 2000", networkIO.BytesRecv)
	}
}
