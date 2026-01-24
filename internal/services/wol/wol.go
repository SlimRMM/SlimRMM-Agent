// Package wol provides Wake-on-LAN functionality for remotely waking devices.
package wol

import (
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

const (
	// MagicPacketSize is the size of a WoL magic packet (6 + 16*6 = 102 bytes).
	MagicPacketSize = 102
	// DefaultPort is the standard WoL port.
	DefaultPort = 9
	// AlternativePort is an alternative WoL port sometimes used.
	AlternativePort = 7
)

var (
	// macRegex validates MAC address formats.
	macRegex = regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$|^([0-9A-Fa-f]{12})$`)
)

// MagicPacket represents a Wake-on-LAN magic packet.
type MagicPacket [MagicPacketSize]byte

// WakeResult contains the result of a WoL operation.
type WakeResult struct {
	MACAddress    string   `json:"mac_address"`
	Success       bool     `json:"success"`
	Error         string   `json:"error,omitempty"`
	BroadcastIPs  []string `json:"broadcast_ips,omitempty"`
	PacketsSent   int      `json:"packets_sent"`
}

// NewMagicPacket creates a new magic packet for the given MAC address.
// The magic packet consists of 6 bytes of 0xFF followed by 16 repetitions
// of the target MAC address.
func NewMagicPacket(mac string) (*MagicPacket, error) {
	macBytes, err := ParseMACAddress(mac)
	if err != nil {
		return nil, err
	}

	var packet MagicPacket

	// First 6 bytes are 0xFF (synchronization stream)
	for i := 0; i < 6; i++ {
		packet[i] = 0xFF
	}

	// Repeat MAC address 16 times
	for i := 0; i < 16; i++ {
		copy(packet[6+i*6:], macBytes)
	}

	return &packet, nil
}

// ParseMACAddress parses a MAC address string into bytes.
// Supports formats: "AA:BB:CC:DD:EE:FF", "AA-BB-CC-DD-EE-FF", "AABBCCDDEEFF".
func ParseMACAddress(mac string) ([]byte, error) {
	mac = strings.TrimSpace(mac)

	if !macRegex.MatchString(mac) {
		return nil, fmt.Errorf("invalid MAC address format: %s", mac)
	}

	// Remove separators
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, "-", "")

	// Decode hex string
	bytes, err := hex.DecodeString(mac)
	if err != nil {
		return nil, fmt.Errorf("failed to decode MAC address: %w", err)
	}

	if len(bytes) != 6 {
		return nil, fmt.Errorf("MAC address must be 6 bytes, got %d", len(bytes))
	}

	return bytes, nil
}

// IsValidMACAddress checks if a MAC address string is valid.
func IsValidMACAddress(mac string) bool {
	mac = strings.TrimSpace(mac)
	return macRegex.MatchString(mac)
}

// NormalizeMACAddress converts a MAC address to the standard format (XX:XX:XX:XX:XX:XX).
func NormalizeMACAddress(mac string) (string, error) {
	bytes, err := ParseMACAddress(mac)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]), nil
}

// Service provides Wake-on-LAN functionality.
type Service struct{}

// NewService creates a new WoL service.
func NewService() *Service {
	return &Service{}
}

// Wake sends a WoL magic packet to the specified MAC address.
// It broadcasts the packet to all available network interfaces.
func (s *Service) Wake(mac string) (*WakeResult, error) {
	return s.WakeWithOptions(mac, DefaultPort, "")
}

// WakeWithOptions sends a WoL magic packet with custom options.
// If broadcastIP is empty, it broadcasts to all available interfaces.
func (s *Service) WakeWithOptions(mac string, port int, broadcastIP string) (*WakeResult, error) {
	result := &WakeResult{
		MACAddress:   mac,
		BroadcastIPs: []string{},
	}

	// Normalize and validate MAC address
	normalizedMAC, err := NormalizeMACAddress(mac)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	result.MACAddress = normalizedMAC

	// Create magic packet
	packet, err := NewMagicPacket(mac)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Get broadcast addresses
	var broadcastAddrs []string
	if broadcastIP != "" {
		broadcastAddrs = []string{broadcastIP}
	} else {
		broadcastAddrs = s.getBroadcastAddresses()
		// Always include the standard broadcast address
		broadcastAddrs = append(broadcastAddrs, "255.255.255.255")
	}

	result.BroadcastIPs = broadcastAddrs

	// Send to each broadcast address
	var lastErr error
	for _, addr := range broadcastAddrs {
		err := s.sendPacket(packet, addr, port)
		if err != nil {
			lastErr = err
		} else {
			result.PacketsSent++
		}
	}

	// Also try the alternative port
	if port == DefaultPort {
		for _, addr := range broadcastAddrs {
			err := s.sendPacket(packet, addr, AlternativePort)
			if err == nil {
				result.PacketsSent++
			}
		}
	}

	if result.PacketsSent > 0 {
		result.Success = true
	} else if lastErr != nil {
		result.Error = lastErr.Error()
		return result, lastErr
	}

	return result, nil
}

// sendPacket sends a magic packet to the specified address and port.
func (s *Service) sendPacket(packet *MagicPacket, broadcastIP string, port int) error {
	addr := net.JoinHostPort(broadcastIP, strconv.Itoa(port))

	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to create UDP connection to %s: %w", addr, err)
	}
	defer conn.Close()

	// Enable broadcast
	if udpConn, ok := conn.(*net.UDPConn); ok {
		udpConn.SetWriteBuffer(MagicPacketSize)
	}

	n, err := conn.Write(packet[:])
	if err != nil {
		return fmt.Errorf("failed to send magic packet to %s: %w", addr, err)
	}

	if n != MagicPacketSize {
		return fmt.Errorf("incomplete packet sent to %s: %d/%d bytes", addr, n, MagicPacketSize)
	}

	return nil
}

// getBroadcastAddresses returns broadcast addresses for all network interfaces.
func (s *Service) getBroadcastAddresses() []string {
	var broadcasts []string
	seen := make(map[string]bool)

	interfaces, err := net.Interfaces()
	if err != nil {
		return broadcasts
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// Only IPv4
			ip4 := ipNet.IP.To4()
			if ip4 == nil {
				continue
			}

			// Calculate broadcast address
			broadcast := calculateBroadcast(ip4, ipNet.Mask)
			if broadcast != nil {
				broadcastStr := broadcast.String()
				if !seen[broadcastStr] {
					seen[broadcastStr] = true
					broadcasts = append(broadcasts, broadcastStr)
				}
			}
		}
	}

	return broadcasts
}

// calculateBroadcast calculates the broadcast address for a given IP and mask.
func calculateBroadcast(ip net.IP, mask net.IPMask) net.IP {
	if len(ip) != 4 || len(mask) != 4 {
		return nil
	}

	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = ip[i] | ^mask[i]
	}

	return broadcast
}

// GetNetworkInterfaces returns information about network interfaces including MAC addresses.
func (s *Service) GetNetworkInterfaces() ([]NetworkInterface, error) {
	var result []NetworkInterface

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		// Skip interfaces without MAC address
		if len(iface.HardwareAddr) == 0 {
			continue
		}

		ni := NetworkInterface{
			Name:       iface.Name,
			MACAddress: iface.HardwareAddr.String(),
			Flags:      iface.Flags.String(),
			MTU:        iface.MTU,
			IsUp:       iface.Flags&net.FlagUp != 0,
			IsLoopback: iface.Flags&net.FlagLoopback != 0,
		}

		// Get IP addresses
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok {
					if ipNet.IP.To4() != nil {
						ni.IPv4Addresses = append(ni.IPv4Addresses, ipNet.IP.String())
						ni.IPv4Subnets = append(ni.IPv4Subnets, ipNet.String())
					} else {
						ni.IPv6Addresses = append(ni.IPv6Addresses, ipNet.IP.String())
					}
				}
			}
		}

		result = append(result, ni)
	}

	return result, nil
}

// NetworkInterface contains information about a network interface.
type NetworkInterface struct {
	Name          string   `json:"name"`
	MACAddress    string   `json:"mac_address"`
	IPv4Addresses []string `json:"ipv4_addresses,omitempty"`
	IPv4Subnets   []string `json:"ipv4_subnets,omitempty"`
	IPv6Addresses []string `json:"ipv6_addresses,omitempty"`
	Flags         string   `json:"flags"`
	MTU           int      `json:"mtu"`
	IsUp          bool     `json:"is_up"`
	IsLoopback    bool     `json:"is_loopback"`
}
