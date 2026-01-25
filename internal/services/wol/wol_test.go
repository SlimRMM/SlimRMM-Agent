package wol

import (
	"net"
	"testing"
)

func TestParseMACAddress(t *testing.T) {
	tests := []struct {
		name    string
		mac     string
		wantErr bool
	}{
		// Valid formats
		{"colon separated", "AA:BB:CC:DD:EE:FF", false},
		{"colon lowercase", "aa:bb:cc:dd:ee:ff", false},
		{"dash separated", "AA-BB-CC-DD-EE-FF", false},
		{"no separator", "AABBCCDDEEFF", false},
		{"mixed case", "aA:Bb:cC:dD:eE:fF", false},
		{"with spaces", "  AA:BB:CC:DD:EE:FF  ", false},

		// Invalid formats
		{"empty", "", true},
		{"too short", "AA:BB:CC:DD:EE", true},
		{"too long", "AA:BB:CC:DD:EE:FF:00", true},
		{"invalid char", "GG:BB:CC:DD:EE:FF", true},
		{"partial separator", "AA:BBCC:DD:EE:FF", true},
		{"wrong separator", "AA.BB.CC.DD.EE.FF", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseMACAddress(tt.mac)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMACAddress(%q) error = %v, wantErr %v", tt.mac, err, tt.wantErr)
			}
		})
	}
}

func TestParseMACAddressBytes(t *testing.T) {
	bytes, err := ParseMACAddress("AA:BB:CC:DD:EE:FF")
	if err != nil {
		t.Fatalf("ParseMACAddress failed: %v", err)
	}

	expected := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	if len(bytes) != len(expected) {
		t.Fatalf("expected %d bytes, got %d", len(expected), len(bytes))
	}

	for i, b := range bytes {
		if b != expected[i] {
			t.Errorf("byte %d: expected 0x%02X, got 0x%02X", i, expected[i], b)
		}
	}
}

func TestIsValidMACAddress(t *testing.T) {
	tests := []struct {
		mac     string
		isValid bool
	}{
		{"AA:BB:CC:DD:EE:FF", true},
		{"aa:bb:cc:dd:ee:ff", true},
		{"AA-BB-CC-DD-EE-FF", true},
		{"AABBCCDDEEFF", true},
		{"", false},
		{"invalid", false},
		{"AA:BB:CC:DD:EE", false},
	}

	for _, tt := range tests {
		t.Run(tt.mac, func(t *testing.T) {
			got := IsValidMACAddress(tt.mac)
			if got != tt.isValid {
				t.Errorf("IsValidMACAddress(%q) = %v, want %v", tt.mac, got, tt.isValid)
			}
		})
	}
}

func TestNormalizeMACAddress(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF", false},
		{"aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF", false},
		{"AA-BB-CC-DD-EE-FF", "AA:BB:CC:DD:EE:FF", false},
		{"AABBCCDDEEFF", "AA:BB:CC:DD:EE:FF", false},
		{"aabbccddeeff", "AA:BB:CC:DD:EE:FF", false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := NormalizeMACAddress(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NormalizeMACAddress(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("NormalizeMACAddress(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestNewMagicPacket(t *testing.T) {
	packet, err := NewMagicPacket("AA:BB:CC:DD:EE:FF")
	if err != nil {
		t.Fatalf("NewMagicPacket failed: %v", err)
	}

	// Check packet size
	if len(packet) != MagicPacketSize {
		t.Errorf("packet size = %d, want %d", len(packet), MagicPacketSize)
	}

	// Check first 6 bytes are 0xFF
	for i := 0; i < 6; i++ {
		if packet[i] != 0xFF {
			t.Errorf("packet[%d] = 0x%02X, want 0xFF", i, packet[i])
		}
	}

	// Check MAC address is repeated 16 times
	macBytes := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	for i := 0; i < 16; i++ {
		offset := 6 + i*6
		for j := 0; j < 6; j++ {
			if packet[offset+j] != macBytes[j] {
				t.Errorf("packet[%d] = 0x%02X, want 0x%02X", offset+j, packet[offset+j], macBytes[j])
			}
		}
	}
}

func TestNewMagicPacketInvalid(t *testing.T) {
	_, err := NewMagicPacket("invalid")
	if err == nil {
		t.Error("NewMagicPacket should fail for invalid MAC")
	}
}

func TestNewService(t *testing.T) {
	service := NewService()
	if service == nil {
		t.Fatal("NewService returned nil")
	}
}

func TestWakeResult(t *testing.T) {
	result := WakeResult{
		MACAddress:   "AA:BB:CC:DD:EE:FF",
		Success:      true,
		BroadcastIPs: []string{"192.168.1.255", "255.255.255.255"},
		PacketsSent:  4,
	}

	if !result.Success {
		t.Error("Success should be true")
	}
	if len(result.BroadcastIPs) != 2 {
		t.Errorf("BroadcastIPs length = %d, want 2", len(result.BroadcastIPs))
	}
	if result.PacketsSent != 4 {
		t.Errorf("PacketsSent = %d, want 4", result.PacketsSent)
	}
}

func TestNetworkInterface(t *testing.T) {
	ni := NetworkInterface{
		Name:          "eth0",
		MACAddress:    "AA:BB:CC:DD:EE:FF",
		IPv4Addresses: []string{"192.168.1.100"},
		IPv4Subnets:   []string{"192.168.1.0/24"},
		IPv6Addresses: []string{"fe80::1"},
		Flags:         "up|broadcast|multicast",
		MTU:           1500,
		IsUp:          true,
		IsLoopback:    false,
	}

	if ni.Name != "eth0" {
		t.Error("Name not set correctly")
	}
	if !ni.IsUp {
		t.Error("IsUp should be true")
	}
	if ni.IsLoopback {
		t.Error("IsLoopback should be false")
	}
}

func TestGetNetworkInterfaces(t *testing.T) {
	service := NewService()
	interfaces, err := service.GetNetworkInterfaces()
	if err != nil {
		t.Fatalf("GetNetworkInterfaces failed: %v", err)
	}

	// Should return at least one interface on any system
	// (but might not have MAC on all)
	if interfaces == nil {
		t.Fatal("interfaces should not be nil")
	}
}

func TestCalculateBroadcast(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		mask     net.IPMask
		expected net.IP
	}{
		{
			"class C",
			net.IPv4(192, 168, 1, 100),
			net.CIDRMask(24, 32),
			net.IPv4(192, 168, 1, 255),
		},
		{
			"class B",
			net.IPv4(172, 16, 50, 100),
			net.CIDRMask(16, 32),
			net.IPv4(172, 16, 255, 255),
		},
		{
			"class A",
			net.IPv4(10, 0, 0, 1),
			net.CIDRMask(8, 32),
			net.IPv4(10, 255, 255, 255),
		},
		{
			"/30 subnet",
			net.IPv4(192, 168, 1, 1),
			net.CIDRMask(30, 32),
			net.IPv4(192, 168, 1, 3),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			broadcast := calculateBroadcast(tt.ip.To4(), tt.mask)
			if broadcast == nil {
				t.Fatal("broadcast should not be nil")
			}

			expected := tt.expected.To4()
			for i := 0; i < 4; i++ {
				if broadcast[i] != expected[i] {
					t.Errorf("broadcast = %v, want %v", broadcast, expected)
					break
				}
			}
		})
	}
}

func TestCalculateBroadcastInvalid(t *testing.T) {
	// Invalid IP length
	result := calculateBroadcast([]byte{1, 2, 3}, net.CIDRMask(24, 32))
	if result != nil {
		t.Error("should return nil for invalid IP length")
	}

	// Invalid mask length
	result = calculateBroadcast(net.IPv4(192, 168, 1, 1).To4(), []byte{255, 255, 255})
	if result != nil {
		t.Error("should return nil for invalid mask length")
	}
}

func TestConstants(t *testing.T) {
	if MagicPacketSize != 102 {
		t.Errorf("MagicPacketSize = %d, want 102", MagicPacketSize)
	}
	if DefaultPort != 9 {
		t.Errorf("DefaultPort = %d, want 9", DefaultPort)
	}
	if AlternativePort != 7 {
		t.Errorf("AlternativePort = %d, want 7", AlternativePort)
	}
}

func TestServiceWakeInvalidMAC(t *testing.T) {
	service := NewService()

	result, err := service.Wake("invalid")
	if err == nil {
		t.Error("Wake should fail for invalid MAC")
	}
	if result == nil {
		t.Fatal("result should not be nil even on error")
	}
	if result.Error == "" {
		t.Error("result.Error should be set")
	}
}

func TestServiceWakeWithOptions(t *testing.T) {
	service := NewService()

	// Use a non-routable IP to avoid actually sending packets
	// that could trigger network issues
	result, err := service.WakeWithOptions("AA:BB:CC:DD:EE:FF", DefaultPort, "127.0.0.1")
	if err != nil {
		t.Logf("WakeWithOptions returned error (may be expected on some systems): %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if result.MACAddress != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("MACAddress = %s, want AA:BB:CC:DD:EE:FF", result.MACAddress)
	}
}

func TestMacRegex(t *testing.T) {
	validMACs := []string{
		"AA:BB:CC:DD:EE:FF",
		"aa:bb:cc:dd:ee:ff",
		"AA-BB-CC-DD-EE-FF",
		"AABBCCDDEEFF",
		"00:11:22:33:44:55",
	}

	for _, mac := range validMACs {
		if !macRegex.MatchString(mac) {
			t.Errorf("macRegex should match %q", mac)
		}
	}

	invalidMACs := []string{
		"",
		"AA:BB:CC:DD:EE",
		"AA:BB:CC:DD:EE:FF:00",
		"GG:BB:CC:DD:EE:FF",
	}

	for _, mac := range invalidMACs {
		if macRegex.MatchString(mac) {
			t.Errorf("macRegex should not match %q", mac)
		}
	}
}
