package remotedesktop

import "encoding/binary"

const (
	// ActionDesktopFrame is the action type byte for remote desktop frames.
	ActionDesktopFrame byte = 0x01

	// BinaryHeaderSize is the size of the binary frame header in bytes.
	BinaryHeaderSize = 5
)

// BuildBinaryFrame creates a binary WebSocket frame with a 5-byte header + raw JPEG data.
//
// Format:
//
//	Byte 0:     Action type (uint8) — 0x01 for desktop frame
//	Bytes 1-2:  Width (uint16 big-endian)
//	Bytes 3-4:  Height (uint16 big-endian)
//	Bytes 5+:   Raw JPEG data
func BuildBinaryFrame(width, height int, jpegData []byte) []byte {
	frame := make([]byte, BinaryHeaderSize+len(jpegData))
	frame[0] = ActionDesktopFrame
	binary.BigEndian.PutUint16(frame[1:3], uint16(width))
	binary.BigEndian.PutUint16(frame[3:5], uint16(height))
	copy(frame[BinaryHeaderSize:], jpegData)
	return frame
}
