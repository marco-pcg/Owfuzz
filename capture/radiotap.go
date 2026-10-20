// SPDX-License-Identifier: GPL-3.0-or-later
package capture

import (
	"encoding/binary"
	"errors"

	"owfuzz/protocol"
)

// StripRadiotap skips the variable bitmap header and handles the Flags field/FCS.
// Unknown fields after Flags need not be decoded to locate the 802.11 payload.
func StripRadiotap(b []byte) (protocol.Packet, error) {
	if len(b) < 8 || b[0] != 0 {
		return protocol.Packet{}, errors.New("short/unsupported radiotap")
	}
	n := int(binary.LittleEndian.Uint16(b[2:]))
	if n < 8 || n > len(b) {
		return protocol.Packet{}, errors.New("invalid radiotap length")
	}
	first := binary.LittleEndian.Uint32(b[4:])
	offset := 4
	for {
		if offset+4 > n {
			return protocol.Packet{}, errors.New("truncated radiotap bitmap")
		}
		bits := binary.LittleEndian.Uint32(b[offset:])
		offset += 4
		if bits&0x80000000 == 0 {
			break
		}
	}
	if first&1 != 0 {
		offset = (offset + 7) &^ 7
		offset += 8
	}
	var flags byte
	if first&2 != 0 {
		if offset >= n {
			return protocol.Packet{}, errors.New("truncated radiotap flags")
		}
		flags = b[offset]
	}
	payload := b[n:]
	if flags&0x40 != 0 {
		return protocol.Packet{}, errors.New("capture marked bad FCS")
	}
	if flags&0x10 != 0 {
		if len(payload) < 4 {
			return protocol.Packet{}, errors.New("missing FCS")
		}
		payload = payload[:len(payload)-4]
	}
	p := protocol.Packet{Data: append([]byte(nil), payload...), LinkType: protocol.WiFi}
	return p, p.Validate()
}
