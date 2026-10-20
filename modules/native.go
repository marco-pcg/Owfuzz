// SPDX-License-Identifier: GPL-3.0-or-later
package modules

import "owfuzz/protocol"

func init() { provide(ethernetFamily); provide(beFamily) }
func ethernetFamily() protocol.Family {
	return protocol.Family{Name: "ethernet", LinkType: protocol.Ethernet, Frames: []protocol.Frame{{ID: 1, Name: "arp_request", Build: arp}}}
}
func arp(c *protocol.Context) (protocol.Packet, error) {
	b := make([]byte, 60)
	copy(b, c.Destination[:])
	copy(b[6:], c.Source[:])
	copy(b[12:], []byte{8, 6, 0, 1, 8, 0, 6, 4, 0, 1})
	copy(b[22:], c.Source[:])
	copy(b[28:], []byte{192, 0, 2, 1})
	copy(b[38:], []byte{192, 0, 2, 2})
	return protocol.Packet{Data: b, LinkType: protocol.Ethernet}, nil
}
func beFamily() protocol.Family {
	return protocol.Family{Name: "802.11be", LinkType: protocol.WiFi, Frames: []protocol.Frame{{ID: 1, Name: "ml_probe_response", Build: multiLink}, {ID: 2, Name: "ml_invalid_common_length", Build: func(c *protocol.Context) (protocol.Packet, error) {
		p, e := multiLink(c)
		p.Data[43] = 255
		return p, e
	}}}}
}
func multiLink(c *protocol.Context) (protocol.Packet, error) {
	b := make([]byte, 50)
	b[0] = 0x50
	copy(b[4:], c.Destination[:])
	copy(b[10:], c.Source[:])
	copy(b[16:], c.BSSID[:])
	b[22] = byte((c.Iteration & 15) << 4)
	b[23] = byte(c.Iteration >> 4)
	b[32] = 100
	b[34] = 1
	copy(b[38:], []byte{255, 10, 107, 0, 0, 7})
	copy(b[44:], c.Source[:])
	return protocol.Packet{Data: b, LinkType: protocol.WiFi, Channel: c.Channel}, nil
}
