// SPDX-License-Identifier: GPL-3.0-or-later
// Vendor protocol layouts derive from the legacy Owfuzz/OWL sources; Go code is native.
package modules

import (
	"encoding/binary"
	"owfuzz/protocol"
	"owfuzz/wifi"
)

var P2PActionNames = []string{"go_negotiation_request", "go_negotiation_response", "go_negotiation_confirmation", "invitation_request", "invitation_response", "device_discoverability_request", "device_discoverability_response", "provision_discovery_request", "provision_discovery_response"}

func init() { provide(p2pFamily); provide(awdlFamily); provide(meshFamily) }
func p2pAttributes(c *protocol.Context) []byte {
	var b []byte
	b, _ = wifi.AppendField(b, 2, []byte{0x25, 0}, 1, 2, binary.LittleEndian)
	b, _ = wifi.AppendField(b, 6, []byte{'X', 'X', 4, 81, byte(c.Channel)}, 1, 2, binary.LittleEndian)
	b, _ = wifi.AppendField(b, 13, append(append([]byte(nil), c.Source[:]...), 0, 0), 1, 2, binary.LittleEndian)
	return b
}
func p2pIE(b []byte, c *protocol.Context) ([]byte, error) {
	out, e := wifi.AppendElement(b, 221, append([]byte{0x50, 0x6f, 0x9a, 9}, p2pAttributes(c)...))
	if e != nil {
		return nil, e
	}
	wps := []byte{0, 0x50, 0xf2, 4}
	wps, _ = wifi.AppendField(wps, 0x104a, []byte{0x20}, 2, 2, binary.BigEndian)
	wps, _ = wifi.AppendField(wps, 0x1008, []byte{0, 0x8c}, 2, 2, binary.BigEndian)
	wps, e = wifi.AppendField(wps, 0x1011, []byte(c.SSID), 2, 2, binary.BigEndian)
	if e != nil {
		return nil, e
	}
	return wifi.AppendElement(out, 221, wps)
}
func p2pManagement(t byte, c *protocol.Context) (protocol.Packet, error) {
	p, e := Management(t, c)
	if e != nil {
		return p, e
	}
	p.Data, e = p2pIE(p.Data, c)
	return p, e
}
func p2pAction(subtype byte, c *protocol.Context) (protocol.Packet, error) {
	b := wifi.HeaderBytes(0xd0, c)
	token := byte(c.Iteration + 1)
	if len(c.Received) >= 32 && c.Received[0] == 0xd0 {
		token = c.Received[31]
	}
	b = append(b, 4, 9, 0x50, 0x6f, 0x9a, 9, subtype, token)
	b, e := p2pIE(b, c)
	return protocol.Packet{Data: b, LinkType: protocol.WiFi, Channel: c.Channel}, e
}
func p2pFamily() protocol.Family {
	f := protocol.Family{Name: "p2p", LinkType: protocol.WiFi}
	for i, entry := range []struct {
		t byte
		n string
	}{{0x80, "beacon"}, {0x40, "probe_request"}, {0x50, "probe_response"}, {0, "association_request"}, {0x10, "association_response"}} {
		t := entry.t
		f.Frames = append(f.Frames, protocol.Frame{ID: uint32(i + 1), Name: entry.n, Build: func(c *protocol.Context) (protocol.Packet, error) { return p2pManagement(t, c) }})
	}
	for i, name := range P2PActionNames {
		kind := byte(i)
		f.Frames = append(f.Frames, protocol.Frame{ID: uint32(100 + i), Name: name, Build: func(c *protocol.Context) (protocol.Packet, error) { return p2pAction(kind, c) }})
	}
	f.Frames = append(f.Frames, protocol.Frame{ID: 200, Name: "public_action", Build: func(c *protocol.Context) (protocol.Packet, error) { return p2pAction(0, c) }})
	return f
}
func awdlAction(kind byte, c *protocol.Context) (protocol.Packet, error) {
	b := wifi.HeaderBytes(0xd0, c)
	body := make([]byte, 16)
	copy(body, []byte{127, 0, 0x17, 0xf2, 8, 0x10, kind, 0})
	binary.LittleEndian.PutUint32(body[8:], uint32(c.Iteration*102400))
	binary.LittleEndian.PutUint32(body[12:], uint32(c.Iteration*102400))
	b = append(b, body...)
	if len(c.Payload) > 0 {
		b = append(b, c.Payload...)
	} else {
		var e error
		b, e = wifi.AppendField(b, 21, []byte{0x34, 1}, 1, 2, binary.LittleEndian)
		if e != nil {
			return protocol.Packet{}, e
		}
	}
	return protocol.Packet{Data: b, LinkType: protocol.WiFi, Channel: c.Channel}, nil
}
func awdlFamily() protocol.Family {
	return protocol.Family{Name: "awdl", LinkType: protocol.WiFi, Frames: []protocol.Frame{{ID: 1, Name: "action", Build: func(c *protocol.Context) (protocol.Packet, error) { return awdlAction(0, c) }}, {ID: 2, Name: "mif", Build: func(c *protocol.Context) (protocol.Packet, error) { return awdlAction(3, c) }}}}
}
func meshFamily() protocol.Family {
	return protocol.Family{Name: "mesh", LinkType: protocol.WiFi, Frames: []protocol.Frame{{ID: 1, Name: "beacon", Build: func(c *protocol.Context) (protocol.Packet, error) {
		p, e := Management(0x80, c)
		if e != nil {
			return p, e
		}
		p.Data, e = wifi.AppendElement(p.Data, 114, []byte(c.SSID))
		if e != nil {
			return p, e
		}
		p.Data, e = wifi.AppendElement(p.Data, 113, []byte{1, 1, 0, 1, 0, 0, 0})
		return p, e
	}}, {ID: 2, Name: "peering_action", Build: func(c *protocol.Context) (protocol.Packet, error) {
		b := wifi.HeaderBytes(0xd0, c)
		action := byte(1)
		if len(c.Received) >= 26 && c.Received[24] == 15 && c.Received[25] == 1 {
			action = 2
		}
		b = append(b, 15, action, 0, 0)
		return protocol.Packet{Data: b, LinkType: protocol.WiFi, Channel: c.Channel}, nil
	}}, {ID: 3, Name: "probe_request", Build: func(c *protocol.Context) (protocol.Packet, error) { return Management(0x40, c) }}}}
}
