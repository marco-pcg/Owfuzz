// SPDX-License-Identifier: GPL-3.0-or-later
// Wire names/IDs derive from Owfuzz (C) 2020-2021 Hongjian Cao; implementations are native Go.
package modules

import (
	"fmt"

	"owfuzz/protocol"
	"owfuzz/wifi"
)

func init() { provide(wifiFamily) }

var management = []struct {
	id   byte
	name string
}{{0, "association_request"}, {0x10, "association_response"}, {0x20, "reassociation_request"}, {0x30, "reassociation_response"}, {0x40, "probe_request"}, {0x50, "probe_response"}, {0x60, "timing_advertisement"}, {0x80, "beacon"}, {0x90, "atim"}, {0xa0, "disassociation"}, {0xb0, "authentication"}, {0xc0, "deauthentication"}, {0xd0, "action"}, {0xe0, "action_no_ack"}}
var controls = []struct {
	id   byte
	name string
}{{0x44, "beamforming_report_poll"}, {0x54, "vht_ndp_announcement"}, {0x64, "control_frame_extension"}, {0x74, "control_wrapper"}, {0x84, "block_ack_request"}, {0x94, "block_ack"}, {0xa4, "ps_poll"}, {0xb4, "rts"}, {0xc4, "cts"}, {0xd4, "ack"}, {0xe4, "cf_end"}, {0xf4, "cf_end_cf_ack"}}
var dataNames = []string{"data", "data_cf_ack", "data_cf_poll", "data_cf_ack_cf_poll", "null", "cf_ack", "cf_poll", "cf_ack_cf_poll", "qos_data", "qos_data_cf_ack", "qos_data_cf_poll", "qos_data_cf_ack_cf_poll", "qos_null", "qos_cf_ack", "qos_cf_poll", "qos_cf_ack_cf_poll"}

func wifiFamily() protocol.Family {
	f := protocol.Family{Name: "802.11", LinkType: protocol.WiFi}
	for _, entry := range management {
		t := entry.id
		f.Frames = append(f.Frames, protocol.Frame{ID: uint32(t), Name: entry.name, Build: func(c *protocol.Context) (protocol.Packet, error) { return Management(t, c) }})
	}
	for _, entry := range controls {
		t := entry.id
		x := protocol.Frame{ID: uint32(t), Name: entry.name, Build: func(c *protocol.Context) (protocol.Packet, error) { return Control(t, c) }}
		if t == 0x64 {
			x.Unsupported = "control_frame_extension was an empty legacy stub"
		}
		f.Frames = append(f.Frames, x)
	}
	for i, name := range dataNames {
		t := byte(i<<4) | 8
		f.Frames = append(f.Frames, protocol.Frame{ID: uint32(t), Name: name, Build: func(c *protocol.Context) (protocol.Packet, error) { return dataFrame(t, c) }})
	}
	return f
}

// IEOptions configures structured information-element fuzzing without mutable globals.
type IEOptions struct {
	Extra              []wifi.Element
	Mode               string
	Disabled           map[byte]bool
	DisabledExtensions map[byte]bool
}

func baseIEs(b []byte, c *protocol.Context) ([]byte, error) {
	if len(c.SSID) > 32 {
		return nil, fmt.Errorf("SSID exceeds 32 bytes")
	}
	if c.Channel < 1 || c.Channel > 255 {
		return nil, fmt.Errorf("invalid channel")
	}
	es := []wifi.Element{{ID: 0, Value: []byte(c.SSID)}, {ID: 1, Value: []byte{0x82, 0x84, 0x8b, 0x96, 12, 18, 24, 36}}, {ID: 3, Value: []byte{byte(c.Channel)}}}
	if id, value, ok := wifi.SecurityIE(c.Auth); ok {
		es = append(es, wifi.Element{ID: id, Value: value})
	}
	if opt, ok := c.User.(IEOptions); ok {
		switch opt.Mode {
		case "replace":
			es = append([]wifi.Element(nil), opt.Extra...)
		case "omit":
			es = nil
		default:
			es = append(es, opt.Extra...)
		}
		if opt.Mode == "duplicate" {
			es = append(es, es...)
		}
	}
	var e error
	lastLength := -1
	for _, ie := range es {
		if opt, ok := c.User.(IEOptions); ok {
			if opt.Disabled[ie.ID] || (ie.ID == 255 && len(ie.Value) > 0 && opt.DisabledExtensions[ie.Value[0]]) {
				continue
			}
		}
		lastLength = len(b) + 1
		b, e = wifi.AppendElement(b, ie.ID, ie.Value)
		if e != nil {
			return nil, e
		}
	}
	if opt, ok := c.User.(IEOptions); ok && opt.Mode == "invalid-length" && lastLength >= 0 {
		b[lastLength] = 255
	}
	return b, nil
}
func Management(t byte, c *protocol.Context) (protocol.Packet, error) {
	b := wifi.HeaderBytes(t, c)
	capability := uint16(1)
	if wifi.Secure(c.Auth) {
		capability |= 16
	}
	switch t {
	case 0, 0x20:
		b = append(b, byte(capability), byte(capability>>8), 10, 0)
		if t == 0x20 {
			b = append(b, c.BSSID[:]...)
		}
	case 0x10, 0x30:
		b = append(b, byte(capability), byte(capability>>8), 0, 0, 1, 0xc0)
	case 0x40:
	case 0x50, 0x80:
		b = append(b, make([]byte, 12)...)
		wifi.LE.PutUint64(b[24:], c.Iteration*102400)
		b[32] = 100
		wifi.LE.PutUint16(b[34:], capability)
	case 0x60:
		b = append(b, make([]byte, 10)...)
		wifi.LE.PutUint64(b[24:], c.Iteration*102400)
		wifi.LE.PutUint16(b[32:], capability)
	case 0x90:
	case 0xa0, 0xc0:
		b = append(b, 3, 0)
	case 0xb0:
		algorithm, seq := uint16(0), uint16(1)
		if c.Role == "ap" {
			seq = 2
		}
		var received []byte
		if h, e := wifi.Parse(c.Received); e == nil && h.Type == 0xb0 && len(c.Received) >= h.Size+6 {
			received = c.Received[h.Size:]
			seq = wifi.LE.Uint16(received[2:]) + 1
		}
		switch c.Auth {
		case "SHARE_WEP":
			algorithm = 1
		case "WPA3":
			algorithm = 3
			seq = 1
			if len(received) > 0 {
				seq = wifi.LE.Uint16(received[2:])
			}
		}
		b = append(b, byte(algorithm), byte(algorithm>>8), byte(seq), byte(seq>>8), 0, 0)
		if algorithm == 3 {
			if seq == 1 {
				group := uint16(19)
				if len(received) >= 8 {
					group = wifi.LE.Uint16(received[6:])
				}
				b = append(b, byte(group), byte(group>>8))
				for i := 0; i < 96; i++ {
					b = append(b, byte(c.Random()>>24))
				}
			} else if seq == 2 {
				b = append(b, 1, 0)
				for i := 0; i < 32; i++ {
					b = append(b, byte(c.Random()>>24))
				}
			}
		} else if algorithm == 1 {
			if seq == 2 {
				challenge := make([]byte, 128)
				for i := range challenge {
					challenge[i] = byte(c.Random() >> 24)
				}
				b = append(b, 16, 128)
				b = append(b, challenge...)
			} else if seq == 3 && len(received) > 6 {
				b = append(b, received[6:]...)
			}
		}

	case 0xd0, 0xe0:
		b = append(b, 4, 0, byte(c.Iteration))
		b = append(b, c.Payload...)
	default:
		return protocol.Packet{}, fmt.Errorf("unknown management type %x", t)
	}
	if wifi.ElementOffset(t) >= 0 && t != 0xb0 {
		var e error
		b, e = baseIEs(b, c)
		if e != nil {
			return protocol.Packet{}, e
		}
	}
	return protocol.Packet{Data: b, LinkType: protocol.WiFi, Channel: c.Channel}, nil
}
func Control(t byte, c *protocol.Context) (protocol.Packet, error) {
	if t == 0x64 {
		return protocol.Packet{}, fmt.Errorf("%w: control_frame_extension", protocol.ErrUnsupported)
	}
	n := 16
	if t == 0xc4 || t == 0xd4 {
		n = 10
	}
	b := make([]byte, n)
	b[0] = t
	copy(b[4:], c.Destination[:])
	if n >= 16 {
		copy(b[10:], c.Source[:])
	}
	switch t {
	case 0xa4:
		wifi.LE.PutUint16(b[2:], 0xc001)
		copy(b[4:], c.BSSID[:])
	case 0x84:
		b = append(b, 4, 0, 0, 0)
	case 0x94:
		b = append(b, 4, 0, 0, 0)
		b = append(b, make([]byte, 8)...)
	case 0x44:
		b = append(b, 1)
	case 0x54:
		b = append(b, 0, 0, 0)
	case 0x74:
		b[10] = 0xd4
		b[11] = 0
		clear(b[12:16])
	case 0xe4, 0xf4:
		copy(b[10:], c.BSSID[:])
	}
	return protocol.Packet{Data: b, LinkType: protocol.WiFi, Channel: c.Channel}, nil
}
func dataFrame(t byte, c *protocol.Context) (protocol.Packet, error) {
	b := wifi.HeaderBytes(t, c)
	if c.Role == "ap" {
		b[1] = 2
		copy(b[10:], c.BSSID[:])
		copy(b[16:], c.Source[:])
	} else {
		b[1] = 1
		copy(b[4:], c.BSSID[:])
		copy(b[16:], c.Destination[:])
	}
	if t&0x80 != 0 {
		b = append(b, 0, 0)
	}
	if t&0x40 == 0 {
		if len(c.Payload) > 0 {
			b = append(b, c.Payload...)
		} else {
			b = append(b, 0xaa, 0xaa, 3, 0, 0, 0, 8, 0)
			b = append(b, make([]byte, 20)...)
			b[len(b)-20] = 0x45
		}
	}
	return protocol.Packet{Data: b, LinkType: protocol.WiFi, Channel: c.Channel}, nil
}
