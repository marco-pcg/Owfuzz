// SPDX-License-Identifier: GPL-3.0-or-later
// Package wifi implements bounded 802.11 serialization and parsing in Go.
package wifi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"owfuzz/protocol"
)

var LE = binary.LittleEndian
var LLC = []byte{0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e}

type Header struct {
	Type, Flags                               byte
	Duration, Sequence                        uint16
	Receiver, Transmitter, Address3, Address4 protocol.MAC
	Size                                      int
}

func Parse(b []byte) (Header, error) {
	var h Header
	if len(b) > protocol.MaxPacket {
		return h, errors.New("frame exceeds capacity")
	}
	if len(b) < 2 {
		return h, errors.New("short frame control")
	}
	h.Type = b[0]
	h.Flags = b[1]
	if h.Type&3 != 0 {
		return h, errors.New("unsupported WiFi version")
	}
	if h.Type&0x0c == 0 && h.Flags&3 != 0 {
		return h, errors.New("management frame has invalid DS flags")
	}
	n := 24
	if h.Type&0x0c == 4 {
		n = 16
		if h.Type == 0xd4 || h.Type == 0xc4 {
			n = 10
		}
	} else if h.Type&0x0c == 8 {
		if h.Flags&3 == 3 {
			n += 6
		}
		if h.Type&0x80 != 0 {
			n += 2
		}
		if h.Flags&0x80 != 0 && h.Type&0x80 != 0 {
			n += 4
		}
	} else if h.Type&0x0c != 0 {
		return h, errors.New("unsupported extension header")
	}
	if len(b) < n {
		return h, fmt.Errorf("short WiFi header: need %d", n)
	}
	h.Size = n
	h.Duration = LE.Uint16(b[2:])
	copy(h.Receiver[:], b[4:10])
	if n >= 16 && h.Type != 0x74 {
		copy(h.Transmitter[:], b[10:16])
	}
	if h.Type&0x0c != 4 {
		copy(h.Address3[:], b[16:22])
		h.Sequence = LE.Uint16(b[22:24])
		if h.Flags&3 == 3 {
			copy(h.Address4[:], b[24:30])
		}
	}
	return h, nil
}
func (h Header) Source() protocol.MAC {
	if h.Type&0x0c == 4 {
		return h.Transmitter
	}
	switch h.Flags & 3 {
	case 2:
		return h.Address3
	case 3:
		return h.Address4
	default:
		return h.Transmitter
	}
}
func (h Header) Destination() protocol.MAC {
	if h.Type&0x0c == 4 {
		return h.Receiver
	}
	if h.Flags&1 != 0 {
		return h.Address3
	}
	return h.Receiver
}
func (h Header) BSSID() protocol.MAC {
	switch h.Flags & 3 {
	case 1:
		return h.Receiver
	case 2:
		return h.Transmitter
	case 3:
		return protocol.MAC{}
	default:
		return h.Address3
	}
}
func HeaderBytes(t byte, c *protocol.Context) []byte {
	b := make([]byte, 24)
	b[0] = t
	copy(b[4:], c.Destination[:])
	copy(b[10:], c.Source[:])
	copy(b[16:], c.BSSID[:])
	LE.PutUint16(b[22:], uint16(c.Iteration&4095)<<4)
	return b
}

type Element struct {
	ID    byte
	Value []byte
}

func Elements(b []byte) ([]Element, error) {
	if len(b) > protocol.MaxPacket {
		return nil, errors.New("IE area exceeds capacity")
	}
	var out []Element
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, errors.New("truncated IE header")
		}
		n := int(b[1])
		if len(b) < n+2 {
			return nil, errors.New("truncated IE value")
		}
		out = append(out, Element{b[0], append([]byte(nil), b[2:2+n]...)})
		b = b[n+2:]
	}
	return out, nil
}
func AppendElement(b []byte, id byte, value []byte) ([]byte, error) {
	if len(value) > 255 || len(b)+2+len(value) > protocol.MaxPacket {
		return nil, errors.New("IE exceeds capacity")
	}
	return append(append(b, id, byte(len(value))), value...), nil
}
func ElementOffset(t byte) int {
	switch t {
	case 0x80, 0x50:
		return 36
	case 0x40:
		return 24
	case 0:
		return 28
	case 0x20:
		return 34
	case 0x10, 0x30, 0xb0:
		return 30
	case 0x60:
		return 34
	default:
		return -1
	}
}

// RSN returns a CCMP/PSK advertisement; SAE advertisement is corpus-only.
func RSN(auth string) []byte {
	akm := byte(2)
	if auth == "WPA3" {
		akm = 8
	}
	return []byte{1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, akm, 0, 0}
}
func Secure(auth string) bool { return auth != "" && auth != "OPEN_NONE" }
func EAPOL(b []byte) ([]byte, error) {
	h, e := Parse(b)
	if e != nil {
		return nil, e
	}
	if h.Type&0x0c != 8 || h.Flags&0x40 != 0 {
		return nil, errors.New("not unencrypted data")
	}
	body := b[h.Size:]
	if len(body) < 8 || string(body[:8]) != string(LLC) {
		return nil, errors.New("not EAPOL")
	}
	body = body[8:]
	if len(body) < 4 {
		return nil, errors.New("short EAPOL")
	}
	n := int(binary.BigEndian.Uint16(body[2:])) + 4
	if n > len(body) {
		return nil, errors.New("truncated EAPOL")
	}
	return append([]byte(nil), body[:n]...), nil
}
func Data(c *protocol.Context, eapol []byte) protocol.Packet {
	b := HeaderBytes(0x88, c)
	if c.Role == "ap" {
		b[1] = 2
		copy(b[10:], c.BSSID[:])
		copy(b[16:], c.Source[:])
	} else {
		b[1] = 1
		copy(b[4:], c.BSSID[:])
		copy(b[16:], c.Destination[:])
	}
	b = append(b, 0, 0)
	b = append(b, LLC...)
	b = append(b, eapol...)
	return protocol.Packet{Data: b, LinkType: protocol.WiFi, Channel: c.Channel}
}

// SecurityIE builds the requested advertisement. This does not implement the
// corresponding authentication state machine (only OPEN/WPA2-CCMP have one).
func SecurityIE(auth string) (byte, []byte, bool) {
	if auth == "" || auth == "OPEN_NONE" || auth == "OPEN_WEP" || auth == "SHARE_WEP" {
		return 0, nil, false
	}
	oui := []byte{0, 15, 172}
	vendor := len(auth) >= 4 && auth[:4] == "WPA_"
	if vendor {
		oui = []byte{0, 0x50, 0xf2}
	}
	group := byte(4)
	if auth == "WPA_PSK_TKIP" || auth == "WPA2_PSK_TKIP" || auth == "WPA_PSK_TKIP_AES" || auth == "WPA2_PSK_TKIP_AES" {
		group = 2
	}
	b := []byte{1, 0}
	b = append(b, oui...)
	b = append(b, group)
	mix := auth == "WPA_PSK_TKIP_AES" || auth == "WPA2_PSK_TKIP_AES"
	count := byte(1)
	if mix {
		count = 2
	}
	b = append(b, count, 0)
	b = append(b, oui...)
	b = append(b, group)
	if mix {
		b = append(b, oui...)
		b = append(b, 4)
	}
	b = append(b, 1, 0)
	b = append(b, oui...)
	akm := byte(2)
	if auth == "WPA3" {
		akm = 8
	}
	if auth == "EAP_8021X" {
		akm = 1
	}
	b = append(b, akm)
	caps := byte(0)
	if auth == "WPA3" {
		caps = 0xc0
	}
	b = append(b, caps, 0)
	if vendor {
		return 221, append([]byte{0, 0x50, 0xf2, 1}, b...), true
	}
	return 48, b, true
}
