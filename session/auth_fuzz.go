// SPDX-License-Identifier: GPL-3.0-or-later
package session

import (
	"encoding/binary"
	"errors"
	"owfuzz/protocol"
	"owfuzz/wifi"
	"strings"
)

// NewFuzz creates a malformed-message exchange controller, like the legacy fuzzer.
// It never promotes unverified cryptographic traffic to the Connected state.
func NewFuzz(c protocol.Context) (*Controller, error) {
	if c.Role != "ap" && c.Role != "sta" {
		return nil, errors.New("role must be ap/sta")
	}
	switch c.Auth {
	case "OPEN_NONE", "OPEN_WEP", "SHARE_WEP", "WPA_PSK_TKIP", "WPA_PSK_AES", "WPA_PSK_TKIP_AES", "WPA2_PSK_TKIP", "WPA2_PSK_AES", "WPA2_PSK_TKIP_AES", "EAP_8021X", "WPA3":
	default:
		return nil, errors.New("unknown authentication corpus")
	}
	return &Controller{Context: c, State: Disconnected, Fuzz: true}, nil
}
func fuzzEAPOL(c *protocol.Context, received []byte) ([]byte, error) {
	if c.Auth == "EAP_8021X" {
		if len(received) == 0 {
			if c.Role == "sta" {
				return []byte{2, 1, 0, 0}, nil
			}
			return []byte{2, 0, 0, 5, 1, byte(c.Iteration), 0, 5, 1}, nil
		}
		if len(received) < 4 {
			return nil, errors.New("short EAPOL")
		}
		if received[1] == 1 {
			return []byte{2, 0, 0, 5, 1, byte(c.Iteration), 0, 5, 1}, nil
		}
		if received[1] != 0 {
			return nil, nil
		}
		if len(received) < 8 {
			return nil, errors.New("short EAP packet")
		}
		if received[4] == 3 || received[4] == 4 {
			return nil, nil
		}
		if len(received) < 9 {
			return nil, errors.New("short EAP method")
		}
		data := []byte("owfuzz")
		if received[8] != 1 {
			data = nonce(c)
		}
		n := 5 + len(data)
		b := []byte{2, 0, byte(n >> 8), byte(n), 2, received[5], byte(n >> 8), byte(n), received[8]}
		return append(b, data...), nil
	}
	version := uint16(2)
	descriptor := byte(2)
	if strings.HasPrefix(c.Auth, "WPA_") {
		descriptor = 254
	}
	if strings.Contains(c.Auth, "TKIP") {
		version = 1
	}
	info := version | 8
	replay := uint64(1)
	if len(received) > 0 {
		if len(received) < 99 || received[1] != 3 {
			return nil, errors.New("short/non-key EAPOL fuzz input")
		}
		replay = binary.BigEndian.Uint64(received[9:])
		incoming := binary.BigEndian.Uint16(received[5:])
		if c.Role == "ap" {
			if incoming&0x200 != 0 {
				return nil, nil
			}
			info |= 0x1c0
			replay++
		} else {
			info |= 0x100
			if incoming&0x100 != 0 {
				info |= 0x200
			}
		}
	} else if c.Role == "ap" {
		info |= 0x80
	} else {
		info |= 0x100
	}
	b := keyPacket(info, replay, nonce(c), nil, nil)
	b[4] = descriptor
	if info&0x100 != 0 {
		for i := 81; i < 97; i++ {
			b[i] = byte(c.Random() >> 24)
		}
	}
	return b, nil
}
func (c *Controller) fuzzData(ctx *protocol.Context, p protocol.Packet) ([]protocol.Packet, error) {
	msg, e := wifi.EAPOL(p.Data)
	if e != nil {
		return nil, nil
	}
	if ctx.Role == "ap" && c.peer != (protocol.MAC{}) {
		ctx.Destination = c.peer
	}
	response, e := fuzzEAPOL(ctx, msg)
	if e != nil {
		return nil, e
	}
	c.Context.RandomState = ctx.RandomState
	c.State = Fuzzing
	if response == nil {
		return nil, nil
	}
	return []protocol.Packet{wifi.Data(ctx, response)}, nil
}
