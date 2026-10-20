// SPDX-License-Identifier: GPL-3.0-or-later
package session

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"owfuzz/modules"
	"owfuzz/protocol"
	"owfuzz/wifi"
)

const Fuzzing State = "fuzzing-exchange"

// NewProfile preserves the legacy vendor-message responder role. It never reports
// a complete P2P group, mesh peering, or AWDL synchronization session.
func NewProfile(family string, c protocol.Context) (*Controller, error) {
	if c.Role != "ap" && c.Role != "sta" {
		return nil, errors.New("profile role must be ap/sta")
	}
	if family != "p2p" && family != "awdl" && family != "mesh" {
		return nil, errors.New("unknown responder profile")
	}
	r, e := modules.NewRegistry()
	if e != nil {
		return nil, e
	}
	f, e := r.Family(family)
	if e != nil {
		return nil, e
	}
	return &Controller{Context: c, State: Scanning, profile: &f}, nil
}
func (c *Controller) profileBuild(name string, ctx *protocol.Context) (protocol.Packet, error) {
	ctx.Iteration = c.Context.Iteration
	none, _ := protocol.Strategy("none")
	p, e := protocol.Generate(*c.profile, name, ctx, none)
	c.Context.Iteration++
	c.Context.RandomState = ctx.RandomState
	return p, e
}
func (c *Controller) profileInitial() ([]protocol.Packet, error) {
	ctx := c.Context
	name := "beacon"
	switch c.profile.Name {
	case "p2p":
		if ctx.Role == "sta" {
			name = "probe_request"
		}
	case "awdl":
		name = "action"
	}
	p, e := c.profileBuild(name, &ctx)
	return []protocol.Packet{p}, e
}
func (c *Controller) profileHandle(p protocol.Packet, h wifi.Header) ([]protocol.Packet, error) {
	ctx := c.Context
	if h.Transmitter == ctx.Source {
		return nil, nil
	}
	if ctx.Destination != protocol.Broadcast && ctx.Destination != h.Transmitter {
		return nil, nil
	}
	ctx.Destination = h.Transmitter
	ctx.Received = append([]byte(nil), p.Data...)
	body := p.Data[h.Size:]
	name := ""
	switch c.profile.Name {
	case "awdl":
		if h.Type != 0xd0 {
			return nil, nil
		}
		if len(body) < 16 {
			return nil, errors.New("short AWDL action")
		}
		if !bytes.Equal(body[:5], []byte{127, 0, 0x17, 0xf2, 8}) {
			return nil, nil
		}
		if body[6] != 0 && body[6] != 3 {
			return nil, nil
		}
		if _, e := wifi.ReadFields(body[16:], 1, 2, binary.LittleEndian); e != nil {
			return nil, e
		}
		name = "action"
	case "p2p":
		if h.Type == 0xd0 {
			if len(body) < 8 {
				return nil, errors.New("short P2P action")
			}
			if !bytes.Equal(body[:6], []byte{4, 9, 0x50, 0x6f, 0x9a, 9}) {
				return nil, nil
			}
			if _, e := p2pElements(body[8:]); e != nil {
				return nil, e
			}
			responses := map[byte]byte{0: 1, 1: 2, 3: 4, 5: 6, 7: 8}
			response, ok := responses[body[6]]
			if !ok {
				return nil, nil
			}
			name = modules.P2PActionNames[response]
		} else {
			offset := wifi.ElementOffset(h.Type)
			if offset < 0 || offset > len(p.Data) {
				return nil, nil
			}
			matched, e := p2pElements(p.Data[offset:])
			if e != nil {
				return nil, e
			}
			if !matched {
				return nil, nil
			}
			switch h.Type {
			case 0x40:
				name = "probe_response"
			case 0x50:
				name = "go_negotiation_request"
			case 0x80:
				name = "probe_request"
			case 0:
				name = "association_response"
			}
		}
	case "mesh":
		if h.Type == 0x80 {
			if len(body) < 12 {
				return nil, errors.New("short mesh beacon")
			}
			ies, e := wifi.Elements(body[12:])
			if e != nil {
				return nil, e
			}
			for _, ie := range ies {
				if ie.ID == 113 || ie.ID == 114 {
					c.State = Scanning
					return nil, nil
				}
			}
		} else if h.Type&0x0c == 8 {
			if h.Destination() == (protocol.MAC{1, 0x80, 0xc2, 0, 0, 0x0e}) {
				name = "probe_request"
			}
		} else if h.Type == 0xd0 && len(body) >= 2 && body[0] == 15 {
			if body[1] == 1 {
				name = "peering_action"
			}
		}
	}
	if name == "" {
		return nil, nil
	}
	c.State = Fuzzing
	response, e := c.profileBuild(name, &ctx)
	if e != nil {
		return nil, fmt.Errorf("%s: %w", c.profile.Name, e)
	}
	return []protocol.Packet{response}, nil
}
func p2pElements(b []byte) (bool, error) {
	ies, e := wifi.Elements(b)
	if e != nil {
		return false, e
	}
	matched := false
	for _, ie := range ies {
		if ie.ID == 221 && len(ie.Value) >= 4 && bytes.Equal(ie.Value[:4], []byte{0, 0x50, 0xf2, 4}) {
			if _, err := wifi.ReadFields(ie.Value[4:], 2, 2, binary.BigEndian); err != nil {
				return false, err
			}
		}
		if ie.ID == 221 && len(ie.Value) >= 4 && bytes.Equal(ie.Value[:4], []byte{0x50, 0x6f, 0x9a, 9}) {
			if _, e := wifi.ReadFields(ie.Value[4:], 1, 2, binary.LittleEndian); e != nil {
				return false, e
			}
			matched = true
		}
	}
	return matched, nil
}
