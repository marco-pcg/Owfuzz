// SPDX-License-Identifier: GPL-3.0-or-later
// Package session implements packet-driven OPEN and WPA2-CCMP AP/STA controllers.
package session

import (
	"bytes"
	"errors"
	"fmt"

	"owfuzz/modules"
	"owfuzz/protocol"
	"owfuzz/wifi"
)

type State string

const (
	Disconnected   State = "disconnected"
	Scanning       State = "scanning"
	Authenticating State = "authenticating"
	Associating    State = "associating"
	Associated     State = "associated"
	Handshake      State = "four-way-handshake"
	Connected      State = "connected"
)

type Controller struct {
	Context protocol.Context
	State   State
	keys    handshake
	peer    protocol.MAC
	profile *protocol.Family
	Fuzz    bool
}

func New(c protocol.Context, password string) (*Controller, error) {
	if c.Role != "ap" && c.Role != "sta" {
		return nil, errors.New("interactive role must be ap or sta")
	}
	if c.Auth == "" {
		c.Auth = "OPEN_NONE"
	}
	x := &Controller{Context: c, State: Disconnected}
	if c.Auth != "OPEN_NONE" {
		if c.Auth != "WPA2_PSK_AES" {
			return nil, fmt.Errorf("%w: interactive authentication %s (OPEN_NONE and WPA2_PSK_AES supported)", protocol.ErrUnsupported, c.Auth)
		}
		pmk, e := PMK(password, c.SSID)
		if e != nil {
			return nil, e
		}
		x.keys.pmk = pmk
	}
	return x, nil
}
func (c *Controller) build(t byte, ctx *protocol.Context) (protocol.Packet, error) {
	ctx.Iteration = c.Context.Iteration
	c.Context.Iteration++
	packet, err := modules.Management(t, ctx)
	c.Context.RandomState = ctx.RandomState
	return packet, err
}
func (c *Controller) Initial() ([]protocol.Packet, error) {
	if c.profile != nil {
		return c.profileInitial()
	}
	ctx := c.Context
	if ctx.Role == "ap" {
		ctx.Destination = protocol.Broadcast
		p, e := c.build(0x80, &ctx)
		return []protocol.Packet{p}, e
	}
	c.State = Scanning
	p, e := c.build(0x40, &ctx)
	return []protocol.Packet{p}, e
}
func (c *Controller) Reset() {
	pmk := c.keys.pmk
	c.keys = handshake{pmk: pmk}
	c.State = Disconnected
	c.peer = protocol.MAC{}
}

// Handle ignores unrelated traffic and rejects malformed/truncated matching exchanges.
func (c *Controller) Handle(p protocol.Packet) ([]protocol.Packet, error) {
	if p.LinkType != protocol.WiFi {
		return nil, errors.New("interactive controller requires WiFi packets")
	}
	h, e := wifi.Parse(p.Data)
	if e != nil {
		return nil, e
	}
	ctx := c.Context
	if c.profile != nil {
		return c.profileHandle(p, h)
	}
	if h.Type&0x0c == 4 {
		return nil, nil
	}
	if h.Transmitter == ctx.Source {
		return nil, nil
	}
	if ctx.Role == "ap" {
		if h.Receiver != ctx.Source && h.Receiver != ctx.BSSID && h.Receiver != protocol.Broadcast {
			return nil, nil
		}
		if ctx.Destination != protocol.Broadcast && h.Transmitter != ctx.Destination {
			return nil, nil
		}
		if c.peer != (protocol.MAC{}) && h.Transmitter != c.peer {
			return nil, nil
		}
		ctx.Destination = h.Transmitter
	} else {
		if h.Transmitter != ctx.BSSID {
			return nil, nil
		}
		if h.Receiver != ctx.Source && h.Receiver != protocol.Broadcast {
			return nil, nil
		}
		ctx.Destination = ctx.BSSID
	}
	ctx.Received = append([]byte(nil), p.Data...)
	body := p.Data[h.Size:]
	if h.Type == 0xc0 || h.Type == 0xa0 {
		if len(body) < 2 {
			return nil, errors.New("short disconnect")
		}
		c.Reset()
		return nil, nil
	}
	switch h.Type {
	case 0x40:
		if ctx.Role != "ap" {
			return nil, nil
		}
		ies, e := wifi.Elements(body)
		if e != nil {
			return nil, e
		}
		for _, ie := range ies {
			if ie.ID == 0 && len(ie.Value) > 0 && !bytes.Equal(ie.Value, []byte(ctx.SSID)) {
				return nil, nil
			}
		}
		c.State = Scanning
		response, e := c.build(0x50, &ctx)
		return []protocol.Packet{response}, e
	case 0x80, 0x50:
		if ctx.Role != "sta" || c.State != Scanning {
			return nil, nil
		}
		if len(body) < 12 {
			return nil, errors.New("short beacon/probe response")
		}
		ies, e := wifi.Elements(body[12:])
		if e != nil {
			return nil, e
		}
		found := false
		for _, ie := range ies {
			if ie.ID == 0 && bytes.Equal(ie.Value, []byte(ctx.SSID)) {
				found = true
			}
		}
		if !found {
			return nil, nil
		}
		c.State = Authenticating
		response, e := c.build(0xb0, &ctx)
		return []protocol.Packet{response}, e
	case 0xb0:
		if len(body) < 6 {
			return nil, errors.New("short authentication")
		}
		algorithm, sequence, status := wifi.LE.Uint16(body), wifi.LE.Uint16(body[2:]), wifi.LE.Uint16(body[4:])
		if (algorithm != 0 && !c.Fuzz) || status != 0 {
			return nil, errors.New("authentication rejected/unsupported algorithm")
		}
		if c.Fuzz && algorithm == 3 {
			if sequence != 1 && sequence != 2 {
				return nil, errors.New("unexpected SAE fuzz sequence")
			}
			c.peer = h.Transmitter
			c.State = Authenticating
			if ctx.Role == "sta" && sequence == 2 {
				c.State = Associating
				request, err := c.build(0, &ctx)
				return []protocol.Packet{request}, err
			}
			if ctx.Role == "sta" && sequence == 1 {
				wifi.LE.PutUint16(ctx.Received[h.Size+2:], 2)
			}
			response, err := c.build(0xb0, &ctx)
			return []protocol.Packet{response}, err
		}

		if c.Fuzz && algorithm == 1 {
			if sequence < 1 || sequence > 4 {
				return nil, errors.New("unexpected WEP fuzz sequence")
			}
			c.peer = h.Transmitter
			c.State = Authenticating
			if sequence == 4 && ctx.Role == "sta" {
				c.State = Associating
				request, err := c.build(0, &ctx)
				return []protocol.Packet{request}, err
			}
			response, err := c.build(0xb0, &ctx)
			return []protocol.Packet{response}, err
		}
		if ctx.Role == "ap" {
			if sequence != 1 {
				return nil, nil
			}
			if c.State == Connected || c.State == Handshake {
				c.Reset()
			}
			c.peer = h.Transmitter
			c.State = Authenticating
			response, e := c.build(0xb0, &ctx)
			return []protocol.Packet{response}, e
		}
		if sequence != 2 || c.State != Authenticating {
			return nil, errors.New("unexpected authentication sequence")
		}
		c.State = Associating
		response, e := c.build(0, &ctx)
		return []protocol.Packet{response}, e
	case 0, 0x20:
		if ctx.Role != "ap" {
			return nil, nil
		}
		if c.State != Authenticating && c.State != Associated {
			return nil, errors.New("association before authentication")
		}
		fixed := 4
		if h.Type == 0x20 {
			fixed = 10
		}
		if len(body) < fixed {
			return nil, errors.New("short association request")
		}
		if _, e := wifi.Elements(body[fixed:]); e != nil {
			return nil, e
		}
		c.State = Associated
		kind := byte(0x10)
		if h.Type == 0x20 {
			kind = 0x30
		}
		response, e := c.build(kind, &ctx)
		if e != nil {
			return nil, e
		}
		out := []protocol.Packet{response}
		if c.Fuzz {
			c.State = Fuzzing
			if ctx.Auth != "OPEN_NONE" && ctx.Auth != "OPEN_WEP" && ctx.Auth != "SHARE_WEP" {
				message, err := fuzzEAPOL(&ctx, nil)
				if err != nil {
					return nil, err
				}
				c.Context.RandomState = ctx.RandomState
				out = append(out, wifi.Data(&ctx, message))
			}
			return out, nil
		}
		if ctx.Auth != "OPEN_NONE" {
			ctx.RandomState = c.Context.RandomState
			msg := c.keys.start(&ctx)
			c.Context.RandomState = ctx.RandomState
			out = append(out, wifi.Data(&ctx, msg))
			c.State = Handshake
		} else {
			c.State = Connected
		}
		return out, nil
	case 0x10, 0x30:
		if ctx.Role != "sta" || c.State != Associating {
			return nil, nil
		}
		if len(body) < 6 {
			return nil, errors.New("short association response")
		}
		if wifi.LE.Uint16(body[2:]) != 0 {
			return nil, errors.New("association rejected")
		}
		if c.Fuzz {
			c.State = Fuzzing
			if ctx.Auth == "EAP_8021X" {
				message, err := fuzzEAPOL(&ctx, nil)
				if err != nil {
					return nil, err
				}
				return []protocol.Packet{wifi.Data(&ctx, message)}, nil
			}
			return nil, nil
		}
		if ctx.Auth == "OPEN_NONE" {
			c.State = Connected
		} else {
			c.State = Handshake
		}
		return nil, nil
	}
	if h.Type&0x0c == 8 && c.Fuzz {
		return c.fuzzData(&ctx, p)
	}
	if h.Type&0x0c == 8 && ctx.Auth != "OPEN_NONE" {
		if c.State != Handshake && c.State != Connected {
			return nil, errors.New("EAPOL before association")
		}
		msg, e := wifi.EAPOL(p.Data)
		if e != nil {
			return nil, nil
		}
		if ctx.Role == "ap" {
			ctx.Destination = c.peer
		}
		ctx.RandomState = c.Context.RandomState
		response, e := c.keys.handle(&ctx, msg)
		c.Context.RandomState = ctx.RandomState
		if e != nil {
			return nil, e
		}
		if c.keys.complete {
			c.State = Connected
		}
		if response != nil {
			return []protocol.Packet{wifi.Data(&ctx, response)}, nil
		}
	}
	return nil, nil
}
