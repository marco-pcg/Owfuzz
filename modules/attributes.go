// SPDX-License-Identifier: GPL-3.0-or-later
package modules

import (
	"bytes"
	"encoding/binary"
	"errors"
	"owfuzz/protocol"
	"owfuzz/wifi"
)

func attributeField(c *protocol.Context, idWidth int, order binary.ByteOrder, capacity int) ([]byte, error) {
	variant := c.Iteration % 8
	id := uint16((c.Iteration / 8) % 256)
	if idWidth == 2 {
		ids := []uint16{0x104a, 0x1008, 0x1011, 0x1021, 0x1023, 0x1024, 0x103b, 0x1054}
		id = ids[(c.Iteration/8)%uint64(len(ids))]
	}
	if variant == 0 {
		return nil, nil
	}
	n := 0
	switch variant {
	case 2:
		n = 1
	case 3, 4:
		n = 8
	case 5, 6, 7:
		n = capacity - idWidth - 2
	}
	value := make([]byte, n)
	for i := range value {
		if variant == 3 || variant == 6 {
			value[i] = 255
		} else if variant == 4 || variant == 5 {
			value[i] = byte(c.Random() >> 24)
		}
	}
	b, e := wifi.AppendField(nil, id, value, idWidth, 2, order)
	if e != nil {
		return nil, e
	}
	if variant == 7 {
		order.PutUint16(b[idWidth:], 65535)
	}
	return b, nil
}
func mutateAttributes(c *protocol.Context, p *protocol.Packet) error {
	if p.LinkType != protocol.WiFi {
		return errors.New("attribute mutation requires WiFi")
	}
	h, e := wifi.Parse(p.Data)
	if e != nil {
		return e
	}
	body := p.Data[h.Size:]
	if h.Type == 0xd0 && len(body) >= 16 && bytes.Equal(body[:5], []byte{127, 0, 0x17, 0xf2, 8}) {
		if _, e = wifi.ReadFields(body[16:], 1, 2, binary.LittleEndian); e != nil {
			return e
		}
		attrs, e := attributeField(c, 1, binary.LittleEndian, 258)
		if e != nil {
			return e
		}
		p.Data = append(append([]byte(nil), p.Data[:h.Size+16]...), attrs...)
		return nil
	}
	offset := wifi.ElementOffset(h.Type)
	if h.Type == 0xd0 && len(body) >= 8 && bytes.Equal(body[:6], []byte{4, 9, 0x50, 0x6f, 0x9a, 9}) {
		offset = h.Size + 8
	}
	if offset < 0 || offset > len(p.Data) {
		return errors.New("no vendor attribute area")
	}
	ies, e := wifi.Elements(p.Data[offset:])
	if e != nil {
		return e
	}
	var matches []int
	for i, ie := range ies {
		if ie.ID == 221 && len(ie.Value) >= 4 && (bytes.Equal(ie.Value[:4], []byte{0x50, 0x6f, 0x9a, 9}) || bytes.Equal(ie.Value[:4], []byte{0, 0x50, 0xf2, 4})) {
			matches = append(matches, i)
		}
	}
	if len(matches) == 0 {
		return errors.New("no P2P/WPS attributes")
	}
	selected := matches[(c.Iteration/2048)%uint64(len(matches))]
	ie := ies[selected]
	width := 1
	var order binary.ByteOrder = binary.LittleEndian
	if ie.Value[3] == 4 {
		width = 2
		order = binary.BigEndian
	}
	if _, e = wifi.ReadFields(ie.Value[4:], width, 2, order); e != nil {
		return e
	}
	attrs, e := attributeField(c, width, order, 251)
	if e != nil {
		return e
	}
	ies[selected].Value = append(append([]byte(nil), ie.Value[:4]...), attrs...)
	out := append([]byte(nil), p.Data[:offset]...)
	for _, x := range ies {
		out, e = wifi.AppendElement(out, x.ID, x.Value)
		if e != nil {
			return e
		}
	}
	p.Data = out
	return nil
}
