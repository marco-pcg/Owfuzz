// SPDX-License-Identifier: GPL-3.0-or-later
package modules

import (
	"errors"

	"owfuzz/protocol"
	"owfuzz/wifi"
)

// Strategy adds structured management-IE campaigns to the protocol-neutral ones.
func Strategy(name string) (protocol.Mutator, error) {
	if name == "attributes" {
		return mutateAttributes, nil
	}
	if name != "ie" {
		return protocol.Strategy(name)
	}
	return func(c *protocol.Context, p *protocol.Packet) error {
		if p.LinkType != protocol.WiFi || len(p.Data) < 2 {
			return errors.New("IE mutation requires WiFi")
		}
		offset := wifi.ElementOffset(p.Data[0])
		if offset < 0 || len(p.Data) < offset {
			return errors.New("frame has no information-element area")
		}
		options, _ := c.User.(IEOptions)
		var ids []byte
		for i := 0; i < 256; i++ {
			if !options.Disabled[byte(i)] {
				ids = append(ids, byte(i))
			}
		}
		if len(ids) == 0 {
			return errors.New("all information elements disabled")
		}
		variant := c.Iteration % 8
		id := ids[(c.Iteration/8)%uint64(len(ids))]
		// Preserve other elements, but remove previous copies of the selected type.
		parsed, e := wifi.Elements(p.Data[offset:])
		if e != nil {
			return e
		}
		out := append([]byte(nil), p.Data[:offset]...)
		for _, ie := range parsed {
			if ie.ID != id {
				out, e = wifi.AppendElement(out, ie.ID, ie.Value)
				if e != nil {
					return e
				}
			}
		}
		if variant == 0 {
			p.Data = out
			return nil
		}
		n := 0
		switch variant {
		case 2:
			n = 1
		case 3, 4:
			n = 8
		case 5, 6, 7:
			n = 255
		}
		value := make([]byte, n)
		for i := range value {
			if variant == 4 || variant == 6 {
				value[i] = 255
			} else if variant == 5 {
				value[i] = byte(c.Random() >> 24)
			}
		}
		if id == 255 {
			var extensions []byte
			for i := 0; i < 256; i++ {
				if !options.DisabledExtensions[byte(i)] {
					extensions = append(extensions, byte(i))
				}
			}
			if len(extensions) == 0 {
				return errors.New("all IE extensions disabled")
			}
			if len(value) == 0 {
				value = []byte{extensions[(c.Iteration/2048)%uint64(len(extensions))]}
			} else {
				value[0] = extensions[(c.Iteration/2048)%uint64(len(extensions))]
			}
		}
		out, e = wifi.AppendElement(out, id, value)
		if e != nil {
			return e
		}
		if variant == 7 {
			if len(value) > 0 {
				out[len(out)-len(value)-1] = 0
			} else {
				out[len(out)-1] = 255
			}
		}
		p.Data = out
		return nil
	}, nil
}
