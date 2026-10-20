// SPDX-License-Identifier: GPL-3.0-or-later
package wifi

import (
	"encoding/binary"
	"errors"
	"owfuzz/protocol"
)

type Field struct {
	ID    uint16
	Value []byte
}

func ReadFields(b []byte, idWidth, lenWidth int, order binary.ByteOrder) ([]Field, error) {
	if len(b) > protocol.MaxPacket || (idWidth != 1 && idWidth != 2) || (lenWidth != 1 && lenWidth != 2) {
		return nil, errors.New("invalid TLV bounds/widths")
	}
	var out []Field
	for len(b) > 0 {
		header := idWidth + lenWidth
		if len(b) < header {
			return nil, errors.New("short TLV header")
		}
		id := uint16(b[0])
		if idWidth == 2 {
			id = order.Uint16(b)
		}
		n := int(b[idWidth])
		if lenWidth == 2 {
			n = int(order.Uint16(b[idWidth:]))
		}
		if n > len(b)-header {
			return nil, errors.New("short TLV value")
		}
		out = append(out, Field{id, append([]byte(nil), b[header:header+n]...)})
		b = b[header+n:]
	}
	return out, nil
}
func AppendField(b []byte, id uint16, value []byte, idWidth, lenWidth int, order binary.ByteOrder) ([]byte, error) {
	if (idWidth != 1 && idWidth != 2) || (lenWidth != 1 && lenWidth != 2) || idWidth == 1 && id > 255 || lenWidth == 1 && len(value) > 255 || len(b)+idWidth+lenWidth+len(value) > protocol.MaxPacket {
		return nil, errors.New("TLV exceeds bounds")
	}
	header := make([]byte, idWidth+lenWidth)
	if idWidth == 1 {
		header[0] = byte(id)
	} else {
		order.PutUint16(header, id)
	}
	if lenWidth == 1 {
		header[idWidth] = byte(len(value))
	} else {
		order.PutUint16(header[idWidth:], uint16(len(value)))
	}
	b = append(b, header...)
	return append(b, value...), nil
}
