// SPDX-License-Identifier: GPL-3.0-or-later
// Package capture reads and writes bounded classic PCAP without libpcap/cgo.
package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"owfuzz/protocol"
)

type Writer struct {
	w        io.Writer
	link     uint32
	mu       sync.Mutex
	sequence uint64
	err      error
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if n < 0 || n > len(b) {
			return errors.New("invalid write count")
		}
		b = b[n:]
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func NewWriter(w io.Writer, link uint32) (*Writer, error) {
	if w == nil || link == 0 {
		return nil, errors.New("writer and link type required")
	}
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b, 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(b[4:], 2)
	binary.LittleEndian.PutUint16(b[6:], 4)
	binary.LittleEndian.PutUint32(b[16:], protocol.MaxPacket)
	binary.LittleEndian.PutUint32(b[20:], link)
	if e := writeAll(w, b); e != nil {
		return nil, e
	}
	return &Writer{w: w, link: link}, nil
}
func (w *Writer) LinkType() uint32 { return w.link }
func (w *Writer) Send(ctx context.Context, p protocol.Packet) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := p.Validate(); e != nil {
		return e
	}
	if p.LinkType != w.link {
		return errors.New("PCAP link type mismatch")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	b := make([]byte, 16+len(p.Data))
	binary.LittleEndian.PutUint32(b, uint32(w.sequence/1000000))
	binary.LittleEndian.PutUint32(b[4:], uint32(w.sequence%1000000))
	binary.LittleEndian.PutUint32(b[8:], uint32(len(p.Data)))
	binary.LittleEndian.PutUint32(b[12:], uint32(len(p.Data)))
	copy(b[16:], p.Data)
	w.err = writeAll(w.w, b)
	if w.err == nil {
		w.sequence++
	}
	return w.err
}

type Reader struct {
	r     io.Reader
	order binary.ByteOrder
	link  uint32
	snap  uint32
	nano  bool
}

func NewReader(r io.Reader) (*Reader, error) {
	b := make([]byte, 24)
	if _, e := io.ReadFull(r, b); e != nil {
		return nil, e
	}
	x := &Reader{r: r}
	switch binary.LittleEndian.Uint32(b) {
	case 0xa1b2c3d4:
		x.order = binary.LittleEndian
	case 0xd4c3b2a1:
		x.order = binary.BigEndian
	case 0xa1b23c4d:
		x.order = binary.LittleEndian
		x.nano = true
	case 0x4d3cb2a1:
		x.order = binary.BigEndian
		x.nano = true
	default:
		return nil, errors.New("not classic PCAP (pcapng is not supported)")
	}
	if x.order.Uint16(b[4:]) != 2 || x.order.Uint16(b[6:]) != 4 {
		return nil, errors.New("unsupported PCAP version")
	}
	x.snap = x.order.Uint32(b[16:])
	x.link = x.order.Uint32(b[20:]) & 0x0fffffff
	if x.snap == 0 || x.link == 0 {
		return nil, errors.New("invalid PCAP header")
	}
	return x, nil
}
func (r *Reader) LinkType() uint32 { return r.link }
func (r *Reader) Receive(ctx context.Context) (protocol.Packet, error) {
	if e := ctx.Err(); e != nil {
		return protocol.Packet{}, e
	}
	h := make([]byte, 16)
	if _, e := io.ReadFull(r.r, h); e != nil {
		return protocol.Packet{}, e
	}
	n := r.order.Uint32(h[8:])
	original := r.order.Uint32(h[12:])
	limit := uint32(protocol.MaxPacket)
	if r.link == protocol.Radiotap {
		limit += 4096
	}
	if n == 0 || n > limit || n > r.snap || original < n {
		return protocol.Packet{}, fmt.Errorf("invalid capture lengths %d/%d", n, original)
	}
	fraction := r.order.Uint32(h[4:])
	if (!r.nano && fraction >= 1000000) || (r.nano && fraction >= 1000000000) {
		return protocol.Packet{}, errors.New("invalid capture timestamp")
	}
	b := make([]byte, n)
	if _, e := io.ReadFull(r.r, b); e != nil {
		return protocol.Packet{}, e
	}
	p := protocol.Packet{Data: b, LinkType: r.link}
	if r.link == protocol.Radiotap {
		return StripRadiotap(b)
	}
	return p, p.Validate()
}
