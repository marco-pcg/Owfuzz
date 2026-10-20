//go:build linux

// SPDX-License-Identifier: GPL-3.0-or-later
// Package radio provides a pure-Go Linux AF_PACKET backend for existing interfaces.
package radio

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"owfuzz/capture"
	"owfuzz/protocol"
)

type Device struct {
	mu       sync.Mutex
	fd       int
	index    int
	link     uint32
	channel  int
	radiotap bool
	closed   bool
}

func htons(n uint16) uint16 {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], n)
	return binary.BigEndian.Uint16(b[:])
}
func Open(ctx context.Context, name string, channel int, link uint32) (*Device, error) {
	iface, e := net.InterfaceByName(name)
	if e != nil {
		return nil, e
	}
	raw, e := os.ReadFile("/sys/class/net/" + iface.Name + "/type")
	if e != nil {
		return nil, e
	}
	kind, e := strconv.Atoi(strings.TrimSpace(string(raw)))
	if e != nil {
		return nil, e
	}
	if link == protocol.WiFi {
		if kind != 801 && kind != 803 {
			return nil, fmt.Errorf("%s is not an IEEE802.11 monitor interface (type %d)", name, kind)
		}
		if channel < 0 || channel > 255 {
			return nil, errors.New("invalid channel")
		}
		if channel > 0 {
			out, e := exec.CommandContext(ctx, "iw", "dev", name, "set", "channel", strconv.Itoa(channel)).CombinedOutput()
			if e != nil {
				return nil, fmt.Errorf("set channel: %w: %s", e, out)
			}
		}
	} else if link != protocol.Ethernet || kind != 1 {
		return nil, errors.New("interface/link type mismatch")
	}
	fd, e := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, int(htons(3)))
	if e != nil {
		return nil, fmt.Errorf("AF_PACKET (requires CAP_NET_RAW): %w", e)
	}
	fail := func(err error) (*Device, error) { syscall.Close(fd); return nil, err }
	if e = syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(3), Ifindex: iface.Index}); e != nil {
		return fail(e)
	}
	timeout := syscall.NsecToTimeval((100 * time.Millisecond).Nanoseconds())
	if e = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout); e != nil {
		return fail(e)
	}
	// Ignore our own outgoing packets when the kernel supports this option.
	_ = syscall.SetsockoptInt(fd, 263, 23, 1)
	return &Device{fd: fd, index: iface.Index, link: link, channel: channel, radiotap: kind == 803}, nil
}
func (d *Device) LinkType() uint32 { return d.link }
func (d *Device) Send(ctx context.Context, p protocol.Packet) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := p.Validate(); e != nil {
		return e
	}
	if p.LinkType != d.link {
		return errors.New("radio link mismatch")
	}
	if p.Channel != 0 && d.channel != 0 && p.Channel != d.channel {
		return errors.New("packet/interface channel mismatch")
	}
	data := p.Data
	if d.radiotap {
		data = append([]byte{0, 0, 8, 0, 0, 0, 0, 0}, data...)
	}
	addr := &syscall.SockaddrLinklayer{Ifindex: d.index, Protocol: htons(3), Halen: 6}
	if p.LinkType == protocol.Ethernet {
		copy(addr.Addr[:], p.Data[:min(6, len(p.Data))])
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return os.ErrClosed
	}
	return syscall.Sendto(d.fd, data, 0, addr)
}
func (d *Device) Receive(ctx context.Context) (protocol.Packet, error) {
	b := make([]byte, protocol.MaxPacket+4096)
	for {
		if e := ctx.Err(); e != nil {
			return protocol.Packet{}, e
		}
		d.mu.Lock()
		if d.closed {
			d.mu.Unlock()
			return protocol.Packet{}, os.ErrClosed
		}
		n, addr, e := syscall.Recvfrom(d.fd, b, 0)
		d.mu.Unlock()
		if e == syscall.EAGAIN || e == syscall.EWOULDBLOCK || e == syscall.EINTR {
			continue
		}
		if e != nil {
			return protocol.Packet{}, e
		}
		if ll, ok := addr.(*syscall.SockaddrLinklayer); ok && ll.Pkttype == 4 {
			continue
		}
		var p protocol.Packet
		if d.radiotap {
			p, e = capture.StripRadiotap(b[:n])
			if e != nil {
				continue
			}
		} else {
			p = protocol.Packet{Data: append([]byte(nil), b[:n]...), LinkType: d.link}
			if e = p.Validate(); e != nil {
				continue
			}
		}
		p.Channel = d.channel
		return p, nil
	}
}
func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	return syscall.Close(d.fd)
}
func candidateChannel(d *Device) int { return d.channel }
