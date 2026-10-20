// SPDX-License-Identifier: GPL-3.0-or-later
package session

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"
)

var probeSequence atomic.Uint32

func checksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}

// CheckAlive sends an IPv4 ICMP echo using Go's raw-IP API (CAP_NET_RAW required).
func CheckAlive(ctx context.Context, ip net.IP, timeout time.Duration) error {
	if ip.To4() == nil {
		return errors.New("liveness probe requires IPv4")
	}
	conn, e := net.DialIP("ip4:icmp", nil, &net.IPAddr{IP: ip})
	if e != nil {
		return e
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if e = conn.SetDeadline(deadline); e != nil {
		return e
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	id := uint16(os.Getpid())
	seq := uint16(probeSequence.Add(1))
	msg := make([]byte, 16)
	msg[0] = 8
	binary.BigEndian.PutUint16(msg[4:], id)
	binary.BigEndian.PutUint16(msg[6:], seq)
	copy(msg[8:], "owfuzzGo")
	binary.BigEndian.PutUint16(msg[2:], checksum(msg))
	if _, e = conn.Write(msg); e != nil {
		return e
	}
	buf := make([]byte, 1500)
	for {
		if e = ctx.Err(); e != nil {
			return e
		}
		n, e := conn.Read(buf)
		if e != nil {
			return fmt.Errorf("target %s did not answer: %w", ip, e)
		}
		if matchEcho(buf[:n], id, seq) {
			return nil
		}
	}
}
func matchEcho(b []byte, id, seq uint16) bool {
	if len(b) >= 20 && b[0]>>4 == 4 {
		n := int(b[0]&15) * 4
		if n < 20 || n > len(b) {
			return false
		}
		b = b[n:]
	}
	return len(b) >= 8 && b[0] == 0 && b[1] == 0 && binary.BigEndian.Uint16(b[4:]) == id && binary.BigEndian.Uint16(b[6:]) == seq && checksum(b) == 0
}
