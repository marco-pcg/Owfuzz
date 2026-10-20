//go:build !linux

// SPDX-License-Identifier: GPL-3.0-or-later
package radio

import (
	"context"
	"fmt"

	"owfuzz/protocol"
)

type Device struct{}

func Open(context.Context, string, int, uint32) (*Device, error) {
	return nil, fmt.Errorf("%w: live interfaces require Linux", protocol.ErrUnsupported)
}
func (*Device) LinkType() uint32                            { return 0 }
func (*Device) Send(context.Context, protocol.Packet) error { return protocol.ErrUnsupported }
func (*Device) Receive(context.Context) (protocol.Packet, error) {
	return protocol.Packet{}, protocol.ErrUnsupported
}
func (*Device) Close() error       { return nil }
func candidateChannel(*Device) int { return 0 }
