// SPDX-License-Identifier: GPL-3.0-or-later
package radio

import (
	"context"
	"errors"
	"sync"

	"owfuzz/protocol"
)

type result struct {
	p protocol.Packet
	e error
}

// Group multiplexes independent interfaces without sharing a socket or campaign state.
type Group struct {
	lifecycle sync.Mutex
	closed    bool
	ctx       context.Context
	closeOnce sync.Once
	devices   []*Device
	link      uint32
	mu        sync.Mutex
	next      int
	events    chan result
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	once      sync.Once
	closeErr  error
}

func OpenGroup(ctx context.Context, names []string, channels []int, link uint32) (*Group, error) {
	if len(names) == 0 || len(channels) != len(names) {
		return nil, errors.New("interface/channel counts differ")
	}
	g := &Group{link: link, events: make(chan result, 128)}
	ctx, g.cancel = context.WithCancel(ctx)
	g.ctx = ctx
	seen := map[string]bool{}
	for i, name := range names {
		if seen[name] {
			g.Close()
			return nil, errors.New("duplicate interface")
		}
		seen[name] = true
		d, e := Open(ctx, name, channels[i], link)
		if e != nil {
			g.Close()
			return nil, e
		}
		g.devices = append(g.devices, d)
	}
	return g, nil
}
func (g *Group) LinkType() uint32 { return g.link }
func (g *Group) Send(ctx context.Context, p protocol.Packet) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.devices) == 0 {
		return errors.New("no interfaces")
	}
	d := g.devices[g.next%len(g.devices)]
	if p.Channel != 0 {
		var matching []*Device
		for _, candidate := range g.devices {
			if candidateChannel(candidate) == p.Channel {
				matching = append(matching, candidate)
			}
		}
		if len(matching) == 0 {
			return errors.New("no interface configured for packet channel")
		}
		d = matching[g.next%len(matching)]
	}
	g.next++
	return protocol.Deliver(ctx, d, p)
}
func (g *Group) Receive(ctx context.Context) (protocol.Packet, error) {
	g.lifecycle.Lock()
	if g.closed {
		g.lifecycle.Unlock()
		return protocol.Packet{}, context.Canceled
	}
	g.once.Do(func() {
		for _, d := range g.devices {
			g.wg.Add(1)
			go func(device *Device) {
				defer g.wg.Done()
				for {
					p, e := device.Receive(g.ctx)
					select {
					case g.events <- result{p, e}:
					case <-g.ctx.Done():
						return
					}
					if e != nil {
						return
					}
				}
			}(d)
		}
	})
	g.lifecycle.Unlock()
	select {
	case x := <-g.events:
		return x.p, x.e
	case <-ctx.Done():
		return protocol.Packet{}, ctx.Err()
	case <-g.ctx.Done():
		return protocol.Packet{}, g.ctx.Err()
	}
}
func (g *Group) Close() error {
	g.closeOnce.Do(func() {
		g.lifecycle.Lock()
		g.closed = true
		if g.cancel != nil {
			g.cancel()
		}
		g.lifecycle.Unlock()
		for _, d := range g.devices {
			if e := d.Close(); e != nil {
				g.closeErr = e
			}
		}
		g.wg.Wait()
	})
	return g.closeErr
}
