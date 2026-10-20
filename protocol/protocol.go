// SPDX-License-Identifier: GPL-3.0-or-later
// Package protocol provides the protocol-independent fuzzing contracts.
package protocol

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
)

const MaxPacket = 4096
const (
	Ethernet uint32 = 1
	WiFi     uint32 = 105
	Radiotap uint32 = 127
)

var ErrUnsupported = errors.New("unsupported operation")

type MAC [6]byte

func ParseMAC(s string) (MAC, error) {
	var out MAC
	m, e := net.ParseMAC(s)
	if e != nil || len(m) != 6 {
		return out, fmt.Errorf("invalid six-byte MAC %q", s)
	}
	copy(out[:], m)
	return out, nil
}
func (m MAC) String() string { return net.HardwareAddr(m[:]).String() }

var Broadcast = MAC{255, 255, 255, 255, 255, 255}

type Packet struct {
	Data     []byte
	LinkType uint32
	Channel  int
}

func (p Packet) Validate() error {
	if len(p.Data) == 0 || len(p.Data) > MaxPacket {
		return fmt.Errorf("packet length %d outside 1..%d", len(p.Data), MaxPacket)
	}
	if p.LinkType == 0 {
		return errors.New("missing link type")
	}
	return nil
}
func (p Packet) Clone() Packet { p.Data = append([]byte(nil), p.Data...); return p }

// Context is owned by one campaign. Builders must not retain or concurrently mutate it.
type Context struct {
	Source, Destination, BSSID MAC
	Iteration                  uint64
	RandomState                uint32
	Received                   []byte
	SSID, Auth, Role           string
	Channel                    int
	Payload                    []byte
	// User carries per-protocol state without global variables.
	User any
}

func DefaultContext() Context {
	return Context{Source: MAC{2, 0, 0, 0, 0, 1}, BSSID: MAC{2, 0, 0, 0, 0, 1}, Destination: Broadcast, RandomState: 1, SSID: "owfuzz", Auth: "OPEN_NONE", Role: "ap", Channel: 1}
}

// Random intentionally matches the C campaign engine's uint32 LCG, including seed zero.
func (c *Context) Random() uint32 {
	c.RandomState = c.RandomState*1664525 + 1013904223
	return c.RandomState
}

type Builder func(*Context) (Packet, error)
type Frame struct {
	ID          uint32
	Name        string
	Build       Builder
	Unsupported string
}
type Family struct {
	Name     string
	LinkType uint32
	Frames   []Frame
}
type Registry struct {
	mu       sync.RWMutex
	families map[string]Family
}

func NewRegistry() *Registry { return &Registry{families: make(map[string]Family)} }
func (r *Registry) Register(f Family) error {
	if f.Name == "" || f.LinkType == 0 || len(f.Frames) == 0 {
		return errors.New("incomplete family")
	}
	names := map[string]bool{}
	ids := map[uint32]bool{}
	for _, frame := range f.Frames {
		if frame.Name == "" || frame.Build == nil || names[frame.Name] || ids[frame.ID] {
			return fmt.Errorf("invalid/duplicate frame %q", frame.Name)
		}
		names[frame.Name] = true
		ids[frame.ID] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.families == nil {
		r.families = make(map[string]Family)
	}
	if _, ok := r.families[f.Name]; ok {
		return fmt.Errorf("duplicate family %q", f.Name)
	}
	f.Frames = append([]Frame(nil), f.Frames...)
	r.families[f.Name] = f
	return nil
}
func (r *Registry) Family(name string) (Family, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.families[name]
	if !ok {
		return Family{}, fmt.Errorf("unknown protocol %q", name)
	}
	f.Frames = append([]Frame(nil), f.Frames...)
	return f, nil
}
func (r *Registry) List() []Family {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Family, 0, len(r.families))
	for _, f := range r.families {
		f.Frames = append([]Frame(nil), f.Frames...)
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
func (f Family) Frame(name string) (Frame, error) {
	for _, x := range f.Frames {
		if x.Name == name {
			return x, nil
		}
	}
	return Frame{}, fmt.Errorf("unknown frame %q in %s", name, f.Name)
}

type Mutator func(*Context, *Packet) error

func Strategy(name string) (Mutator, error) {
	switch name {
	case "none":
		return func(_ *Context, _ *Packet) error { return nil }, nil
	case "bitflip":
		return func(c *Context, p *Packet) error {
			if err := p.Validate(); err != nil {
				return err
			}
			pos := int(uint64(c.Random()) % uint64(len(p.Data)))
			p.Data[pos] ^= 1 << (c.Random() % 8)
			return nil
		}, nil
	case "truncate":
		return func(c *Context, p *Packet) error {
			if err := p.Validate(); err != nil {
				return err
			}
			p.Data = p.Data[:1+int(uint64(c.Random())%uint64(len(p.Data)))]
			return nil
		}, nil
	case "bytes":
		return func(c *Context, p *Packet) error {
			if err := p.Validate(); err != nil {
				return err
			}
			pos := int(uint64(c.Random()) % uint64(len(p.Data)))
			p.Data[pos] = byte(c.Random() >> 24)
			return nil
		}, nil
	default:
		return nil, fmt.Errorf("unknown strategy %q", name)
	}
}
func Generate(f Family, name string, c *Context, m Mutator) (Packet, error) {
	if c == nil || m == nil {
		return Packet{}, errors.New("nil context/strategy")
	}
	frame, e := f.Frame(name)
	if e != nil {
		return Packet{}, e
	}
	if frame.Unsupported != "" {
		return Packet{}, fmt.Errorf("%w: %s", ErrUnsupported, frame.Unsupported)
	}
	p, e := frame.Build(c)
	if e != nil {
		return Packet{}, fmt.Errorf("%s/%s: %w", f.Name, name, e)
	}
	if e = p.Validate(); e != nil {
		return Packet{}, e
	}
	if p.LinkType != f.LinkType {
		return Packet{}, errors.New("builder changed link type")
	}
	// A callback may reuse storage; mutation and callers receive an owned buffer.
	p = p.Clone()
	if e = m(c, &p); e != nil {
		return Packet{}, e
	}
	if e = p.Validate(); e != nil {
		return Packet{}, e
	}
	if p.LinkType != f.LinkType {
		return Packet{}, errors.New("mutation changed link type")
	}
	return p, nil
}

type Sender interface {
	LinkType() uint32
	Send(context.Context, Packet) error
}
type Receiver interface {
	Receive(context.Context) (Packet, error)
}

func Deliver(ctx context.Context, s Sender, p Packet) error {
	if s == nil {
		return errors.New("nil transport")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if e := p.Validate(); e != nil {
		return e
	}
	if s.LinkType() != p.LinkType {
		return errors.New("transport link type mismatch")
	}
	return s.Send(ctx, p)
}

type Campaign struct {
	Family   Family
	Frames   []string
	Count    uint64
	Channels []int
	Mutate   Mutator
	Context  Context
	OnPacket func(uint64, Packet) error
}

func (c *Campaign) Run(ctx context.Context, s Sender) error {
	if c.Count == 0 || len(c.Frames) == 0 {
		return errors.New("nonempty frame selection and positive count required")
	}
	for _, name := range c.Frames {
		if _, e := c.Family.Frame(name); e != nil {
			return e
		}
	}
	for i := uint64(0); i < c.Count; i++ {
		if e := ctx.Err(); e != nil {
			return e
		}
		c.Context.Iteration = i
		if len(c.Channels) > 0 {
			c.Context.Channel = c.Channels[i%uint64(len(c.Channels))]
		}
		p, e := Generate(c.Family, c.Frames[i%uint64(len(c.Frames))], &c.Context, c.Mutate)
		if e != nil {
			return fmt.Errorf("iteration %d: %w", i, e)
		}
		if e = Deliver(ctx, s, p); e != nil {
			return e
		}
		if c.OnPacket != nil {
			if e = c.OnPacket(i, p.Clone()); e != nil {
				return e
			}
		}
	}
	return nil
}
