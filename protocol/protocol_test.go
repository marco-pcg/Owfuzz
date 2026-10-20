package protocol

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func family() Family {
	return Family{Name: "example", LinkType: 147, Frames: []Frame{{ID: 65536, Name: "frame", Build: func(c *Context) (Packet, error) {
		return Packet{Data: []byte{byte(c.Iteration), 2, 3}, LinkType: 147}, nil
	}}}}
}

type sink struct {
	packets []Packet
	fail    bool
}

func (s *sink) LinkType() uint32 { return 147 }
func (s *sink) Send(_ context.Context, p Packet) error {
	if s.fail {
		return errors.New("sink failed")
	}
	s.packets = append(s.packets, p.Clone())
	return nil
}
func TestRegistryOwnershipAndConcurrentReads(t *testing.T) {
	r := NewRegistry()
	f := family()
	if e := r.Register(f); e != nil {
		t.Fatal(e)
	}
	f.Frames[0].Name = "changed"
	got, e := r.Family("example")
	if e != nil || got.Frames[0].Name != "frame" {
		t.Fatal("registry aliases input")
	}
	got.Frames[0].Name = "also changed"
	if e = r.Register(family()); e == nil {
		t.Fatal("duplicate family admitted")
	}
	bad := family()
	bad.Name = "bad"
	bad.Frames = append(bad.Frames, bad.Frames[0])
	if e = r.Register(bad); e == nil {
		t.Fatal("duplicate frame admitted")
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = r.Family("example")
				_ = r.List()
			}
		}()
	}
	wg.Wait()
}
func TestCampaignBoundsAndFailure(t *testing.T) {
	m, _ := Strategy("bitflip")
	a, b := DefaultContext(), DefaultContext()
	a.RandomState = 0
	b.RandomState = 0
	f := family()
	for i := 0; i < 100; i++ {
		p, e := Generate(f, "frame", &a, m)
		if e != nil {
			t.Fatal(e)
		}
		q, _ := Generate(f, "frame", &b, m)
		if string(p.Data) != string(q.Data) || a.RandomState != b.RandomState {
			t.Fatal("nondeterministic")
		}
	}
	bad := f
	bad.Frames = []Frame{{Name: "empty", Build: func(*Context) (Packet, error) { return Packet{LinkType: 147}, nil }}}
	if _, e := Generate(bad, "empty", &a, m); e == nil {
		t.Fatal("empty admitted")
	}
	bad.Frames[0].Build = func(*Context) (Packet, error) { return Packet{Data: make([]byte, MaxPacket+1), LinkType: 147}, nil }
	if _, e := Generate(bad, "empty", &a, m); e == nil {
		t.Fatal("oversized admitted")
	}
	mutate := func(_ *Context, p *Packet) error { p.LinkType = 1; return nil }
	if _, e := Generate(f, "frame", &a, mutate); e == nil {
		t.Fatal("link mutation admitted")
	}
	s := &sink{}
	p := Packet{Data: []byte{1}, LinkType: 1}
	if e := Deliver(context.Background(), s, p); e == nil {
		t.Fatal("foreign transport admitted")
	}
	none, _ := Strategy("none")
	campaign := Campaign{Family: f, Frames: []string{"frame"}, Count: 5, Mutate: none, Context: a}
	if e := campaign.Run(context.Background(), s); e != nil || len(s.packets) != 5 {
		t.Fatal(e)
	}
	s.fail = true
	if e := campaign.Run(context.Background(), s); e == nil {
		t.Fatal("send failure swallowed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := campaign.Run(ctx, s); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
