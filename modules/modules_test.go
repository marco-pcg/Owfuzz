package modules

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"owfuzz/protocol"
	"owfuzz/wifi"
)

func TestAllFrames(t *testing.T) {
	r, e := NewRegistry()
	if e != nil {
		t.Fatal(e)
	}
	f, e := r.Family("802.11")
	if e != nil || len(f.Frames) != 42 {
		t.Fatal(e, len(f.Frames))
	}
	none, _ := protocol.Strategy("none")
	for _, family := range r.List() {
		for _, frame := range family.Frames {
			t.Run(family.Name+"/"+frame.Name, func(t *testing.T) {
				c := protocol.DefaultContext()
				p, e := protocol.Generate(family, frame.Name, &c, none)
				if frame.Unsupported != "" {
					if e == nil {
						t.Fatal("stub succeeded")
					}
					return
				}
				if e != nil {
					t.Fatal(e)
				}
				if family.LinkType == protocol.WiFi {
					h, e := wifi.Parse(p.Data)
					if e != nil {
						t.Fatal(e)
					}
					if family.Name == "802.11" && h.Type != byte(frame.ID) {
						t.Fatal("wire ID mismatch")
					}
				}
			})
		}
	}
}
func TestNativeGoldenAndSeedIsolation(t *testing.T) {
	r, _ := NewRegistry()
	f, _ := r.Family("ethernet")
	none, _ := protocol.Strategy("none")
	c := protocol.DefaultContext()
	p, e := protocol.Generate(f, "arp_request", &c, none)
	if e != nil {
		t.Fatal(e)
	}
	want, _ := hex.DecodeString("ffffffffffff02000000000108060001080006040001020000000001c0000201000000000000c0000202000000000000000000000000000000000000")
	if !bytes.Equal(want, p.Data) {
		t.Fatalf("%x != %x", p.Data, want)
	}
	f, _ = r.Family("802.11be")
	for i := uint64(0); i < 500; i++ {
		c.Iteration = i
		p, e = protocol.Generate(f, "ml_probe_response", &c, none)
		if e != nil {
			t.Fatal(e)
		}
		if len(p.Data) != 50 || p.Data[40] != 107 || p.Data[43] != 7 || p.Data[22] != byte(i<<4) || p.Data[23] != byte(i>>4) {
			t.Fatalf("iteration %d", i)
		}
	}
}
func TestIEBoundaries(t *testing.T) {
	c := protocol.DefaultContext()
	c.User = IEOptions{Mode: "replace", Extra: []wifi.Element{{ID: 221, Value: make([]byte, 255)}}}
	p, e := Management(0x80, &c)
	if e != nil {
		t.Fatal(e)
	}
	ies, e := wifi.Elements(p.Data[36:])
	if e != nil || len(ies) != 1 || len(ies[0].Value) != 255 {
		t.Fatal(e)
	}
	c.User = IEOptions{Mode: "replace", Extra: []wifi.Element{{ID: 1, Value: make([]byte, 256)}}}
	if _, e = Management(0x80, &c); e == nil {
		t.Fatal("IE overflow")
	}
	c.User = IEOptions{Mode: "invalid-length"}
	p, e = Management(0x80, &c)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = wifi.Elements(p.Data[36:]); e == nil {
		t.Fatal("invalid-length corpus is valid")
	}
	_ = fmt.Sprint(p)
}
func TestStructuredIEStrategy(t *testing.T) {
	r, _ := NewRegistry()
	f, _ := r.Family("802.11")
	c := protocol.DefaultContext()
	m, e := Strategy("ie")
	if e != nil {
		t.Fatal(e)
	}
	for i := uint64(0); i < 2048; i++ {
		c.Iteration = i
		p, e := protocol.Generate(f, "beacon", &c, m)
		if e != nil {
			t.Fatalf("step %d: %v", i, e)
		}
		if len(p.Data) > protocol.MaxPacket {
			t.Fatal("IE overflow")
		}
	}
}
func TestVendorAttributeStrategies(t *testing.T) {
	r, _ := NewRegistry()
	mutation, e := Strategy("attributes")
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range []struct{ family, frame string }{{"p2p", "probe_request"}, {"p2p", "go_negotiation_request"}, {"awdl", "action"}} {
		family, _ := r.Family(entry.family)
		c := protocol.DefaultContext()
		for i := uint64(0); i < 4100; i++ {
			c.Iteration = i
			p, e := protocol.Generate(family, entry.frame, &c, mutation)
			if e != nil {
				t.Fatalf("%s step %d: %v", entry.family, i, e)
			}
			if len(p.Data) > protocol.MaxPacket {
				t.Fatal("attribute overflow")
			}
		}
	}
}
