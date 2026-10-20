package session

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"

	"owfuzz/modules"
	"owfuzz/protocol"
	"owfuzz/wifi"
)

func TestCryptoVectors(t *testing.T) {
	pmk, e := PMK("password", "IEEE")
	if e != nil {
		t.Fatal(e)
	}
	if hex.EncodeToString(pmk) != "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e" {
		t.Fatalf("PBKDF2 %x", pmk)
	}
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	plain, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	want, _ := hex.DecodeString("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5")
	wrapped, e := AESWrap(key, plain)
	if e != nil || !bytes.Equal(wrapped, want) {
		t.Fatal(e, hex.EncodeToString(wrapped))
	}
	unwrapped, e := AESUnwrap(key, wrapped)
	if e != nil || !bytes.Equal(unwrapped, plain) {
		t.Fatal(e)
	}
	wrapped[4] ^= 1
	if _, e = AESUnwrap(key, wrapped); e == nil {
		t.Fatal("tampered key accepted")
	}
}
func contexts() (protocol.Context, protocol.Context) {
	ap := protocol.DefaultContext()
	ap.Destination = protocol.MAC{2, 0, 0, 0, 0, 2}
	sta := protocol.DefaultContext()
	sta.Role = "sta"
	sta.Source = ap.Destination
	sta.Destination = ap.Source
	sta.BSSID = ap.BSSID
	return ap, sta
}
func exchange(t *testing.T, auth string) (*Controller, *Controller, protocol.Packet) {
	t.Helper()
	ac, sc := contexts()
	ac.Auth = auth
	sc.Auth = auth
	ap, e := New(ac, "password")
	if e != nil {
		t.Fatal(e)
	}
	sta, e := New(sc, "password")
	if e != nil {
		t.Fatal(e)
	}
	probe, e := sta.Initial()
	if e != nil {
		t.Fatal(e)
	}
	responses, e := ap.Handle(probe[0])
	if e != nil || len(responses) != 1 {
		t.Fatal(e, len(responses))
	}
	authreq, e := sta.Handle(responses[0])
	if e != nil || len(authreq) != 1 {
		t.Fatal(e)
	}
	authresp, e := ap.Handle(authreq[0])
	if e != nil {
		t.Fatal(e)
	}
	assocreq, e := sta.Handle(authresp[0])
	if e != nil {
		t.Fatal(e)
	}
	assocresp, e := ap.Handle(assocreq[0])
	if e != nil {
		t.Fatal(e)
	}
	_, e = sta.Handle(assocresp[0])
	if e != nil {
		t.Fatal(e)
	}
	if auth == "OPEN_NONE" {
		return ap, sta, protocol.Packet{}
	}
	m2, e := sta.Handle(assocresp[1])
	if e != nil || len(m2) != 1 {
		t.Fatal(e)
	}
	bad := m2[0].Clone()
	bad.Data[len(bad.Data)-1] ^= 1
	if _, e = ap.Handle(bad); e == nil {
		t.Fatal("bad M2 accepted")
	}
	m3, e := ap.Handle(m2[0])
	if e != nil || len(m3) != 1 {
		t.Fatal(e)
	}
	m4, e := sta.Handle(m3[0])
	if e != nil || len(m4) != 1 {
		t.Fatal(e)
	}
	if _, e = ap.Handle(m4[0]); e != nil {
		t.Fatal(e)
	}
	if retransmitted, e := sta.Handle(m3[0]); e != nil || len(retransmitted) != 1 || sta.State != Connected {
		t.Fatal("exact M3 retransmission did not resend M4", e)
	}
	old := assocresp[1].Clone()
	if _, e = sta.Handle(old); e == nil {
		t.Fatal("old M1 replay accepted")
	}
	return ap, sta, m4[0]
}
func TestOpenAndWPA2Controllers(t *testing.T) {
	for _, auth := range []string{"OPEN_NONE", "WPA2_PSK_AES"} {
		t.Run(auth, func(t *testing.T) {
			ap, sta, _ := exchange(t, auth)
			if ap.State != Connected || sta.State != Connected {
				t.Fatal(ap.State, sta.State)
			}
			c := ap.Context
			c.Destination = sta.Context.Source
			p, e := modules.Management(0xc0, &c)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = sta.Handle(p); e != nil {
				t.Fatal(e)
			}
			if sta.State != Disconnected {
				t.Fatal("disconnect ignored")
			}
		})
	}
}
func TestPeerFilteringAndTruncatedFrames(t *testing.T) {
	ac, sc := contexts()
	ap, _ := New(ac, "")
	sc.Source = protocol.MAC{8}
	p, _ := modules.Management(0xb0, &sc)
	out, e := ap.Handle(p)
	if e != nil || len(out) != 0 {
		t.Fatal("foreign peer handled")
	}
	p.Data = p.Data[:3]
	if _, e = ap.Handle(p); e == nil {
		t.Fatal("short header admitted")
	}
	ac.Auth = "WPA3"
	if _, e = New(ac, "password"); !errors.Is(e, protocol.ErrUnsupported) {
		t.Fatal(e)
	}
}

type memoryReceiver struct{ packets []protocol.Packet }

func (r *memoryReceiver) Receive(ctx context.Context) (protocol.Packet, error) {
	if e := ctx.Err(); e != nil {
		return protocol.Packet{}, e
	}
	if len(r.packets) == 0 {
		return protocol.Packet{}, io.EOF
	}
	p := r.packets[0]
	r.packets = r.packets[1:]
	return p, nil
}

type memorySender struct{ packets []protocol.Packet }

func (s *memorySender) LinkType() uint32 { return protocol.WiFi }
func (s *memorySender) Send(_ context.Context, p protocol.Packet) error {
	s.packets = append(s.packets, p.Clone())
	return nil
}
func TestRunnerReplayAndState(t *testing.T) {
	ac, sc := contexts()
	ap, _ := New(ac, "")
	probe, _ := modules.Management(0x40, &sc)
	auth, _ := modules.Management(0xb0, &sc)
	assoc, _ := modules.Management(0, &sc)
	receiver := &memoryReceiver{[]protocol.Packet{probe, auth, assoc}}
	sender := &memorySender{}
	runner := Runner{Controller: ap, Receiver: receiver, Sender: sender, StatePath: t.TempDir() + "/state.json"}
	if e := runner.Run(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(sender.packets) != 4 || ap.State != Connected {
		t.Fatal(len(sender.packets), ap.State)
	}
	none, _ := protocol.Strategy("none")
	c := protocol.DefaultContext()
	if e := Replay(context.Background(), &memoryReceiver{[]protocol.Packet{probe}}, sender, &c, none, 0, nil); e != nil {
		t.Fatal(e)
	}
}
func FuzzEAPOLKey(f *testing.F) {
	f.Add(keyPacket(0x008a, 1, make([]byte, 32), nil, nil))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseKey(b); _, _ = wifi.EAPOL(b) })
}
func TestEchoMatching(t *testing.T) {
	reply := []byte{0, 0, 0, 0, 0, 123, 0, 42, 1, 2}
	sum := checksum(reply)
	reply[2] = byte(sum >> 8)
	reply[3] = byte(sum)
	if !matchEcho(reply, 123, 42) || matchEcho(reply, 123, 43) {
		t.Fatal("ICMP identifier mismatch")
	}
	reply[8] ^= 1
	if matchEcho(reply, 123, 42) {
		t.Fatal("bad ICMP checksum accepted")
	}
}

type blockingReceiver struct{}

func (blockingReceiver) Receive(ctx context.Context) (protocol.Packet, error) {
	<-ctx.Done()
	return protocol.Packet{}, ctx.Err()
}

type receiverFunc func(context.Context) (protocol.Packet, error)

func (f receiverFunc) Receive(ctx context.Context) (protocol.Packet, error) { return f(ctx) }
func TestPeriodicBeaconsAndCancellation(t *testing.T) {
	ac, _ := contexts()
	ap, _ := New(ac, "")
	sender := &memorySender{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	receiver := receiverFunc(func(receiveCtx context.Context) (protocol.Packet, error) {
		calls++
		if calls == 2 {
			cancel()
			return protocol.Packet{}, context.Canceled
		}
		<-receiveCtx.Done()
		return protocol.Packet{}, receiveCtx.Err()
	})
	runner := Runner{Controller: ap, Receiver: receiver, Sender: sender, BeaconInterval: time.Millisecond}
	if e := runner.Run(ctx); !errors.Is(e, context.Canceled) || len(sender.packets) != 2 {
		t.Fatal(e, len(sender.packets))
	}
}
func TestProfileResponders(t *testing.T) {
	ac, sc := contexts()
	registry, _ := modules.NewRegistry()
	none, _ := protocol.Strategy("none")
	for _, profile := range []string{"p2p", "awdl", "mesh"} {
		t.Run(profile, func(t *testing.T) {
			controller, e := NewProfile(profile, ac)
			if e != nil {
				t.Fatal(e)
			}
			initial, e := controller.Initial()
			if e != nil || len(initial) != 1 {
				t.Fatal(e)
			}
			family, _ := registry.Family(profile)
			frame := "probe_request"
			if profile == "awdl" {
				frame = "mif"
			}
			if profile == "mesh" {
				frame = "peering_action"
			}
			p, e := protocol.Generate(family, frame, &sc, none)
			if e != nil {
				t.Fatal(e)
			}
			responses, e := controller.Handle(p)
			if e != nil || len(responses) != 1 {
				t.Fatal(e, len(responses))
			}
			if controller.State != Fuzzing {
				t.Fatal(controller.State)
			}
			if profile == "p2p" {
				action, e := protocol.Generate(family, "go_negotiation_request", &sc, none)
				if e != nil {
					t.Fatal(e)
				}
				responses, e = controller.Handle(action)
				if e != nil || len(responses) != 1 || responses[0].Data[30] != 1 {
					t.Fatal(e, "P2P request not answered")
				}
			}
		})
	}
}
func TestMalformedAuthenticationControllers(t *testing.T) {
	for _, auth := range []string{"WPA3", "SHARE_WEP", "WPA_PSK_TKIP", "WPA2_PSK_TKIP_AES", "EAP_8021X"} {
		t.Run(auth, func(t *testing.T) {
			ac, sc := contexts()
			ac.Auth = auth
			sc.Auth = auth
			ap, e := NewFuzz(ac)
			if e != nil {
				t.Fatal(e)
			}
			sta, e := NewFuzz(sc)
			if e != nil {
				t.Fatal(e)
			}
			messages, e := sta.Initial()
			if e != nil {
				t.Fatal(e)
			}
			for step := 0; step < 12 && len(messages) > 0; step++ {
				var next []protocol.Packet
				for _, p := range messages {
					var out []protocol.Packet
					if step%2 == 0 {
						out, e = ap.Handle(p)
					} else {
						out, e = sta.Handle(p)
					}
					if e != nil {
						t.Fatalf("step %d: %v", step, e)
					}
					next = append(next, out...)
				}
				messages = next
			}
			if ap.State == Connected || sta.State == Connected {
				t.Fatal("unverified exchange marked connected")
			}
			if ap.State != Fuzzing && sta.State != Fuzzing {
				t.Fatal("fuzz exchange did not progress", ap.State, sta.State)
			}
		})
	}
}
