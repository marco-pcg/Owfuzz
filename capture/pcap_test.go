package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"owfuzz/protocol"
)

func TestRoundTripAndBounds(t *testing.T) {
	var b bytes.Buffer
	w, e := NewWriter(&b, 105)
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	p := protocol.Packet{Data: []byte{0x80, 0, 1}, LinkType: 105}
	if e = w.Send(ctx, p); e != nil {
		t.Fatal(e)
	}
	r, e := NewReader(bytes.NewReader(b.Bytes()))
	if e != nil {
		t.Fatal(e)
	}
	got, e := r.Receive(ctx)
	if e != nil || !bytes.Equal(got.Data, p.Data) {
		t.Fatal(e)
	}
	if _, e = r.Receive(ctx); !errors.Is(e, io.EOF) {
		t.Fatal(e)
	}
	bad := append([]byte(nil), b.Bytes()...)
	binary.LittleEndian.PutUint32(bad[32:], 0xffffffff)
	r, _ = NewReader(bytes.NewReader(bad))
	if _, e = r.Receive(ctx); e == nil {
		t.Fatal("bad length accepted")
	}
	if e = w.Send(ctx, protocol.Packet{Data: []byte{1}, LinkType: 1}); e == nil {
		t.Fatal("wrong link accepted")
	}
}
func TestBigEndianNanosecond(t *testing.T) {
	var b bytes.Buffer
	for _, v := range []any{uint32(0xa1b23c4d), uint16(2), uint16(4), uint32(0), uint32(0), uint32(4096), uint32(1), uint32(0), uint32(999999999), uint32(1), uint32(1), byte(42)} {
		if e := binary.Write(&b, binary.BigEndian, v); e != nil {
			t.Fatal(e)
		}
	}
	r, e := NewReader(&b)
	if e != nil {
		t.Fatal(e)
	}
	p, e := r.Receive(context.Background())
	if e != nil || len(p.Data) != 1 || p.Data[0] != 42 {
		t.Fatal(e)
	}
}
func TestRadiotapFCSAndTruncation(t *testing.T) {
	b := []byte{0, 0, 9, 0, 2, 0, 0, 0, 0x10, 0x80, 0, 0, 0, 1, 2, 3, 4}
	p, e := StripRadiotap(b)
	if e != nil || !bytes.Equal(p.Data, []byte{0x80, 0, 0, 0}) {
		t.Fatal(e, p)
	}
	for _, bad := range [][]byte{{}, b[:5], {0, 0, 8, 0, 0, 0, 0, 128}, {0, 0, 9, 0, 2, 0, 0, 0, 0x40, 1}} {
		if _, e := StripRadiotap(bad); e == nil {
			t.Fatal("invalid radiotap accepted")
		}
	}
}

type shortWriter struct{}

func (shortWriter) Write([]byte) (int, error) { return 0, nil }
func TestWriteFailure(t *testing.T) {
	if _, e := NewWriter(shortWriter{}, 105); !errors.Is(e, io.ErrShortWrite) {
		t.Fatal(e)
	}
}
func FuzzPCAP(f *testing.F) {
	var b bytes.Buffer
	w, _ := NewWriter(&b, 1)
	_ = w.Send(context.Background(), protocol.Packet{Data: []byte{1, 2}, LinkType: 1})
	f.Add(b.Bytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, e := NewReader(bytes.NewReader(b))
		if e != nil {
			return
		}
		for i := 0; i < 10; i++ {
			p, e := r.Receive(context.Background())
			if e != nil {
				return
			}
			if e = p.Validate(); e != nil {
				t.Fatal(e)
			}
		}
	})
}
func FuzzRadiotap(f *testing.F) {
	f.Add([]byte{0, 0, 8, 0, 0, 0, 0, 0, 0x80})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, e := StripRadiotap(b)
		if e == nil {
			if e = p.Validate(); e != nil {
				t.Fatal(e)
			}
		}
	})
}
func TestTextPoCAndJSONL(t *testing.T) {
	ctx := context.Background()
	r := NewTextReader(bytes.NewBufferString("# poc\n\\x80\\x00\\x01\n80:00:02\n"), 105, false)
	for i := byte(1); i <= 2; i++ {
		p, e := r.Receive(ctx)
		if e != nil || !bytes.Equal(p.Data, []byte{0x80, 0, i}) {
			t.Fatal(e, p)
		}
	}
	if _, e := r.Receive(ctx); !errors.Is(e, io.EOF) {
		t.Fatal(e)
	}
	r = NewTextReader(bytes.NewBufferString("{\"direction\":\"receive\",\"link_type\":105,\"data\":\"AQ==\"}\n{\"direction\":\"send\",\"link_type\":105,\"data\":\"Ag==\"}\n"), 105, true)
	p, e := r.Receive(ctx)
	if e != nil || !bytes.Equal(p.Data, []byte{2}) {
		t.Fatal(e, p)
	}
}
