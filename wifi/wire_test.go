package wifi

import (
	"owfuzz/protocol"
	"testing"
)

func TestDSAddresses(t *testing.T) {
	c := protocol.DefaultContext()
	c.Source = protocol.MAC{1}
	c.Destination = protocol.MAC{2}
	c.BSSID = protocol.MAC{3}
	for _, role := range []string{"ap", "sta"} {
		c.Role = role
		p := Data(&c, []byte{2, 1, 0, 0})
		h, e := Parse(p.Data)
		if e != nil {
			t.Fatal(e)
		}
		if h.Source() != c.Source || h.Destination() != c.Destination || h.BSSID() != c.BSSID {
			t.Fatal(role, h)
		}
		got, e := EAPOL(p.Data)
		if e != nil || len(got) != 4 {
			t.Fatal(e)
		}
	}
}
func FuzzParse(f *testing.F) {
	f.Add(make([]byte, 24))
	f.Add([]byte{0xd4, 0, 0, 0, 1, 2, 3, 4, 5, 6})
	f.Fuzz(func(t *testing.T, b []byte) {
		h, e := Parse(b)
		if e == nil && h.Size > len(b) {
			t.Fatal("header length exceeds frame")
		}
		_, _ = EAPOL(b)
		_, _ = Elements(b)
		_, _ = ReadFields(b, 1, 2, LE)
	})
}
func TestVendorTLVs(t *testing.T) {
	b, e := AppendField(nil, 65535, []byte{1, 2}, 2, 2, LE)
	if e != nil {
		t.Fatal(e)
	}
	fields, e := ReadFields(b, 2, 2, LE)
	if e != nil || len(fields) != 1 || fields[0].ID != 65535 {
		t.Fatal(e)
	}
	if _, e = ReadFields(b[:len(b)-1], 2, 2, LE); e == nil {
		t.Fatal("truncated TLV accepted")
	}
}
func TestMalformedManagementDSFlags(t *testing.T) {
	b := make([]byte, 24)
	b[0] = 0x30
	b[1] = 3
	if _, e := Parse(b); e == nil {
		t.Fatal("invalid management DS flags accepted")
	}
}
